import click
import json
import re
import semver

fucked_distance = 0xFFFFFFFF
max_size_diff = 10


def get_sem_ver(exe_file: str):
    res = re.match(".*ffxiv_dx11\.(\d).(\d)(\d)(\w?)\.exe", exe_file)
    sem_ver = f"{res.group(1)}.{res.group(2)}.{res.group(3)}"
    if res.group(4) != "":
        sem_ver = f"{sem_ver}+{res.group(4)}"
    return sem_ver

def get_zone_proto_down_sig(sem_ver: str):
    if semver.compare(sem_ver, "7.2.0") >= 0:
        return "40 55 53 56 57 41 55 41 56 41 57 48 8D AC 24 ? ? ? ? B8 ? ? ? ? E8 ? ? ? ? 48 2B E0 48 8B 05 ? ? ? ? 48 33 C4 48 89 85 ? ? ? ? 45 0F B7 78 ?"
        # return "E8 ? ? ? ? 41 83 C7 9A EB 1B"
    elif semver.compare(sem_ver, "6.4.0") >= 0:
        return "40 53 56 48 81 EC ? ? ? ? 48 8B 05 ? ? ? ? 48 33 C4 48 89 44 24 ? 8B F2"
    else:
        return "48 89 ? 24 ? ? 48 83 EC 50 8B F2 49 8B"

def get_opcode_offset_sig(sem_ver: str):
    if semver.compare(sem_ver, "7.2.0") >= 0:
        return "E8 ? ? ? ? 41 83 C7 ? EB 1B"
    elif semver.compare(sem_ver, "6.4.0") >= 0:
        return "40 53 56 48 81 EC ? ? ? ? 48 8B 05 ? ? ? ? 48 33 C4 48 89 44 24 ? 8B F2"
    else:
        return "48 89 ? 24 ? ? 48 83 EC 50 8B F2 49 8B"


def get_opcode_offset_7_20(r2):
    orig_loc = r2.cmd("s")  # Save original spot
    r2.cmd("aei")  # Initialize ESIL VM
    r2.cmd("aeim")  # Initialize ESIL VM stack
    r2.cmd("aeip")  # Initialize ESIL VM IP to curseek
    r2.cmd("aeso") # step over call
    r2.cmd("aer r15=0x500")  # set r15 to some arbitrary number
    r2.cmd("aeso")  # step

    regs = r2.cmdj("arj")
    opcode_offset = 0x500 - regs["r15"]

    # Clear the ESIL environment
    r2.cmd("ar0")
    r2.cmd("aeim-")
    r2.cmd("aei-")
    r2.cmd(f"s {orig_loc}")  # Seek back to original spot

    return opcode_offset

def get_opcode_offset(r2):
    orig_loc = r2.cmd("s")  # Save original spot
    r2.cmd("aei")  # Initialize ESIL VM
    r2.cmd("aeim")  # Initialize ESIL VM stack
    r2.cmd("aeip")  # Initialize ESIL VM IP to curseek

    r2.cmd("aecc")  # continue until call
    r2.cmd("aer rax=0x0")  # set rax to 0
    r2.cmd('"aesue rax,0x0,>"')  # continue until rax changes?
    r2.cmd("aer rdx=0x200")  # set rdx to some arbitrary number
    r2.cmd("aeso")  # step

    regs = r2.cmdj("arj")
    opcode_offset = regs["rdx"] - regs["rax"]

    # Clear the ESIL environment
    r2.cmd("ar0")
    r2.cmd("aeim-")
    r2.cmd("aei-")
    r2.cmd(f"s {orig_loc}")  # Seek back to original spot

    return opcode_offset


def get_correct_switch(approx_ea, switch_cases):
    switches = dict()

    pattern = re.compile("case\.(0x[0-9a-fA-F]+)\.(\d+)")

    for l in switch_cases:
        match = pattern.match(l["name"])
        if match is not None:
            switch_ea = match[1]
            case_ea = l["offset"]

            if switch_ea not in switches:
                switches[switch_ea] = dict()
            if case_ea not in switches[switch_ea]:
                switches[switch_ea][case_ea] = {
                    "opcodes": [],
                }
            switches[switch_ea][case_ea]["opcodes"].append(match[2])

    found_switch = None
    longest_switch = dict()
    for switch_ea in switches:
        int_switch_ea = int(switch_ea, 16)
        if int_switch_ea < approx_ea or int_switch_ea > approx_ea+0x100:
            continue
        if len(switches[switch_ea].keys()) > len(longest_switch):
            found_switch = switch_ea
            longest_switch = switches[switch_ea]

    return found_switch, longest_switch


def get_block_sizes(blocks):
    block_sizes = dict()
    for block in blocks:
        block_sizes[block["addr"]] = block["size"]
    return block_sizes


def generate_opcodes_db(packet_handler_ea, switch, opcode_offset, block_sizes):
    opcodes_db = dict()

    for case_ea, data in switch.items():
        resolved_opcodes = [int(opcode) + opcode_offset for opcode in data["opcodes"]]
        opcodes_db[resolved_opcodes[0]] = {
            "case_ea": case_ea,
            "rel_ea": case_ea - packet_handler_ea,
            "opcodes": resolved_opcodes,
            "size": block_sizes[case_ea] if case_ea in block_sizes else 0,
        }
    return opcodes_db


def extract_opcode_data(exe_file):
    from utils import eprint, create_r2_byte_pattern, sync_r2_output

    import r2pipe

    r2 = r2pipe.open(exe_file, ["-2"])
    eprint(f"Radare loaded {exe_file}")

    sync_r2_output(r2)

    sem_ver = get_sem_ver(exe_file)
    p = create_r2_byte_pattern(get_zone_proto_down_sig(sem_ver))
    target = r2.cmd(f"/x {p}").split()[0]  # Find byte pattern
    packet_handler_ea = int(target, 16)
    r2.cmd(f"s {target}")  # Seek to target

    ## STEP 1: Grab switch cases
    r2.cmd("f--")  # Delete existing flags
    r2.cmd("afr")  # Analyze function recursively
    switch_cases = r2.cmdj(f"fj")

    eprint(f"  Loaded switch cases")

    ## STEP 2: Grab opcode offset
    p = create_r2_byte_pattern(get_opcode_offset_sig(sem_ver))
    opcode_offset_target = r2.cmd(f"/x {p}").split()[0]  # Find byte pattern
    packet_handler_ea = int(opcode_offset_target, 16)
    r2.cmd(f"s {opcode_offset_target}")  # Seek to target

    if semver.compare(sem_ver, "7.2.0") >= 0:
        opcode_offset = get_opcode_offset_7_20(r2)
    else:
        opcode_offset = get_opcode_offset(r2)
    eprint(f"  Found opcode offset: {opcode_offset}")

    r2.cmd(f"s {target}")  # Seek to original target

    ## STEP 3: Grab blocks from packet handler
    blocks = r2.cmdj("afbj")

    r2.quit()

    eprint(f"  Grabbed blocks from packet handler")

    ## STEP 4: Process data
    switch_ea, packet_handler_switch = get_correct_switch(packet_handler_ea, switch_cases)
    eprint(f"  Found switch at {switch_ea}")

    block_sizes = get_block_sizes(blocks)
    opcodes_db = generate_opcodes_db(
        packet_handler_ea, packet_handler_switch, opcode_offset, block_sizes
    )

    eprint(f"  Loaded {len(opcodes_db)} cases from packet handler")

    return opcodes_db


def find_closest_rel_ea(opcodes_db, dest):
    closest = fucked_distance
    closest_opcode = None

    for opcode, case in opcodes_db.items():
        rel_ea = case["rel_ea"]

        num = abs(rel_ea - dest)

        if num < closest:
            closest = num
            closest_opcode = opcode
    return (closest, closest_opcode)


def get_opcodes_str(opcodes):
    return ", ".join([hex(o) for o in opcodes])


def add_match_case(cases, case):
    # check if case already exists

    for c in cases:
        if c["rel_ea"] == case["rel_ea"]:
            return

    cases.append(case)


def find_opcode_matches(old_opcodes_db, new_opcodes_db):
    matches = []
    new_opcodes = list(new_opcodes_db.keys())

    for k, case in enumerate(old_opcodes_db.values()):
        old_opcodes = case["opcodes"]

        # see if we can get a match for the relative ea first
        dist, dist_match_opcode = find_closest_rel_ea(new_opcodes_db, case["rel_ea"])

        if dist == fucked_distance:
            continue

        order_match_opcode = new_opcodes[k]

        order_match = new_opcodes_db[order_match_opcode]
        dist_match = new_opcodes_db[dist_match_opcode]

        size_diff = abs(dist_match["size"] - case["size"])

        # see if the rva matches for the cases found by the distance and order
        if dist_match["rel_ea"] == order_match["rel_ea"] and size_diff < max_size_diff:
            matches.append((old_opcodes, order_match["opcodes"]))

    return matches


@click.command()
@click.argument(
    "old_exe", type=click.Path(exists=True, dir_okay=False, resolve_path=True)
)
@click.argument(
    "new_exe", type=click.Path(exists=True, dir_okay=False, resolve_path=True)
)
def minor_patch_diff(old_exe, new_exe):
    """
    Generates an opcode diff file for minor patches (e.g 6.30 => 6.30h).

    This script outputs to stdout, so pipe it to a json file.

    The format of the output is a list (all fields are optional):

    \b
    [
        {
            "old": (list of opcodes in the switch case),
            "new": (list of opcodes in the switch case),
        },
        ...
    ]

    Example:

    python minor_patch_diff.py ffxiv_dx11.old.exe ffxiv_dx11.new.exe > diff.json
    """
    old_opcodes_db = extract_opcode_data(old_exe)
    new_opcodes_db = extract_opcode_data(new_exe)

    opcodes_found = find_opcode_matches(old_opcodes_db, new_opcodes_db)
    opcodes_object = []

    for old, new in opcodes_found:
        opcodes_object.append(
            {
                "old": [hex(o) for o in old],
                "new": [hex(o) for o in new],
            }
        )

    print(json.dumps(opcodes_object, indent=2))


if __name__ == "__main__":
    minor_patch_diff()
