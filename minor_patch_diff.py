import click
import json
import re

ZONE_PROTO_DOWN_SIG = "48 89 ? 24 ? ? 48 83 EC 50 8B F2 49 8B"

fucked_distance = 0xFFFFFFFF
max_size_diff = 10


def get_opcode_offset(r2):
    orig_loc = r2.cmd("s")  # Save original spot
    r2.cmd("aei")  # Initialize ESIL VM
    r2.cmd("aeim")  # Initialize ESIL VM stack
    r2.cmd("aeip")  # Initialize ESIL VM IP to curseek

    r2.cmd("aecc")  # continue until call
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


def get_longest_switch(switch_cases):
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

    longest_switch = dict()
    for switch_ea in switches:
        if len(switches[switch_ea].keys()) > len(longest_switch):
            longest_switch = switches[switch_ea]

    return longest_switch


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

    p = create_r2_byte_pattern(ZONE_PROTO_DOWN_SIG)
    target = r2.cmd(f"/x {p}").split()[0]  # Find byte pattern
    packet_handler_ea = int(target, 16)

    r2.cmd(f"s {target}")  # Seek to target

    ## STEP 1: Grab switch cases
    r2.cmd("f--")  # Delete existing flags
    r2.cmd("afr")  # Analyze function recursively
    switch_cases = r2.cmdj(f"fj")

    eprint(f"  Loaded switch cases")

    ## STEP 2: Grab opcode offset

    opcode_offset = get_opcode_offset(r2)
    eprint(f"  Found opcode offset: {opcode_offset}")

    ## STEP 3: Grab blocks from packet handler
    blocks = r2.cmdj("afbj")

    r2.quit()

    eprint(f"  Grabbed blocks from packet handler")

    ## STEP 4: Process data
    packet_handler_switch = get_longest_switch(switch_cases)
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
    old_opcodes_db = extract_opcode_data(old_exe)
    new_opcodes_db = extract_opcode_data(new_exe)

    opcodes_found = find_opcode_matches(old_opcodes_db, new_opcodes_db)
    opcodes_object = []

    for k, v in enumerate(opcodes_found):
        old, new = v

        opcodes_object.append(
            {
                "old": [hex(o) for o in old],
                "new": [hex(o) for o in new],
            }
        )

    print(json.dumps(opcodes_object, indent=2))


if __name__ == "__main__":
    minor_patch_diff()
