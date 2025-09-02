import click
import json

from analysis_utils import (
    get_correct_switch,
    get_packet_handler_addr,
    get_packet_handler_opcode_offset,
    get_packet_handler_switch_addr,
)

fucked_distance = 0xFFFFFFFF
max_size_diff = 10


def get_block_sizes(blocks):
    block_sizes = dict()
    for block in blocks:
        block_sizes[block["addr"]] = block["size"]
    return block_sizes


def generate_opcodes_db(packet_handler_ea, switch, opcode_offset, block_sizes):
    opcodes_db = dict()
    packet_handler_ea = int(packet_handler_ea, 16)
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
    from utils import eprint, sync_r2_output

    import r2pipe

    r2 = r2pipe.open(exe_file, ["-2"])
    eprint(f"Radare loaded {exe_file}")

    sync_r2_output(r2)

    target = get_packet_handler_addr(r2, exe_file)
    r2.cmd(f"s {target}")  # Seek to target

    ## STEP 1: Grab switch cases
    r2.cmd("f--")  # Delete existing flags
    r2.cmd("afr")  # Analyze function recursively
    switch_cases = r2.cmdj(f"fj")

    eprint(f"  Loaded switch cases")

    ## STEP 2: Get opcode offset
    opcode_offset = get_packet_handler_opcode_offset(r2, exe_file)
    eprint(f"  Found opcode offset: {opcode_offset}")

    r2.cmd(f"s {target}")  # Seek to original target

    ## STEP 3: Grab blocks from packet handler
    blocks = r2.cmdj("afbj")

    r2.quit()

    eprint(f"  Grabbed blocks from packet handler")

    ## STEP 4: Process data
    packet_handler_ea = get_packet_handler_switch_addr(r2, exe_file)
    switch_ea, packet_handler_switch = get_correct_switch(
        packet_handler_ea, switch_cases
    )
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
    DEPRECATED. Use vtable_diff.py instead. It's a more reliable method of
    getting the diff for a minor patch.

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
