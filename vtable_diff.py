import click
import json

from minor_patch_diff import get_longest_switch
from utils import eprint, create_r2_byte_pattern, sync_r2_output
import r2pipe

ON_RECEIVE_PACKET_SIG = "49 8B 40 10 4C 8B 50 38"


def get_opcode_offset(r2):
    orig_loc = r2.cmd("s")  # Save original spot
    r2.cmd("aei; aeim; aeip")  # Initialize ESIL VM, stack, instruction pointer
    r2.cmd('"aesue rax,0x0,>"')  # continue until rax changes
    r2.cmd('"aesue rax,0x0,>"')  # continue until rax changes again
    r2.cmd("aeso")  # step
    r2.cmd("aer rax=0x200")  # set rax to some arbitrary number
    r2.cmd("aeso")  # step
    regs = r2.cmdj("arj")
    new_rax = regs["rax"]
    opcode_offset = 0x200 - new_rax

    # Clear the ESIL environment
    r2.cmd("ar0; aeim-; aei-")
    r2.cmd(f"s {orig_loc}")  # Seek back to original spot

    return opcode_offset


def extract_opcode_data(exe_file):

    r2 = r2pipe.open(exe_file, ["-2"])
    eprint(f"Radare loaded {exe_file}")

    sync_r2_output(r2)

    p = create_r2_byte_pattern(ON_RECEIVE_PACKET_SIG)
    target = r2.cmd(f"/x {p}").split()[0]  # Find byte pattern

    r2.cmd(f"s {target}")  # Seek to target

    ## STEP 1: Grab switch cases
    r2.cmd("f--")  # Delete existing flags
    r2.cmd("afr")  # Analyze function recursively
    switch_cases = r2.cmdj(f"fj")

    eprint(f"  Loaded switch cases")

    ## STEP 2: Grab opcode offset

    opcode_offset = get_opcode_offset(r2)
    eprint(f"  Found opcode offset: {opcode_offset}")

    r2.quit()

    eprint(f"  Grabbed blocks from packet handler")

    ## STEP 4: Process data
    opcodes_db = dict()
    packet_handler_switch = get_longest_switch(switch_cases)
    vtable_offset = 0x10
    for data in packet_handler_switch.values():
        if len(data["opcodes"]) > 10:
            continue
        opcodes_db[vtable_offset] = int(data["opcodes"][0]) + opcode_offset
        vtable_offset += 0x8

    eprint(f"  Loaded {len(opcodes_db)} cases from packet handler")
    return opcodes_db


def find_opcode_matches(old_opcodes_db, new_opcodes_db):
    matches = []

    for (offset, old_opcode) in old_opcodes_db.items():
        if offset in new_opcodes_db:
            matches.append((old_opcode, new_opcodes_db[offset]))

    return matches


@click.command()
@click.argument(
    "old_exe", type=click.Path(exists=True, dir_okay=False, resolve_path=True)
)
@click.argument(
    "new_exe", type=click.Path(exists=True, dir_okay=False, resolve_path=True)
)
def vtable_diff(old_exe, new_exe):
    """
    Generates an opcode diff file by comparing vtables.

    This script outputs to stdout, so pipe it to a json file.

    The format of the output is a list (all fields are optional):

    \b
    [
        {
            "old": [opcode],
            "new": [opcode],
        },
        ...
    ]

    Example:

    python vtable_diff.py ffxiv_dx11.old.exe ffxiv_dx11.new.exe > diff.json
    """
    old_opcodes_db = extract_opcode_data(old_exe)
    new_opcodes_db = extract_opcode_data(new_exe)

    opcodes_found = find_opcode_matches(old_opcodes_db, new_opcodes_db)
    opcodes_object = []

    for (old, new) in opcodes_found:
        opcodes_object.append(
            {
                "old": [hex(old)],
                "new": [hex(new)],
            }
        )

    print(json.dumps(opcodes_object, indent=2))


if __name__ == "__main__":
    vtable_diff()
