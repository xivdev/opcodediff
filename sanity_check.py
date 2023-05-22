import json
import re
import click


def load_diff_file(f):
    diff = dict()
    diff_json = json.load(f)
    for pair in diff_json:
        if "old" not in pair or "new" not in pair:
            continue
        for old_opcode in pair["old"]:
            diff[int(old_opcode, 16)] = set(
                (int(new_opcode, 16) for new_opcode in pair["new"])
            )
    return diff


@click.command()
@click.argument("vtable_diff", type=click.File("r"))
@click.argument("minor_patch_diff", type=click.File("r"))
def sanity_check(vtable_diff, minor_patch_diff):
    """
    Compares two JSON diff files to cross-check results from the different
    scripts in this repo.

    Example:

    python sanity_check.py vtable_diff.json minor_patch_diff.json
    """
    diff1 = load_diff_file(vtable_diff)
    diff2 = load_diff_file(minor_patch_diff)

    all_good = True
    for old_opcode, new_opcodes in diff2.items():
        if old_opcode not in diff1:
            if len(new_opcodes) < 50:
                print(f"Missing old opcode in vtable diff: {old_opcode}")
                all_good = False
            continue

        other_new_opcodes = diff1[old_opcode]
        if list(other_new_opcodes)[0] not in new_opcodes:
            print(f"vtable diff mismatch for case {old_opcode} => {other_new_opcodes}")
            all_good = False

    if all_good:
        print("Sanity check OK")
    else:
        print("Errors detected")


if __name__ == "__main__":
    sanity_check()
