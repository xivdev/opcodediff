import json
import re
import click


def load_diff_file(f, reverse=False):
    diff = dict()
    diff_json = json.load(f)
    for pair in diff_json:
        if "old" not in pair or "new" not in pair:
            continue
        old_key = "new" if reverse else "old"
        new_key = "old" if reverse else "new"
        for old_opcode in pair[old_key]:
            diff[int(old_opcode, 16)] = set(
                (int(new_opcode, 16) for new_opcode in pair[new_key])
            )
    return diff


def opcodes_str(opcodes):
    if len(opcodes) == 1:
        return hex(list(opcodes)[0])
    elif len(opcodes) > 1:
        return " or ".join((hex(opcode) for opcode in opcodes))
    else:
        return "UNKNOWN"


def replace_line_with_new_opcode(line, diff, ver, old_ver):
    match_groups = re.findall(
        r"^(\s*[^\/]\w+\s*)=\s*(.*),(\s*)\/\/.*" + old_ver + "$", line
    )
    if len(match_groups) != 1:
        return line

    opcode_name = match_groups[0][0]
    opcode_val = match_groups[0][1]
    comment_spacing = match_groups[0][2]
    if " or " in opcode_val:
        old_opcode = int(opcode_val.split(" or ")[0], 16)
    else:
        old_opcode = int(opcode_val, 16)
    if old_opcode in diff:
        new_opcodes = diff[old_opcode]
        return f"{opcode_name}= {opcodes_str(new_opcodes)},{comment_spacing}// updated {ver}\n"

    return f"{line}"


@click.command()
@click.argument("old_version_string")
@click.argument("new_version_string")
@click.argument("diff_file", type=click.File("r"))
@click.argument("opcodes_file", type=click.File("r"))
@click.option(
    "--reverse", is_flag=True, help="Applies the diff file in the opposite direction"
)
@click.option(
    "-o", "--output", type=click.Path(exists = False, resolve_path=True), help="Output filename"
)
def generate_opcodes_file(
    old_version_string, new_version_string, diff_file, opcodes_file, reverse, output
):
    """
    Parses an OPCODES_FILE and applies a JSON DIFF_FILE to generate a new one.
    The opcodes file is basically anything that has syntax resembling Sapphire's
    `Ipcs.h`. It doesn't do any C++ header parsing; it's just a bunch of regexes
    slapped together but it works.

    Example:

    python generate_opcodes_file.py 6.30 6.30h diff.json Ipcs.h
    """
    diff = load_diff_file(diff_file, reverse)
    queued_lines = []
    for line in opcodes_file.readlines():
        queued_lines.append(
            replace_line_with_new_opcode(
                line,
                diff,
                new_version_string,
                old_version_string,
            )
        )

    if output:
        new_filename = output
    else:
        new_filename = f"Ipcs.{new_version_string}.h"
    with open(new_filename, "w+") as f:
        f.writelines(queued_lines)

    print("Wrote to", new_filename)


if __name__ == "__main__":
    generate_opcodes_file()
