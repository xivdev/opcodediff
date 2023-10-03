import click
from vtable_alignment import Similarity

from utils import HexIntParamType


@click.command()
@click.argument(
    "similarity_json_file",
    type=click.Path(exists=True, dir_okay=False, resolve_path=True),
)
@click.argument("opcode", type=HexIntParamType())
@click.option(
    "--reverse",
    is_flag=True,
    help="Prints a column of the similarity matrix given a new opcode",
)
@click.option(
    "--accept",
    default=None,
    help="Modifies the similarity matrix file by accepting the match between the opcode argument and the argument to this option",
    type=HexIntParamType(),
)
def debug_similarity_matrix(similarity_json_file, opcode, reverse, accept):
    """
    Given an old opcode, debug prints a row of the similarity matrix generated
    from generate_similarity_matrix.py.

    Example:
    python debug_similarity_matrix.py similarity.json 0x200
    """

    entries = dict()
    similarity = Similarity(similarity_json_file)

    if accept is not None:
        similarity.accept(opcode, accept)
        similarity.write_to_file(similarity_json_file)
        return

    if reverse:
        print("Checking column of matrix since --reverse was provided")
        for old_opcode in similarity.old_opcodes:
            entries[old_opcode] = similarity.lookup(old_opcode, opcode)
    else:
        for new_opcode in similarity.new_opcodes:
            entries[new_opcode] = similarity.lookup(opcode, new_opcode)

    max_opcode = 0
    max_score = -9999

    print(f"Similarities for {hex(opcode)}")

    entries = list(entries.items())
    entries.sort(key=lambda x: x[1], reverse=True)
    for candidate, similarity in entries:
        print(f"\t{hex(candidate)} => {similarity}")
        if similarity > max_score:
            max_opcode = candidate
            max_score = similarity

    print("Best match")
    print(f"{hex(max_opcode)} => {max_score}")


if __name__ == "__main__":
    debug_similarity_matrix()
