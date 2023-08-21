import click
from vtable_alignment import Similarity

from utils import HexIntParamType


@click.command()
@click.argument(
    "similarity_json_file",
    type=click.Path(exists=True, dir_okay=False, resolve_path=True),
)
@click.argument("opcode", type=HexIntParamType())
def debug_similarity_matrix(similarity_json_file, opcode):
    """
    Given an old opcode, debug prints a row of the similarity matrix generated
    from generate_similarity_matrix.py.

    Example:
    python debug_similarity_matrix.py similarity.json 0x200
    """

    entries = dict()
    similarity = Similarity(similarity_json_file)
    for new_opcode in similarity.new_opcodes:
        entries[new_opcode] = similarity.lookup(opcode, new_opcode)

    max_opcode = 0
    max_score = -9999

    print(f"Similarities for {hex(opcode)}")

    for new_opcode, similarity in entries.items():
        print(f"\t{hex(new_opcode)} => {similarity}")
        if similarity > max_score:
            max_opcode = new_opcode
            max_score = similarity

    print("Best match")
    print(f"{hex(max_opcode)} => {max_score}")


if __name__ == "__main__":
    debug_similarity_matrix()
