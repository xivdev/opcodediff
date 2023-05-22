import click
import json

from vtable_diff import extract_opcode_data
from utils import eprint


def needleman_wunsch(old_seq, new_seq, similarity, gap_penalty):
    """
    The Needleman-Wunsch algorithm adapted from
    https://github.com/farhanma/pyseq/blob/master/functions1_3.py

    Returns (alignment, alignment_score)
    """

    # Stage 1: Create a zero matrix and fills it via algorithm
    n, m = len(old_seq), len(new_seq)
    mat = []
    for i in range(n + 1):
        mat.append([0] * (m + 1))
    for j in range(m + 1):
        mat[0][j] = gap_penalty * j
    for i in range(n + 1):
        mat[i][0] = gap_penalty * i
    for i in range(1, n + 1):
        for j in range(1, m + 1):
            mat[i][j] = max(
                mat[i - 1][j - 1] + similarity.lookup(old_seq[i - 1], new_seq[j - 1]),
                mat[i][j - 1] + gap_penalty,
                mat[i - 1][j] + gap_penalty,
            )

    # Stage 2: Computes the final alignment, by backtracking through matrix
    alignment = []
    i, j = n, m
    while i and j:
        score, scoreDiag, scoreUp, scoreLeft = (
            mat[i][j],
            mat[i - 1][j - 1],
            mat[i - 1][j],
            mat[i][j - 1],
        )
        if score == scoreDiag + similarity.lookup(old_seq[i - 1], new_seq[j - 1]):
            alignment.append((old_seq[i - 1], new_seq[j - 1]))
            i -= 1
            j -= 1
        elif score == scoreUp + gap_penalty:
            alignment.append((old_seq[i - 1], None))
            i -= 1
        elif score == scoreLeft + gap_penalty:
            alignment.append((None, new_seq[j - 1]))
            j -= 1
    while i:
        alignment.append((old_seq[i - 1], None))
        i -= 1
    while j:
        alignment.append((None, new_seq[j - 1]))
        j -= 1

    # Since we were backtracking, we reverse the collected alignment
    alignment.reverse()

    return alignment, mat[n][m]


class Similarity:
    def __init__(self, similarity_json_file):
        with open(similarity_json_file) as f:
            data = json.load(f)

        self.old_opcodes = {
            opcode: idx for (idx, opcode) in enumerate(data["old_opcodes"])
        }
        self.new_opcodes = {
            opcode: idx for (idx, opcode) in enumerate(data["new_opcodes"])
        }
        self.__matrix = data["matrix"]

    def lookup(self, old_opcode, new_opcode):
        if old_opcode not in self.old_opcodes:
            eprint(
                f"WARNING: Could not find old opcode {hex(old_opcode)} in similarity matrix"
            )
            return 0
        if new_opcode not in self.new_opcodes:
            eprint(
                f"WARNING: Could not find new opcode {hex(new_opcode)} in similarity matrix"
            )
            return 0
        i = self.old_opcodes[old_opcode]
        j = self.new_opcodes[new_opcode]
        return self.__matrix[i][j]


@click.command()
@click.argument(
    "old_exe", type=click.Path(exists=True, dir_okay=False, resolve_path=True)
)
@click.argument(
    "new_exe", type=click.Path(exists=True, dir_okay=False, resolve_path=True)
)
@click.argument(
    "similarity_json_file",
    type=click.Path(exists=True, dir_okay=False, resolve_path=True),
)
def vtable_alignment(old_exe, new_exe, similarity_json_file):
    """
    A more generalized version of vtable_diff. Generates an opcode
    diff file by running a sequence alignment algorithm and attempting
    to find the optimal global alignment of the vtable opcodes
    from different exe versions.

    Requires a similarity matrix generated from generate_similarity_matrix.py.

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

    python vtable_alignment.py ffxiv_dx11.old.exe ffxiv_dx11.new.exe similarity.json > diff.json
    """
    old_opcodes_db = extract_opcode_data(old_exe)
    new_opcodes_db = extract_opcode_data(new_exe)

    old_seq = [opcode for opcode in old_opcodes_db.values()]
    new_seq = [opcode for opcode in new_opcodes_db.values()]

    similarity = Similarity(similarity_json_file)
    alignment, score = needleman_wunsch(old_seq, new_seq, similarity, -1)
    eprint(f"Alignment score: {score}")

    diff = []
    for old, new in alignment:
        if old is None:
            eprint("New opcode did not find matching old one:", hex(new))
            diff.append({"old": [], "new": [hex(new)]})
        elif new is None:
            eprint("Old opcode did not find matching new one:", hex(old))
            diff.append({"old": [hex(old)], "new": []})
        else:
            diff.append({"old": [hex(old)], "new": [hex(new)]})

    print(json.dumps(diff, indent=2))


if __name__ == "__main__":
    vtable_alignment()
