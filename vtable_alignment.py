import click
import json
import numpy as np

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
            # max(Match, Insertion, Deletion)
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


class Placeholder:
    def __init__(self, old, new):
        self.old = old
        self.new = new


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
        self.matrix = np.array(data["matrix"])
        self.warnings = set()

    def lookup(self, old_opcode, new_opcode):
        if isinstance(old_opcode, Placeholder) or isinstance(new_opcode, Placeholder):
            return -9999

        if old_opcode not in self.old_opcodes:
            self.warnings.add(
                f"WARNING: Could not find old opcode {hex(old_opcode)} in similarity matrix"
            )
            return 0
        if new_opcode not in self.new_opcodes:
            self.warnings.add(
                f"WARNING: Could not find new opcode {hex(new_opcode)} in similarity matrix"
            )
            return 0
        i = self.old_opcodes[old_opcode]
        j = self.new_opcodes[new_opcode]
        return self.matrix[i][j]

    def get_confident_matches(self, threshold=0.1):
        """
        Returns matches in the form of [(old,new), ...] that are confidently
        above the score threshold and where all pairs in the matching prefer
        each other over any other opcodes.
        """
        scores = {}
        new_opcodes = np.array([op for op in self.new_opcodes])
        for old_op, i in self.old_opcodes.items():
            top_n_idxs = np.argpartition(-self.matrix[i], 2)[:2]
            scores[old_op] = [(new_opcodes[j], self.matrix[i][j]) for j in top_n_idxs]
            scores[old_op].sort(key=lambda x: x[1], reverse=True)

        transposed_matrix = self.matrix.transpose()
        rev_scores = {}
        old_opcodes = np.array([op for op in self.old_opcodes])
        for new_op, j in self.new_opcodes.items():
            top_n_idxs = np.argpartition(-transposed_matrix[j], 2)[:2]
            rev_scores[new_op] = [
                (old_opcodes[i], transposed_matrix[j][i]) for i in top_n_idxs
            ]
            rev_scores[new_op].sort(key=lambda x: x[1], reverse=True)

        # Accept matches if they pass the threshold in the old => new direction,
        # and if the new => old direction is a best match
        matches = []
        for old_op, top_matches in scores.items():
            new_op = top_matches[0][0]
            if top_matches[0][1] - top_matches[1][1] >= threshold:
                rev_top_matches = rev_scores[new_op]
                if (
                    rev_top_matches[0][0] == old_op
                    and rev_top_matches[0][1] > 0
                    and rev_top_matches[0][1] - rev_top_matches[1][1] >= threshold
                ):
                    matches.append((old_op, new_op))

        return matches

    def clear_warnings(self):
        self.warnings = set()

    def print_warnings(self):
        for warning in self.warnings:
            eprint(warning)


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

    matches = similarity.get_confident_matches()

    # Ensure matches at least exist somewhere in the seq
    old_seq_set = set(old_seq)
    new_seq_set = set(new_seq)
    matches = list(
        filter(lambda x: x[0] in old_seq_set and x[1] in new_seq_set, matches)
    )

    eprint(f'Found {len(matches)} "confident" matches')

    eprint("Running initial alignment...")
    alignment, score = needleman_wunsch(old_seq, new_seq, similarity, -1)

    similarity.print_warnings()
    eprint(f"Alignment score: {score}")

    # Check for mismatches
    matched_old = {match[0]: match[1] for match in matches}

    mismatched_old = set()
    mismatched_new = dict()
    for old, new in alignment:
        if old in matched_old and matched_old[old] != new:
            truth = matched_old[old]
            eprint(f"Mismatch detected! {hex(old)} => {hex(truth)}, got {hex(new)}")
            mismatched_old.add(old)
            mismatched_new[truth] = Placeholder(old, truth)

    eprint("Attempting to fix mismatches")
    old_seq = list(filter(lambda x: x not in mismatched_old, old_seq))
    new_seq = list(
        map(lambda x: mismatched_new[x] if x in mismatched_new else x, new_seq)
    )

    alignment, score = needleman_wunsch(old_seq, new_seq, similarity, -1)

    old_seq = []
    new_seq = []
    for old, target in alignment:
        if isinstance(target, Placeholder):
            old_seq.append(target.old)
            new_seq.append(target.new)
        else:
            if old is not None:
                old_seq.append(old)
            if target is not None:
                new_seq.append(target)

    similarity.clear_warnings()
    alignment, score = needleman_wunsch(old_seq, new_seq, similarity, -1)
    similarity.print_warnings()
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
