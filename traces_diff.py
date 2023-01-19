import click
import torch
from asm2vec.utils import (
    TraceData,
    AsmDataset,
    preprocess,
    train,
    save_model,
    cosine_similarities,
)
from asm2vec.datatype import Tokens
import json

import Levenshtein as lev


class OpcodeMatcher:
    def __init__(
        self,
        cosine_similarity_matrix,
        old_trace_data: TraceData,
        new_trace_data: TraceData,
    ):
        self.csm = cosine_similarity_matrix
        self.old_trace_data = old_trace_data
        self.new_trace_data = new_trace_data

        self.old_functions = list(old_trace_data.traces.keys())
        self.new_functions = list(new_trace_data.traces.keys())

        self.old_ptr_opcodes = self.__enumerate_ptr_opcodes(old_trace_data)
        self.new_ptr_opcodes = self.__enumerate_ptr_opcodes(new_trace_data)

        self.cand_dict = None

    def length_heuristic(self, old_idx, new_idx, debug=False):
        """
        Function length heuristic (since asm2vec is terrible at handling mismatched lengths)

        Returns a similarity metric in the range [0, 1]
        """
        l0 = len(self.old_functions[old_idx].insts)
        l1 = len(self.new_functions[new_idx].insts)
        length_diff = abs(l0 - l1)
        # Weight mismatched lengths considerably lower, but clip factor to 0
        length_factor = max(1 - 4 * (length_diff / (l0 + l1)), 0)
        if debug:
            print("Length factor", l0, l1, length_factor)
        return length_factor

    def constants_heuristic(self, old_opcode, new_opcode, debug=False):
        """
        Constants vector heuristic.
        Runs a bit slow because it uses Levenshtein distance.

        Returns a similarity metric in the range [0, 1]
        """
        v0 = self.old_trace_data.constants_vectors[old_opcode]
        v1 = self.new_trace_data.constants_vectors[new_opcode]
        constants_diff = lev.distance(v0[:50], v1[:50])
        # Weight any constants differences harshly, but clip factor to 0
        constants_factor = max(1 - (constants_diff * 0.1), 0)
        if debug:
            print("Constants factor", constants_diff)
            print("v0", v0)
            print("v1", v1)
        return constants_factor

    def case_length_heuristic(self, old_opcode, new_opcode, debug=False):
        """
        Number of opcodes in case heuristic.

        This one has questionable value because cases with different number of
        opcodes are already different enough from other cases.

        Returns a similarity metric in the range [0, 1]
        """
        n0 = len(self.old_trace_data.opcode_sets[old_opcode])
        n1 = len(self.new_trace_data.opcode_sets[new_opcode])
        case_length_diff = abs(n0 - n1)
        case_length_factor = max(1 - case_length_diff * 0.1, 0)
        if debug:
            print("Case length factor", n0, n1, case_length_diff)

        return case_length_factor

    @staticmethod
    def __enumerate_ptr_opcodes(trace_data: TraceData):
        ptr_opcodes = []
        for id, data in trace_data.ids.items():
            idx = data["idx"]
            for opcode in data["ptr_opcodes"]:
                ptr_opcodes.append((idx, opcode))
        return ptr_opcodes

    def initialize_candidates(self):
        """
        Generates a table of candidate matches between old pointer opcodes and
        new pointer opcodes.
        """
        self.cand_dict = dict()

        for (old_idx, old_opcode) in self.old_ptr_opcodes:
            candidates = []
            for (new_idx, new_opcode) in self.new_ptr_opcodes:
                length_factor = self.length_heuristic(old_idx, new_idx)
                constants_factor = self.constants_heuristic(old_opcode, new_opcode)
                case_length_factor = self.case_length_heuristic(old_opcode, new_opcode)
                # Since cosine similarity is in the range (-1, 1), add 1 to push it
                # into the range (0, 2).
                cs = self.csm[old_idx, new_idx] + 1

                # Multiply all these factors together to yield some value in the range
                # (0, 2), then subtract 1 to get a score from range (-1, 1)
                score = length_factor * constants_factor * case_length_factor * cs - 1
                candidates.append((new_opcode, score))
            candidates.sort(key=lambda x: x[1], reverse=True)

            if candidates[0][1] < -0.99:
                # If the top match is this low, then the heuristics screwed up the
                # candidates, so we'll have to go with just the cosine similarity metric
                candidates = [
                    (new_opcode, self.csm[old_idx, new_idx])
                    for (new_idx, new_opcode) in self.new_ptr_opcodes
                ]
                candidates.sort(key=lambda x: x[1], reverse=True)
                candidates = candidates[:5]

            self.cand_dict[old_opcode] = candidates

    def accept_confident_matches(self, matches, threshold=0.1):
        """
        Accepts matches for candidates where the score difference between the
        first and second best match is wider than the given threshold.
        """
        num_new_matches = 0
        accepted_match_targets = set()
        unmatched = []

        for opcode, candidates in self.cand_dict.items():
            if len(candidates) == 1 or (
                len(candidates) > 1
                and (candidates[0][1] - candidates[1][1] > threshold)
            ):
                matches[opcode] = {
                    "match": candidates[0][0],
                    "score_lead": candidates[0][1] - candidates[1][1]
                    if len(candidates) > 1
                    else 0,
                }
                accepted_match_targets.add(candidates[0][0])
                num_new_matches += 1
            else:
                unmatched.append((opcode, candidates))

        # Filter out match candidates that have already been matched
        new_candidates = dict()
        for opcode, candidates in unmatched:
            new_candidates[opcode] = [
                (cand_opcode, score)
                for (cand_opcode, score) in candidates
                if cand_opcode not in accepted_match_targets
            ]

        self.cand_dict = new_candidates
        return num_new_matches

    def find_opcode_matches(self, threshold=0.1):
        """
        Returns the best matches between old pointer opcodes and new pointer
        opcodes where the confidence is greater than the given threshold.
        """
        matches = dict()
        self.initialize_candidates()
        num_new_matches = self.accept_confident_matches(matches, threshold)
        print("First pass added", num_new_matches, "matches")
        while num_new_matches > 0:
            num_new_matches = self.accept_confident_matches(matches, threshold)
            print("Added", num_new_matches, "additional matches")
        return matches

    def find_matches_and_nonmatches(self):
        """
        Returns the following information:

        1. The best matches between old pointer opcodes and new pointer
        opcodes where the confidence is greater than the given threshold.
        2. Old opcodes for which a match could not be confidently found.
        3. New opcodes for which a match could not be confidently found.

        The format of the output is a list (all fields are optional):
        [
            {
                "old": (list of opcodes in the switch case),
                "new": (list of opcodes in the switch case),
                "score_lead": (confidence above 2nd best match),
                "unknown": (true if a match was not made in this case),
                "candidates: [
                    {
                        "set": (list of opcodes in switch case),
                        "score": (candidate score),
                    }
                    ...
                ]
            }
        ]
        """
        output = []

        matches = self.find_opcode_matches()
        old_opcode_sets = self.old_trace_data.opcode_sets
        new_opcode_sets = self.new_trace_data.opcode_sets

        for opcode, data in matches.items():
            output.append(
                {
                    "old": [hex(old_opcode) for old_opcode in old_opcode_sets[opcode]],
                    "new": [
                        hex(new_opcode) for new_opcode in new_opcode_sets[data["match"]]
                    ],
                    "score_lead": str(data["score_lead"]),
                }
            )

        for opcode, candidates in self.cand_dict.items():
            output.append(
                {
                    "old": [hex(old_opcode) for old_opcode in old_opcode_sets[opcode]],
                    "candidates": [
                        {
                            "set": [
                                hex(new_opcode)
                                for new_opcode in new_opcode_sets[candidate]
                            ],
                            "score": str(score),
                        }
                        for (candidate, score) in candidates
                        if score > -1.0
                    ],
                    "unknown": True,
                }
            )

        unmatched_new_opcodes = set([opcode for (idx, opcode) in self.new_ptr_opcodes])
        for data in matches.values():
            if data["match"] in unmatched_new_opcodes:
                unmatched_new_opcodes.discard(data["match"])

        for unmatched_opcode in unmatched_new_opcodes:
            output.append(
                {
                    "new": [
                        hex(new_opcode)
                        for new_opcode in new_opcode_sets[unmatched_opcode]
                    ],
                    "unknown": True,
                }
            )

        return output


def print_banner(text):
    print("")
    print(f"======= {text} =======")
    print("")


@click.command()
@click.argument(
    "old_traces", type=click.Path(exists=True, file_okay=False, resolve_path=True)
)
@click.argument(
    "new_traces", type=click.Path(exists=True, file_okay=False, resolve_path=True)
)
@click.argument("output_file", type=click.Path(dir_okay=False, resolve_path=True))
def traces_diff(old_traces, new_traces, output_file):
    tokens = Tokens()
    old_trace_data = TraceData.load_data(old_traces, tokens)
    new_trace_data = TraceData.load_data(new_traces, tokens)

    opath = "model.pt"

    def training_callback(context):
        progress = f'{context["epoch"]} | time = {context["time"]:.2f}, loss = {context["loss"]:.4f}'
        if context["accuracy"]:
            progress += f', accuracy = {context["accuracy"]:.4f}'
        print(progress)
        save_model(opath, context["model"], context["tokens"])

    training_params = {
        "embedding_size": 100,
        "batch_size": 1024,
        "epochs": 20,
        "neg_sample_num": 25,
        "calc_acc": True,
        "device": "cuda" if torch.cuda.is_available() else "cpu",
        "callback": training_callback,
        "learning_rate": 0.02,
    }

    print_banner("Training embeddings from scratch on old trace data")
    model = train(old_trace_data, **training_params)

    # Prepare the model for new trace data and freeze all training from old trace data
    model.init_estimation_mode(len(new_trace_data.traces))

    print_banner("Calculating embeddings for new trace data")
    model = train(new_trace_data, model=model, mode="test", **training_params)

    print_banner("Calculating cosine similarities")
    csm = cosine_similarities(model)

    print_banner("Calculating matches between opcodes")
    matcher = OpcodeMatcher(csm, old_trace_data, new_trace_data)
    compiled_data = matcher.find_matches_and_nonmatches()

    with open(output_file, "w+") as f:
        json.dump(compiled_data, f, indent=2)
        print_banner(f"Output written to {output_file}")


if __name__ == "__main__":
    traces_diff()
