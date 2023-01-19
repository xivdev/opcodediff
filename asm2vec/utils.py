import os
import time
import torch
from torch.utils.data import DataLoader, Dataset
from pathlib import Path
from .datatype import Tokens, Function, Instruction
from .model import ASM2VEC

import re
import json

CONSTANTS_RE = re.compile(r"(-? 0x[0-9a-f]+)|\*([0-9])| ([0-9])")


class TraceData:
    """
    A class that stores information about traces read from file.

    Terminology:
        Trace/Function:
            The text produced by the generate_deep_traces.py script for each
            opcode switch case.

        Token:
            A numerical representation of the each symbol that appears in the
            trace. The tokens dictionary should be shared across all traces to
            ensure the same representation matches.

        ID:
            A representative identifier for the trace of a switch case. An ID
            may point to more than one switch case, if the traces of those
            switch cases are textually identical (ignoring constants).

        idx:
            Index of the ID/Function. This is necessary to index into the
            training model embeddings.

        Opcode set:
            A set of opcodes that a single switch case covers.

        Pointer Opcode/ptr_opcode:
            A single opcode that represents the opcode set.

        Constants vector:
            Since the training process removes constants from the input text,
            the constants vector is a "signature" generated by looking at
            constants used in the trace. These are correlated with ptr_opcodes
            and not IDs since constants can differ among cases represented by
            the same ID.
    """

    def __init__(self, tokens):
        self.tokens = tokens

        self.traces = dict()
        """
        maps trace => ID.
        See class docstring for more details.
        """

        self.ids = dict()
        """
        maps ID => { idx, [ptr_opcodes...] }.
        See class docstring for more details.
        """

        self.constants_vectors = dict()
        """
        maps ptr_opcode => constants_vector.
        See class docstriing for more details.
        """

        self.opcode_sets = dict()
        """
        maps ptr_opcode => [opcodes...]
        See class docstriing for more details.
        """

    def __process_trace(self, ptr_opcode, text):
        fn = Function.load(text)
        if fn in self.traces:
            id = self.traces[fn]
            self.ids[id]["ptr_opcodes"].append(ptr_opcode)
        else:
            # Use ptr_opcode as an ID
            id = ptr_opcode

            self.traces[fn] = id
            self.tokens.add(fn.tokens())
            self.ids[id] = {
                "idx": len(self.ids),
                "ptr_opcodes": [ptr_opcode],
            }

        self.constants_vectors[ptr_opcode] = self.__get_constants_vector(text)

    def __process_opcode_sets(self, opcode_sets_file):
        with open(opcode_sets_file) as f:
            data = json.load(f)
            self.opcode_sets = {int(op): ops for op, ops in data.items()}

    @staticmethod
    def __read_trace_from_file(f):
        lines = f.readlines()
        normalized_lines = []
        for line in lines:
            normalized_lines.append(" " + line)
        # cap lines at 200 since Asm2Vec performance goes way down if
        # the text is too long
        return "".join(normalized_lines[:200])

    @staticmethod
    def __get_constants_vector(trace):
        constants = []
        for line in trace.strip("\n").split("\n"):
            match = CONSTANTS_RE.search(line)
            if not match or not match.lastindex:
                continue

            const_str = match.group(match.lastindex)
            const_str = "".join(const_str.split())
            const = int(const_str, 16)

            # We only really care about constants less than 10000
            if abs(const) < 10000:
                constants.append(const)
        return constants

    @staticmethod
    def load_data(paths, tokens):
        """Reads traces from paths and returns TraceData for that path."""
        if type(paths) is not list:
            paths = [paths]

        filenames = []
        for path in paths:
            if os.path.isdir(path):
                filenames += [
                    Path(path) / filename
                    for filename in sorted(os.listdir(path))
                    if os.path.isfile(Path(path) / filename)
                ]
            else:
                filenames += [Path(path)]

        trace_data = TraceData(tokens)
        for filepath in filenames:
            filename = os.path.basename(filepath)
            file_split = os.path.splitext(filename)
            file_ext = file_split[-1]
            if file_ext == ".json" and filename == "opcode_sets.json":
                trace_data.__process_opcode_sets(filepath)
            elif file_ext == ".asm":
                ptr_opcode = int(file_split[0], base=16)
                with open(filepath) as f:
                    text = trace_data.__read_trace_from_file(f)
                    trace_data.__process_trace(ptr_opcode, text)

        return trace_data


class AsmDataset(Dataset):
    def __init__(self, x, y):
        self.x = x
        self.y = y

    def __len__(self):
        return len(self.x)

    def __getitem__(self, index):
        return index, self.x[index], self.y[index]


def preprocess(functions, tokens):
    x, y = [], []
    for i, fn in enumerate(functions):
        for j in range(1, len(fn.insts) - 1):
            x.append(
                [i]
                + [
                    tokens[token].index
                    for token in fn.insts[j - 1].tokens() + fn.insts[j + 1].tokens()
                ]
            )
            y.append([tokens[token].index for token in fn.insts[j].tokens()])
    return torch.tensor(x), torch.tensor(y)


def train(
    trace_data: TraceData,
    model=None,
    embedding_size=100,
    batch_size=1024,
    epochs=10,
    neg_sample_num=25,
    calc_acc=False,
    device="cpu",
    mode="train",
    callback=None,
    learning_rate=0.02,
):
    """Trains the model on the provided trace data."""
    functions = trace_data.traces.keys()
    tokens = trace_data.tokens

    if mode == "train":
        if model is None:
            model = ASM2VEC(
                tokens.size(),
                function_size=len(functions),
                embedding_size=embedding_size,
            ).to(device)
        optimizer = torch.optim.Adam(model.parameters(), lr=learning_rate)
    elif mode == "test":
        if model is None:
            raise ValueError("test mode requires a pretrained model")
        optimizer = torch.optim.Adam(model.embeddings_f.parameters(), lr=learning_rate)
    else:
        raise ValueError("Unknown mode")

    # Precompute the token weights so that they are cached for later use
    inp, pos = preprocess(functions, tokens)
    token_weights = tokens.precompute_weights(pos)
    loader = DataLoader(AsmDataset(inp, pos), batch_size=batch_size, shuffle=True)
    for epoch in range(epochs):
        start = time.time()
        loss_sum, loss_count, accs = 0.0, 0, []

        model.train()
        """
        Recall that the model consumes context tokens as input and uses
        embeddings for each output token as an output layer of the network. The
        model should output a high score for the token that correctly matches
        with the given context, and a low score for tokens that don't match the
        given context.

        Our dataloader outputs samples in the form of
        batch_size x (batch_index, input_context, correct_token).
        """
        for i, (batch_indices, inp, pos) in enumerate(loader):
            for j in range(pos.shape[1]):
                # Sample tokens that are not the positive token.
                neg = tokens.sample(token_weights, batch_indices, neg_sample_num)
                pos_token = torch.unsqueeze(pos[:, j], 1)
                loss = model(inp.to(device), pos_token.to(device), neg.to(device))
                loss_sum, loss_count = loss_sum + loss, loss_count + 1

                optimizer.zero_grad()
                loss.backward()
                optimizer.step()

                if i == 0 and calc_acc:
                    probs = model.predict(inp.to(device), pos.to(device))
                    accs.append(accuracy(pos, probs))

        if callback:
            callback(
                {
                    "model": model,
                    "tokens": tokens,
                    "epoch": epoch,
                    "time": time.time() - start,
                    "loss": loss_sum / loss_count,
                    "accuracy": torch.tensor(accs).mean() if calc_acc else None,
                }
            )

    return model


def save_model(path, model, tokens):
    torch.save(
        {
            "model_params": (
                model.embeddings.num_embeddings,
                model.embeddings_f.num_embeddings,
                model.embeddings.embedding_dim,
            ),
            "model": model.state_dict(),
            "tokens": tokens.state_dict(),
        },
        path,
    )


def load_model(path, device="cpu"):
    checkpoint = torch.load(path, map_location=device)
    tokens = Tokens()
    tokens.load_state_dict(checkpoint["tokens"])
    model = ASM2VEC(*checkpoint["model_params"])
    model.load_state_dict(checkpoint["model"])
    model = model.to(device)
    return model, tokens


def accuracy(y, probs):
    return torch.mean(torch.tensor([torch.sum(probs[i][yi]) for i, yi in enumerate(y)]))


def cosine_similarities(model):
    """
    Reads the old and new embeddings from the model and returns the pairwise
    cosine similarities between these embeddings.
    """
    old_f = model.to("cpu").old_embeddings_f
    new_f = model.to("cpu").embeddings_f
    v_old = old_f(torch.tensor([i for i in range(old_f.num_embeddings)]))
    v_new = new_f(torch.tensor([i for i in range(new_f.num_embeddings)]))

    cs_matrix = torch.nn.functional.cosine_similarity(
        v_old[:, :, None], v_new.t()[None, :, :]
    )

    return cs_matrix.detach().numpy()
