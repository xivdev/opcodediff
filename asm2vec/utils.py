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
PACKET_SIZE_HINT_RE = re.compile(r"mov qword \[rsp \+ 0x20\], (0x[0-9a-f]+)")


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

        fn_idx:
            Index of the Function. This is necessary to index into the
            training model embeddings. Different switch cases may share
            the same fn_idx because they may be textually identical but
            have different constants.

        Opcode Set/opcode_set:
            A set of opcodes that a single switch case covers.

        Pointer Opcode/ptr_opcode:
            A single opcode that represents the opcode set.

        Constants vector/constants_vector:
            Since the training process removes constants from the input text,
            the constants vector is a "signature" generated by looking at
            constants used in the trace.
    """

    def __init__(self, tokens):
        self.tokens = tokens

        self.__traces = dict()
        """
        Maps trace to trace idx
        """

        self.opcodes = dict()
        """
        maps ptr_opcode => { fn_idx, constants_vector, [opcodes...] }.
        See class docstring for more details.
        """

        self.__opcode_sets = dict()
        """
        maps ptr_opcode => [opcodes...]
        """

    @property
    def traces(self):
        """
        A list of parsed traces in the TraceData.

        See class docstring for more details.
        """
        return list(self.__traces.keys())

    def __process_trace(self, ptr_opcode, text):
        fn = Function.load(text)
        if fn in self.__traces:
            fn_idx = self.__traces[fn]
        else:
            fn_idx = len(self.__traces)
            self.__traces[fn] = fn_idx
            self.tokens.add(fn.tokens())

        self.opcodes[ptr_opcode] = {
            "fn_idx": fn_idx,
            "constants_vector": self.__get_constants_vector(text),
            "packet_size_hint": self.__get_packet_size_hint(text),
            "opcodes": self.__opcode_sets[ptr_opcode],
        }

    def __process_opcode_sets(self, opcode_sets_file):
        with open(opcode_sets_file) as f:
            data = json.load(f)
            self.__opcode_sets = {int(op): ops for op, ops in data.items()}

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
    def __get_packet_size_hint(trace):
        """
        Dumb way of getting the packet size hint from whatever handlers
        call them
        """
        call0_lines = []
        call0_found = False

        for line in trace.strip("\n").split("\n"):
            if not call0_found:
                if "CALL0" in line:
                    call0_found = True
                else:
                    continue
            if "CALL0_END" in line:
                break
            else:
                call0_lines.append(line)

        for line in call0_lines:
            match = PACKET_SIZE_HINT_RE.search(line)
            if match and match.lastindex:
                const_str = match.group(match.lastindex)
                const_str = "".join(const_str.split())
                const = int(const_str, 16)
                return const

        # Couldn't find anything, so just return 0
        return 0

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
        # Process opcode_sets.json first, save traces for later

        trace_files = dict()
        for filepath in filenames:
            filename = os.path.basename(filepath)
            file_split = os.path.splitext(filename)
            file_ext = file_split[-1]
            if file_ext == ".json" and filename == "opcode_sets.json":
                trace_data.__process_opcode_sets(filepath)
            elif file_ext == ".asm":
                ptr_opcode = int(file_split[0], base=16)
                trace_files[ptr_opcode] = filepath

        for ptr_opcode, trace_file in trace_files.items():
            with open(trace_file) as f:
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
    functions = trace_data.traces
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
