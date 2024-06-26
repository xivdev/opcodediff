import sys
import time
import os
import click


def eprint(*args, **kwargs):
    print(*args, file=sys.stderr, **kwargs)


def create_r2_byte_pattern(sig):
    tokens = sig.split()
    r2_tokens = []
    for token in tokens:
        if token == "?":
            r2_tokens.append("..")
        else:
            r2_tokens.append(token)
    return "".join(r2_tokens)


def sync_r2_output(r2):
    """
    For some fucking reason r2pipe output gets desynced from the start,
    making the result of every command what the previous command should
    have returned.

    Read stuff from the process pipe until it stops being stupid.
    """

    def set_blocking(fileno, blocking):
        if hasattr(os, "set_blocking"):
            os.set_blocking(fileno, blocking)

    time.sleep(1)
    set_blocking(r2.process.stdout.fileno(), False)
    p = r2.process.stdout.read(1)
    set_blocking(r2.process.stdout.fileno(), True)
    output = r2.cmd(f"?vi 123").strip()
    if output != "123":
        raise Exception("R2 state never got synced")


class HexIntParamType(click.ParamType):
    name = "integer"

    def convert(self, value, param, ctx):
        if isinstance(value, int):
            return value

        try:
            if value[:2].lower() == "0x":
                return int(value[2:], 16)
            return int(value, 16)
        except ValueError:
            self.fail(f"{value!r} is not a valid hex integer", param, ctx)
