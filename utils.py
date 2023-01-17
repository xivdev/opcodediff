import sys
import time


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
    for i in range(10):
        p = r2.process.stdout.read(1)
        if len(p) > 0:
            break
        time.sleep(1)
    output = r2.cmd(f"?vi 123").strip()
    if output != "123":
        raise Exception("R2 state never got synced")
