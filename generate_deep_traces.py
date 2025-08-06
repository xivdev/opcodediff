import click
import json
import pathlib
import semver

from minor_patch_diff import (
    get_opcode_offset_7_30,
    get_sem_ver,
    get_opcode_offset,
    get_opcode_offset_7_20,
    get_correct_switch,
    get_zone_proto_down_sig,
    get_opcode_offset_sig,
)


class RefNode:
    def __init__(self, ea):
        self.ea = ea
        self.calls = []
        self.branch0 = None
        self.branch1 = None

    def add_call(self, ea):
        node = RefNode(ea)
        self.calls.append(node)
        return node

    def add_b0(self, ea):
        if self.branch0:
            raise Exception(f"Node {repr(self)} already has a branch0!")
        self.branch0 = RefNode(ea)
        return self.branch0

    def add_b1(self, ea):
        if self.branch1:
            raise Exception(f"Node {repr(self)} already has a branch1!")
        self.branch1 = RefNode(ea)
        return self.branch1

    def __repr__(self):
        calls = f", calls: {self.calls}" if self.calls else ""
        branch0 = f", b0: {self.branch0}" if self.branch0 else ""
        branch1 = f", b1: {self.branch1}" if self.branch1 else ""
        return f"{{ ea: {hex(self.ea)}{calls}{branch0}{branch1} }}"


class OpcodeCase:
    def __init__(self, ea, opcodes):
        self.ref = RefNode(ea)
        self.opcodes = opcodes

    def __repr__(self):
        return f"{[hex(opcode) for opcode in self.opcodes]}: { repr(self.ref) }"


class BlockDict(dict):
    def missing_set(self, eas):
        missing = set()
        for ea in eas:
            if ea not in self:
                missing.add(ea)
        return missing

    def update_with_missing(self, r2, eas):
        missing = self.missing_set(eas)
        if len(missing) == 0:
            return

        block_json_list = r2.cmd(
            f"pdbj @@={' '.join((hex(ea) for ea in missing))}"
        ).splitlines()
        missing_blocks = [json.loads(block_json) for block_json in block_json_list]
        additional_blocks = {
            missing_block[0]["offset"]: missing_block
            for missing_block in missing_blocks
        }
        self.update(additional_blocks)

        if len(additional_blocks) < len(missing):
            return self.missing_set(eas)

    def mark_missing_as_unknown(self, eas):
        missing = self.missing_set(eas)
        self.update({ea: [{"unknown": True}] for ea in missing})


def populate_child_refs(blocks, refs):
    """Runs a single step of a BFS for traversing calls/jumps"""
    child_refs = []
    for ref in refs:
        for insn in blocks[ref.ea]:
            if "jump" in insn:
                jump_ea = insn["jump"]
                if insn["type"] == "call":
                    child_refs.append(ref.add_call(jump_ea))
                else:
                    child_refs.append(ref.add_b1(jump_ea))
                    if "fail" in insn:
                        child_refs.append(ref.add_b0(insn["fail"]))
    return child_refs


def generate_opcodes_db(r2, switch, opcode_offset, fn_graph):
    opcodes_db = dict()

    for case_ea, data in switch.items():
        opcodes = data["opcodes"]
        resolved_opcodes = [int(opcode) + opcode_offset for opcode in opcodes]
        opcodes_db[resolved_opcodes[0]] = OpcodeCase(case_ea, resolved_opcodes)

    blocks = BlockDict()
    for bb in fn_graph["bbs"]:
        blocks[bb["addr"]] = bb["ops"]

    # This should be a no-op since it is assumed the fn_graph would have
    # every block in the function.
    still_missing = blocks.update_with_missing(r2, switch.keys())
    if still_missing:
        raise Exception("There's no way there should be any missing blocks here")

    ref_nodes = []
    for opcase in opcodes_db.values():
        ref_nodes.append(opcase.ref)

    for i in range(10):
        child_refs = populate_child_refs(blocks, ref_nodes)
        eas = [ref.ea for ref in child_refs]
        still_missing = blocks.update_with_missing(r2, eas)
        if still_missing:
            r2.cmd(f"af @@={' '.join((hex(ea) for ea in still_missing))}")
            yet_still_missing = blocks.update_with_missing(r2, still_missing)
            if yet_still_missing:
                blocks.mark_missing_as_unknown(yet_still_missing)
        ref_nodes = child_refs

    return opcodes_db, blocks


def extract_opcode_data(exe_file):
    from utils import eprint, create_r2_byte_pattern, sync_r2_output

    import r2pipe

    r2 = r2pipe.open(exe_file, ["-2"])
    eprint(f"Radare loaded {exe_file}")

    sync_r2_output(r2)

    sem_ver = get_sem_ver(exe_file)
    p = create_r2_byte_pattern(get_zone_proto_down_sig(sem_ver))
    target = r2.cmd(f"/x {p}").split()[0]  # Find byte pattern
    packet_handler_ea = int(target, 16)

    r2.cmd(f"s {target}")  # Seek to target

    ## STEP 1: Grab switch cases
    r2.cmd("f--")  # Delete existing flags
    r2.cmd("afr")  # Analyze function recursively
    switch_cases = r2.cmdj(f"fj")

    eprint(f"  Loaded switch cases")

    ## STEP 2: Grab opcode offset
    p = create_r2_byte_pattern(get_opcode_offset_sig(sem_ver))
    opcode_offset_target = r2.cmd(f"/x {p}").split()[0]  # Find byte pattern
    packet_handler_ea = int(opcode_offset_target, 16)
    r2.cmd(f"s {opcode_offset_target}")  # Seek to target

    if semver.compare(sem_ver, "7.3.0") >= 0:
        opcode_offset = get_opcode_offset_7_30(r2)
    elif semver.compare(sem_ver, "7.2.0") >= 0:
        opcode_offset = get_opcode_offset_7_20(r2)
    else:
        opcode_offset = get_opcode_offset(r2)
    eprint(f"  Found opcode offset: {opcode_offset}")

    r2.cmd(f"s {target}")  # Seek to original target

    ## STEP 3: Grab function graph
    fn_graph = r2.cmdj(f"pdrj")

    ## STEP 4: Process data
    switch_ea, packet_handler_switch = get_correct_switch(
        packet_handler_ea, switch_cases
    )
    eprint(f"  Found switch at {switch_ea}")

    opcodes_db, blocks = generate_opcodes_db(
        r2, packet_handler_switch, opcode_offset, fn_graph
    )

    eprint(f"  Loaded {len(opcodes_db)} cases from packet handler")

    r2.quit()

    return opcodes_db, blocks


def bb_lines(blocks, ref):
    lines = []
    block = blocks[ref.ea]
    for insn in block:
        if "unknown" in insn:
            lines.append("UNKNOWN_BLOCK")
        else:
            lines.append(insn["opcode"])
    return lines


def trace_lines(blocks, ref):
    # Generate traces in a BFS fashion
    lines = []
    refs = [(None, ref)]
    while refs:
        (name, ref) = refs.pop(0)
        if name:
            lines.append(name)
        lines.extend(bb_lines(blocks, ref))
        if name:
            lines.append(f"{name}_END")
        for i, call_ref in enumerate(ref.calls):
            refs.append((f"CALL{i}", call_ref))
        if ref.branch0:
            refs.append(("BRANCH0", ref.branch0))
        if ref.branch1:
            refs.append(("BRANCH1", ref.branch1))
    return lines


@click.command()
@click.argument(
    "exe_file", type=click.Path(exists=True, dir_okay=False, resolve_path=True)
)
@click.argument("output_dir", type=click.Path(file_okay=False))
def generate_deep_traces(exe_file, output_dir):
    """
    Generates deep traces for every packet handler in the target EXE_FILE.
    This outputs an ASM trace as an .asm file for each pointer opcode.
    It also outputs an `opcode_sets.json` that maps each pointer opcode to the
    full set of opcodes handled by that trace.

    These aren't normal traces by any measure; they are simply basic blocks
    printed in BFS order, where children blocks are added to the BFS tree
    by traversing calls and jumps.

    Example:

    python generate_deep_traces.py ffxiv_dx11.6.28h.exe 6.28h-traces
    """
    opcodes_db, blocks = extract_opcode_data(exe_file)

    pathlib.Path(output_dir).mkdir(parents=True, exist_ok=True)

    for opcode, opcase in opcodes_db.items():
        with open(f"{output_dir}/{hex(opcode)}.asm", "w+") as f:
            trace = trace_lines(blocks, opcase.ref)
            f.writelines(s + "\n" for s in trace)

    with open(f"{output_dir}/opcode_sets.json", "w+") as f:
        opcode_sets = {
            opcode: opcase.opcodes for (opcode, opcase) in opcodes_db.items()
        }
        json.dump(opcode_sets, f)


if __name__ == "__main__":
    generate_deep_traces()
