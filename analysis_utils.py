import re
import semver

from utils import create_r2_byte_pattern


def get_sem_ver(exe_file: str) -> str:
    """Parses the semver from the exe_file name and returns it.

    Args:
        exe_file (str): The path to the executable file.

    Returns:
        str: The semantic version string.
    """
    res = re.match(r".*ffxiv_dx11\.(\d).(\d)(\d)(\w?)(\d?)\.exe", exe_file)
    sem_ver = f"{res.group(1)}.{res.group(2)}.{res.group(3)}"
    if res.group(4) != "":
        sem_ver = f"{sem_ver}+{res.group(4)}"
    return sem_ver


def packet_handler_sig(sem_ver: str) -> str:
    """Returns the signature for Client::Network::PacketDispatcher_OnReceivePacket
    for Zone packets.

    Args:
        sem_ver (str): The semantic version string.
    """
    if semver.compare(sem_ver, "7.3.0") >= 0:
        return "48 89 5C 24 ? 55 56 57 41 54 41 55 41 56 41 57 48 8D AC 24 ? ? ? ? B8 ? ? ? ? E8 ? ? ? ? 48 2B E0 48 8B 05 ? ? ? ? 48 33 C4 48 89 85 ? ? ? ? 45 0F B7"
    elif semver.compare(sem_ver, "7.2.0") >= 0:
        return "40 55 53 56 57 41 55 41 56 41 57 48 8D AC 24 ? ? ? ? B8 ? ? ? ? E8 ? ? ? ? 48 2B E0 48 8B 05 ? ? ? ? 48 33 C4 48 89 85 ? ? ? ? 45 0F B7 78 ?"
    elif semver.compare(sem_ver, "6.4.0") >= 0:
        return "40 53 56 48 81 EC ? ? ? ? 48 8B 05 ? ? ? ? 48 33 C4 48 89 44 24 ? 8B F2"
    else:
        return "48 89 ? 24 ? ? 48 83 EC 50 8B F2 49 8B"


def get_packet_handler_addr(r2, exe_file: str) -> str:
    """Get the address for the Client::Network::PacketDispatcher_OnReceivePacket
    for Zone packets.

    Args:
        r2: An instance of r2pipe.
        exe_file (str): The path to the executable file.

    Returns:
        str: The hex address of the packet dispatch handler.
    """
    sem_ver = get_sem_ver(exe_file)
    p = create_r2_byte_pattern(packet_handler_sig(sem_ver))
    result = r2.cmd(f"/x {p}").split()  # Find byte pattern
    if len(result) == 0:
        raise ValueError(
            "Could not find packet handler address. This could be "
            "because of an incorrect signature or a transient Radare failure."
        )
    return result[0]


def packet_handler_switch_sig(sem_ver: str) -> str:
    """Returns the signature for approximately a couple instructions before the
    actual zone packet handler switch.

    Args:
        sem_ver (str): The semantic version string.
    """
    if semver.compare(sem_ver, "7.3.0") > 0:
        return "E8 ? ? ? ? 41 83 C7 ? 49 8B FD"
    elif semver.compare(sem_ver, "7.3.0") == 0:
        if semver.parse(sem_ver)["build"]:
            return "E8 ? ? ? ? 41 83 C7 ? 49 8B FD"
        return "E8 ? ? ? ? 41 83 C5 ? 49 8B FC"
    elif semver.compare(sem_ver, "7.2.0") >= 0:
        return "E8 ? ? ? ? 41 83 C7 ? EB 1B"
    elif semver.compare(sem_ver, "6.4.0") >= 0:
        return "40 53 56 48 81 EC ? ? ? ? 48 8B 05 ? ? ? ? 48 33 C4 48 89 44 24 ? 8B F2"
    else:
        return "48 89 ? 24 ? ? 48 83 EC 50 8B F2 49 8B"


def get_packet_handler_switch_addr(r2, exe_file: str) -> str:
    """Gets the address of the approximate position where the zone packet
    handler switch is located.

    Args:
        r2 - An instance of r2pipe.
        exe_file (str): The path to the executable file.

    Returns:
        str: The hex address that can be used to find the opcode offset.
    """
    sem_ver = get_sem_ver(exe_file)
    p = create_r2_byte_pattern(packet_handler_switch_sig(sem_ver))
    result = r2.cmd(f"/x {p}").split()  # Find byte pattern
    if len(result) == 0:
        raise ValueError(
            "Could not find packet handler switch address. This could be "
            "because of an incorrect signature or a transient Radare failure."
        )
    return result[0]


def _get_opcode_offset_post_72(r2, reg):
    r2.cmd("aeso")  # step over call
    r2.cmd(f"aer {reg}=0x500")  # set reg to some arbitrary number
    r2.cmd("aeso")  # step

    regs = r2.cmdj("arj")
    return 0x500 - regs[reg]


def _get_opcode_offset_pre_72(r2):
    r2.cmd("aecc")  # continue until call
    r2.cmd("aer rax=0x0")  # set rax to 0
    r2.cmd('"aesue rax,0x0,>"')  # continue until rax changes?
    r2.cmd("aer rdx=0x200")  # set rdx to some arbitrary number
    r2.cmd("aeso")  # step

    regs = r2.cmdj("arj")
    return regs["rdx"] - regs["rax"]


def get_packet_handler_opcode_offset(r2, exe_file: str):
    """Gets the offset that maps the actual opcode to a switch case in the
    zone packet handler.

    Args:
        r2 - An instance of r2pipe.
        exe_file (str): The path to the executable file.
    """
    sem_ver = get_sem_ver(exe_file)
    # The opcode offset can be found somewhere right before the packet handler
    # switch
    opcode_offset_target = get_packet_handler_switch_addr(r2, exe_file)

    orig_loc = r2.cmd("s")  # Save original spot
    r2.cmd(f"s {opcode_offset_target}")
    r2.cmd("aei; aeim; aeip")  # Initialize ESIL VM, stack, and instruction pointer

    if semver.compare(sem_ver, "7.2.0") >= 0:
        offset_reg = "r15"
        if (
            semver.compare(sem_ver, "7.3.0") == 0
            and semver.parse(sem_ver)["build"] == ""
        ):
            offset_reg = "r13"
        opcode_offset = _get_opcode_offset_post_72(r2, offset_reg)
    else:
        opcode_offset = _get_opcode_offset_pre_72(r2)

    # Clear the ESIL environment
    r2.cmd("ar0; aeim-; aei-")
    r2.cmd(f"s {orig_loc}")  # Seek back to original spot

    return opcode_offset


def get_correct_switch(approx_ea: str, switch_cases: list):
    """Despite seeking directly to the packet switch, we still get multiple
    switches from analysis, so we need to find the right one.

    Args:
        approx_ea (str): The approximate address of the packet switch.
        switch_cases (list): The list of switch cases to search through.

    Returns:
        (str, dict): The found switch address and the corresponding switch
    """
    switches = dict()
    approx_ea = int(approx_ea, 16)
    pattern = re.compile(r"case\.(0x[0-9a-fA-F]+)\.(\d+)")

    for l in switch_cases:
        match = pattern.match(l["name"])
        if match is not None:
            switch_ea = match[1]
            case_ea = l["addr"]

            if switch_ea not in switches:
                switches[switch_ea] = dict()
            if case_ea not in switches[switch_ea]:
                switches[switch_ea][case_ea] = {
                    "opcodes": [],
                }
            switches[switch_ea][case_ea]["opcodes"].append(match[2])

    found_switch = None
    longest_switch = dict()
    for switch_ea in switches:
        int_switch_ea = int(switch_ea, 16)
        if int_switch_ea < approx_ea or int_switch_ea > approx_ea + 0x100:
            continue
        if len(switches[switch_ea].keys()) > len(longest_switch):
            found_switch = switch_ea
            longest_switch = switches[switch_ea]

    return found_switch, longest_switch
