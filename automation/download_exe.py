#!/usr/bin/env python3
"""
download_exe.py - Extract ffxiv_dx11.exe from an FFXIV ZiPatch file by streaming.

Does not require a CLUT file. Queries the Thaliak REST API for the patch URL,
then streams and parses the ZiPatch format to assemble ffxiv_dx11.exe on the fly.

Usage:
    python automation/download_exe.py --output latest/
    python automation/download_exe.py --version D2025.01.14.0000.0000 --output previous/
"""

import os
import sys
import struct
import zlib
import argparse
import urllib.request
import json
from typing import Optional

# ---------------------------------------------------------------------------
# Constants
# ---------------------------------------------------------------------------

THALIAK_REPO = "4e9a232b"
THALIAK_API = f"https://thaliak.xiv.dev/api/v2beta/repositories/{THALIAK_REPO}/patches"

# ZiPatch magic: \x91ZIPATCH\r\n\x1A\n
ZIPATCH_MAGIC = bytes(
    [0x91, 0x5A, 0x49, 0x50, 0x41, 0x54, 0x43, 0x48, 0x0D, 0x0A, 0x1A, 0x0A]
)

TARGET_FILE = "ffxiv_dx11.exe"

# SqpkCompressedBlock: compressed_size == 32000 means the block is stored raw
SQPK_BLOCK_UNCOMPRESSED = 32000

# SqpkFile operation codes
OP_ADD_FILE = ord("A")
OP_REMOVE_ALL = ord("R")
OP_DELETE_FILE = ord("D")
OP_MAKE_DIR = ord("M")


# ---------------------------------------------------------------------------
# Thaliak helpers
# ---------------------------------------------------------------------------


def _fetch_json(url: str) -> dict:
    req = urllib.request.Request(
        url, headers={"User-Agent": "ffxiv-exe-downloader/1.0"}
    )
    with urllib.request.urlopen(req) as resp:
        return json.loads(resp.read().decode("utf-8"))


def get_patch_url(version: Optional[str]) -> tuple[str, str]:
    """Return (version_string, remote_url) for *version* or the latest patch."""
    data = _fetch_json(THALIAK_API)
    patches = data.get("patches", [])
    if not patches:
        raise RuntimeError("No patches returned from Thaliak API")

    if version is None:
        return patches[-1]["version_string"], patches[-1]["remote_url"]

    # The version coming from the GHA output may or may not have a D/H prefix.
    for p in reversed(patches):
        vs = p["version_string"]
        bare = vs[1:] if vs[:1] in ("D", "H") else vs
        if vs == version or bare == version:
            return vs, p["remote_url"]

    raise RuntimeError(f"Version {version!r} not found in Thaliak patches")


# ---------------------------------------------------------------------------
# Streaming reader
# ---------------------------------------------------------------------------


class StreamReader:
    """
    Wraps an HTTP response object and exposes read_exact / skip helpers.
    Reads are buffered internally so we never buffer more than needed.
    """

    CHUNK = 65_536  # 64 KiB read chunks for internal buffering

    def __init__(self, response) -> None:
        self._resp = response
        self._buf = bytearray()
        self._eof = False

    def _fill(self, needed: int) -> None:
        while len(self._buf) < needed and not self._eof:
            raw = self._resp.read(self.CHUNK)
            if not raw:
                self._eof = True
                break
            self._buf.extend(raw)

    def read_exact(self, n: int) -> bytes:
        if n == 0:
            return b""
        self._fill(n)
        if len(self._buf) < n:
            raise EOFError(
                f"Stream ended prematurely: needed {n}, got {len(self._buf)}"
            )
        data = bytes(self._buf[:n])
        del self._buf[:n]
        return data

    def skip(self, n: int) -> None:
        """Discard n bytes without buffering them all at once."""
        while n > 0:
            chunk = min(n, self.CHUNK)
            self._fill(chunk)
            take = min(chunk, len(self._buf))
            if take == 0:
                raise EOFError("Stream ended prematurely during skip")
            del self._buf[:take]
            n -= take


# ---------------------------------------------------------------------------
# ZiPatch parsing helpers
# ---------------------------------------------------------------------------


def _align_up(value: int, alignment: int) -> int:
    return (value + alignment - 1) & ~(alignment - 1)


def _decompress_raw_deflate(data: bytes) -> bytes:
    """Decompress raw DEFLATE (no zlib/gzip header, wbits=-15)."""
    return zlib.decompress(data, wbits=-15)


def _parse_sqpk_file_body(body: bytes) -> Optional[tuple]:
    """
    Parse an SQPK command-'F' body.

    Returns (operation, file_offset, file_size, path, blocks_start_offset) or None on error.
    `blocks_start_offset` is the index in `body` where compressed blocks begin.
    """
    # body layout (after the 4-byte inner_size + 1-byte command already consumed):
    #   [1: operation] [2: pad] [8: file_offset BE] [8: file_size BE]
    #   [4: path_len BE] [2: expansion_id BE] [2: pad] [path_len: path]
    #   ... compressed blocks ...
    HEADER = 1 + 2 + 8 + 8 + 4 + 2 + 2  # = 27 bytes
    if len(body) < HEADER:
        return None

    offset = 0
    operation = body[offset]
    offset += 1 + 2  # op + 2 pad bytes

    (file_offset,) = struct.unpack_from(">q", body, offset)
    offset += 8
    (file_size,) = struct.unpack_from(">q", body, offset)
    offset += 8
    (path_len,) = struct.unpack_from(">i", body, offset)
    offset += 4
    offset += 4  # expansion_id (2) + pad (2)

    if path_len < 0 or offset + path_len > len(body):
        return None

    path = (
        body[offset : offset + path_len]
        .decode("utf-8", errors="replace")
        .rstrip("\x00")
    )
    offset += path_len

    return operation, file_offset, file_size, path, offset


def _parse_compressed_blocks(
    body: bytes, blocks_start: int, file_offset: int, out_buf: bytearray
) -> int:
    """
    Parse SqpkCompressedBlock entries from `body[blocks_start:]`, decompressing each
    into `out_buf` starting at `file_offset`.

    Returns the final file offset after all blocks (i.e. file_offset + total decompressed bytes).
    """
    pos = blocks_start
    current_file_off = file_offset

    while pos < len(body):
        blk_start = pos

        if pos + 16 > len(body):
            break  # not enough data for a block header

        (header_size,) = struct.unpack_from("<i", body, pos)
        pos += 4
        pos += 4  # pad (uint32)
        (compressed_size,) = struct.unpack_from("<i", body, pos)
        pos += 4
        (data_size,) = struct.unpack_from("<i", body, pos)
        pos += 4

        # Seek to blk_start + header_size (skip any extra header bytes beyond the 16 we read)
        pos = blk_start + header_size

        is_compressed = compressed_size != SQPK_BLOCK_UNCOMPRESSED

        if is_compressed:
            if pos + compressed_size > len(body):
                break
            raw = body[pos : pos + compressed_size]
            decompressed = _decompress_raw_deflate(raw)
            pos += compressed_size
        else:
            if pos + data_size > len(body):
                break
            decompressed = body[pos : pos + data_size]
            pos += data_size

        # Write decompressed bytes into out_buf at current_file_off,
        # growing the buffer as needed (multiple SqpkFile chunks cover
        # sequential ranges; each chunk's file_size is only its own share).
        end = current_file_off + len(decompressed)
        if end > len(out_buf):
            out_buf.extend(bytes(end - len(out_buf)))
        out_buf[current_file_off:end] = decompressed

        current_file_off += data_size  # advance by the *uncompressed* size

        # Align to next 128-byte boundary from block start
        consumed = pos - blk_start
        aligned = _align_up(consumed, 128)
        pos = blk_start + aligned

    return current_file_off


# ---------------------------------------------------------------------------
# Main extraction logic
# ---------------------------------------------------------------------------


def extract_exe(url: str, output_path: str) -> bool:
    """
    Stream the ZiPatch at *url*, extract ffxiv_dx11.exe, write to *output_path*.
    Returns True on success.
    """
    print(f"Streaming patch: {url}", file=sys.stderr)

    req = urllib.request.Request(
        url, headers={"User-Agent": "ffxiv-exe-downloader/1.0"}
    )
    with urllib.request.urlopen(req) as resp:
        reader = StreamReader(resp)

        # --- Verify ZiPatch magic (12 bytes) ---
        magic = reader.read_exact(12)
        if magic != ZIPATCH_MAGIC:
            raise RuntimeError(f"Not a valid ZiPatch file (bad magic: {magic.hex()})")

        out_buf: Optional[bytearray] = None

        while True:
            # Each chunk: [4: body_size BE] [4: fourcc] [body_size: body] [4: CRC32]
            header = reader.read_exact(4)
            (body_size,) = struct.unpack(">I", header)
            fourcc_bytes = reader.read_exact(4)
            fourcc = fourcc_bytes.decode("ascii", errors="replace")

            if fourcc == "EOF_":
                # EndOfFile chunk – we are done
                reader.skip(body_size + 4)  # body + CRC
                break

            if fourcc != "SQPK":
                # Skip non-SQPK chunks (FileHeader, ApplyOption, etc.)
                reader.skip(body_size + 4)
                continue

            # --- SQPK chunk ---
            # First 5 bytes: inner_size (4, BE) + command (1)
            if body_size < 5:
                reader.skip(body_size + 4)
                continue

            preamble = reader.read_exact(5)
            command = chr(preamble[4])

            if command != "F":
                # Not a file command – skip the rest
                reader.skip(body_size - 5 + 4)
                continue

            # command == 'F' (SqpkFile) – load the full body to parse file path and blocks
            rest = reader.read_exact(body_size - 5)
            reader.skip(4)  # CRC

            parsed = _parse_sqpk_file_body(rest)
            if parsed is None:
                continue

            operation, file_offset, _chunk_file_size, path, blocks_start = parsed

            # Check whether this chunk targets our exe (case-insensitive suffix match)
            is_target = path.lower() == TARGET_FILE.lower() or path.lower().endswith(
                "/" + TARGET_FILE.lower()
            )

            if not is_target:
                continue

            if operation == OP_REMOVE_ALL:
                out_buf = None
                print(f"  RemoveAll on {path}", file=sys.stderr)
                continue

            if operation != OP_ADD_FILE:
                continue

            # AddFile: reset buffer on first write (file_offset == 0 means truncate+rewrite).
            # Do NOT pre-allocate from chunk_file_size — that's only this chunk's share;
            # the full exe spans many SqpkFile chunks at increasing file_offset values.
            if file_offset == 0:
                out_buf = bytearray()
                print(f"  Found {path}", file=sys.stderr)

            if out_buf is None:
                # Shouldn't happen for a well-formed patch
                continue

            _parse_compressed_blocks(rest, blocks_start, file_offset, out_buf)

        if out_buf is None:
            print(f"ERROR: {TARGET_FILE} not found in patch!", file=sys.stderr)
            return False

        os.makedirs(os.path.dirname(os.path.abspath(output_path)), exist_ok=True)
        with open(output_path, "wb") as f:
            f.write(out_buf)
        print(f"  Written {len(out_buf):,} bytes -> {output_path}", file=sys.stderr)
        return True


# ---------------------------------------------------------------------------
# Entry point
# ---------------------------------------------------------------------------


def main() -> None:
    parser = argparse.ArgumentParser(
        description=f"Download {TARGET_FILE} from an FFXIV ZiPatch file without a CLUT."
    )
    parser.add_argument(
        "--version",
        default=None,
        metavar="VERSION",
        help="Thaliak version string (default: latest). Accepts D/H-prefixed or bare form.",
    )
    parser.add_argument(
        "--output",
        required=True,
        metavar="PATH",
        help="Output directory or file path.",
    )
    args = parser.parse_args()

    # Resolve output path to a file
    out = args.output
    if out.endswith(os.sep) or os.path.isdir(out):
        out = os.path.join(out, TARGET_FILE)
    elif not out.lower().endswith(".exe"):
        os.makedirs(out, exist_ok=True)
        out = os.path.join(out, TARGET_FILE)

    print("Fetching patch metadata from Thaliak...", file=sys.stderr)
    version_str, patch_url = get_patch_url(args.version)
    print(f"  Version : {version_str}", file=sys.stderr)
    print(f"  URL     : {patch_url}", file=sys.stderr)

    success = extract_exe(patch_url, out)
    sys.exit(0 if success else 1)


if __name__ == "__main__":
    main()
