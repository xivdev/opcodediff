# opcodediff

A set of tools for matching opcodes across different versions of the FFXIV
binary.

## Prerequisites

1. Ensure you have python >= 3.7 installed.

1. Set up a python venv:
   ```sh
   python -m venv /path/to/venv/dir
   ```

1. Activate the venv

   Linux:
   ```sh
   source venv/bin/activate # csh or fish variants available as well
   ```

   Windows:
   ```
   venv\Scripts\activate
   ```

1. Install dependencies

   ```sh
   pip install -r requirements.txt
   ```

1. Ensure you have [radare](https://github.com/radareorg/radare2) somewhere on
    your path

1. For `traces-diff.py`, an NVIDIA GPU and CUDA support are highly recommended,
   but not required. It might just take twice as long to train.

## Usage

Pass `--help` to any of the scripts for usage.

### Workflow for minor patches

Example:
```sh
python vtable_diff.py ffxiv_dx11.6.30.exe ffxiv_dx11.6.30h.exe > 6.30h.diff.json
```

Post-diff processing:
```sh
python generate_opcodes_file.py 6.30 6.30h 6.30h.diff.json Ipcs.6.30h.h
python generate_act_format.py Ipcs.6.30h.h
```

### Workflow for major patches

We'll need to generate "traces" as signatures for every packet handler.

Example:
```sh
python generate_deep_traces.py ffxiv_dx11.6.28h.exe 6.28h-traces
python generate_deep_traces.py ffxiv_dx11.6.30.exe 6.30-traces
python traces_diff.py 6.28h-traces 6.30-traces 6.30.diff.json
```

Post-diff processing:
```sh
python generate_opcodes_file.py 6.30 6.30h 6.30h.diff.json Ipcs.6.30h.h
# TODO: Need a script to resolve opcodes for handlers with multiple opcodes
python generate_act_format.py Ipcs.6.30h.h
```

###