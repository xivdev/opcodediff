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
    your PATH

1. For `generate_similarity_matrix.py`, an NVIDIA GPU and CUDA support are highly recommended,
   but not required. It might just take twice as long to train.

## Usage

Pass `--help` to any of the scripts for usage.

### Workflow for minor patches

Here we simply match the vtable from the previous version to the new minor patch version,
assuming there is a 1:1 correspondence between the switch cases at the same offset in the function.

Example:
```sh
python vtable_diff.py ffxiv_dx11.6.30.exe ffxiv_dx11.6.30h.exe > 6.30h.diff.json
```

Post-diff processing:
```sh
python generate_opcodes_file.py 6.30 6.30h 6.30h.diff.json Ipcs.6.30h.h
python generate_act_format.py Ipcs.6.30h.h
```

Sanity checking with the older method as validation:
```sh
python minor_patch_diff.py ffxiv_dx11.6.30.exe ffxiv_dx11.6.30h.exe > 6.30h.sanity.json
python sanity_check.py 6.30h.diff.json 6.30h.sanity.json
```

### Workflow for major patches

For major patches, we cannot assume a 1:1 correspondence between vtables as before, since there
are probably insertions in the new version that are scattered throughout the switch case.

To solve this, we can run a sequence alignment algorithm to match the two vtables.

But first, in order to generate a similarity matrix, we must first generate
"traces" as signatures for every packet handler.  Then we can plug these traces
into our language model to generate embeddings for each handler. Then, we can
simply run cross cosine similarity to match these embeddings to generate our
similarity matrix.

Finally, we run the [Needleman-Wunsch algorithm](https://en.wikipedia.org/wiki/Needleman%E2%80%93Wunsch_algorithm)
to generate a global sequence alignment of the two vtables.

Example:
```sh
python generate_deep_traces.py ffxiv_dx11.6.28h.exe 6.28h-traces
python generate_deep_traces.py ffxiv_dx11.6.30.exe 6.30-traces
python generate_similarity_matrix.py 6.28h-traces 6.30-traces 6.30.similarity.json

python vtable_alignment.py ffxiv_dx11.6.28h.exe ffxiv_dx11.6.30.exe 6.30.similarity.json > 6.30.diff.json
```

### Post-diff processing
```sh
python generate_opcodes_file.py 6.30 6.30h 6.30h.diff.json Ipcs.6.30h.h
python generate_act_format.py Ipcs.6.30h.h
```
