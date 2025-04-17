# Lattice Hash

Lattice Hash experiments with an LWE/LWR-inspired compression pipeline that
mixes blocks of degree-512 binary polynomials with Intel HEXL–accelerated NTTs.
The repository produces a shared library (`libhash.so`) whose API exposes the
`absorb`, `mix_256`, `mix_257`, and `squeeze` primitives, plus a reference
pipeline (`test`) that wires the stages together and prints the intermediate
polynomials for inspection or verification in SageMath.

## Requirements

- 64-bit Linux machine with AVX-512IFMA + AVX-512DQ support (used by HEXL).
- `gcc`/`g++` with C11/C++17 support (tested with GCC 11+).
- `cmake` ≥ 3.5 and `make`.
- Python 3 and SageMath (only needed for `verify.sage`).

> **Note:** the Intel HEXL dependency lives as a submodule in `src/hexl`. Clone
> with `--recursive` or run `git submodule update --init --recursive` before
> building.

## Building

```bash
# 1. Fetch the Intel HEXL submodule if you have not already
git submodule update --init --recursive

# 2. Build Intel HEXL inside src/hexl/build/
make hexl

# 3. Build the wrapper, data generator, libhash, and the test driver
make all
```

Running `make all` produces:

- `libhexl_wrapper.so` – a thin C interface over Intel HEXL’s NTT helpers.
- `generate_data` – deterministically populates `src/data.h` with the random
  matrices/vectors used by the hash.
- `libhash.so` – exports the polynomial compression primitives declared in
  `src/hash.h`.
- `test` – sample pipeline that generates random inputs, runs all stages, and
  prints structured output.

Clean intermediate artifacts with `make clean`. Rebuild the HEXL submodule by
rerunning `make hexl` if you update the submodule.

## Usage

### Building prerequisites

```bash
make hexl
make wrapper
```

Make sure `sage` is installed e.g. via `conda`:
```bash
conda create -n sage sage python=3.12
conda activate sage
```


### Running the sample pipeline


Run the hash function
```bash
make run_test > out.out
```

and inspect the output via
```bash
sage verify.sage
```

The program prints every intermediate polynomial block checks plus the wall-clock
latency (`pipeline_time_ns`). 

### Regenerating matrices
Hash function relies on `data.h` fule which contains matrices used during the function execution.
To generate the file, we use `src/generate_data.c`

## Helpful make targets & commands

- `make hexl` – Configure/build Intel HEXL in `src/hexl/build`.
- `make all` – Build the wrapper, data generator, shared library, and test app.
- `make run_test` – Run the pipeline (`LD_LIBRARY_PATH=. ./test`).
- `make wrapper` – Rebuild only `libhexl_wrapper.so`.
- `make clean` – Remove locally built artifacts (shared libraries, test binary).
- `make src/generate_data.c` - Build `data.h` file.

## Project layout

- `src/hash.c`, `src/hash.h` – Core lattice hash implementation and public API.
- `src/generate_data.c` – Generates `src/data.h` via `generate_data`.
- `src/hexl_wrapper.cpp` – Bridges C code with Intel HEXL’s optimized kernels.
- `src/test.c` – Reference pipeline + debugging helpers.
- `verify.sage` – SageMath checker for the printed pipeline transcript.
