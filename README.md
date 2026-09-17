A Toolkit for Succinct Lattice-Based Zero Knowledge Proofs
==========================================================

Artifact for ACM CCS 2026, built on top of the lazer library.


Dependencies
------------
The following hardware and software is required to build
and run lazer:

- Linux amd64 / x86-64 system
- kernel version >= 4.18
- avx512 and aes instruction set extensions
- gcc compiler >= 13.2
- make >= 4.2, cmake >= 3.26
- sagemath >= 10.2
- python3 >= 3.10, its development package and the cffi package 

The following software is required to build the documentation:

 - sphinx >= 5.3 and the sphinxcontrib-bibtex package

The package was tested on Ubuntu 20.04 LTS and RHEL 8.10
with an 11th Gen Intel Core i7-11850H @ 2.50GHz and
with the dependencies' versions equal to the listed above.
We assume that it works with greater versions as well,
as long as they are backward compatible. It *may*
work with lesser versions as well.
Note that during compilation, the cpu_features package
will be cloned from GitHub, so also git and an internet
connection are required.


Building the library
--------------------

To build the lazer C library, from the base directory, run:

`git submodule update --init --recursive`

to clone Labrador's repository and

`make all`

To build lazer's python module, change to the `python` subdirectory and run:

`make`

(If this step fails, check that the python development package is installed.)

Now continue with the section corresponding to the commit you chose in the beginning.


Building the benchmarks
------------------------
To build the benchmarks, change to the `python/succinct_zkp` subdirectory and run `make`:

`cd python/succinct_zkp`

`make`

Instructions for artifact evaluation and result reproduction
------------------------------------------------------------

1.   Set up a system that meets the dependencies decribed above.
2.   Download and build the library as described above.
3.   Build the benchmarks as described above.
4.   Run the following benchmarks from the `python/succinct_zkp` subdirectory:
     - `python3 benchmark_expansion.py` (corresponds to Table 1)
     - `python3 benchmark_compression.py` (corresponds to Table 2)
     - `python3 benchmark_membership_proof.py` (corresponds to Table 3)
     - `python3 benchmark_blind_sign.py` (corresponds to Table 4)

The timings reported in the paper correspond to the medians printed when running the above benchmarks on a single core of an Intel Core i7-11850H.


