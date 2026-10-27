Getting started
===============
.. 
    The LaZer source code is hosted on `GitHub <https://github.com/IBM/lazer>`_.
    You can get a tarball of a specific release from `here <https://github.com/IBM/lazer/releases>`_ or clone the git repository:
    .. code-block:: console

        git clone https://github.com/IBM/lazer


Prerequisites
-------------

To build the lazer library, you need a C compiler (`gcc <https://gcc.gnu.org/>`_ or `clang <https://clang.llvm.org/>`_), the make utility and the `gmp <https://gmplib.org/>`_ and `mpfr <https://www.mpfr.org/>`_ development packages.

To work with the python module, you need `python3 <https://www.python.org/>`_ (at least version 3.10) and the `cffi <https://cffi.readthedocs.io/en/stable/>`_ package.

To generate proof system parameters, you need the `SageMath <https://www.sagemath.org/>`_ computer algebra system.

To build this documentation, you need the `sphinx <https://pypi.org/project/Sphinx/>`_ and the `sphinxcontrib-bibtex <https://pypi.org/project/sphinxcontrib-bibtex/>`_ packages.

Performance is currently only optimized for CPUs with the AVX-512 instruction set extension.

The functions for creating succinct proofs require AVX-512. Those functions will not be available on systems lacking AVX-512.

The library also builds and runs on arm64 / aarch64 (e.g. macOS on Apple silicon, with gmp, mpfr and cmake installed via Homebrew). On non-x86 targets, portable code paths are used (scalar Intel HEXL, Falcon without AVX2, AES-256-CTR via the ARMv8 crypto extensions if available), so performance is lower than on AVX-512 systems.


Building
--------

To build the library, go to the lazer directory and run make:

.. code-block:: console
    
    cd lazer
    make

To try to build the library including the functions requiring AVX-512, do:

.. code-block:: console
    
    cd lazer
    make all

To build the python module, go to the python subdirectory and run make:

.. code-block:: console
    
    cd lazer/python
    make

To build this documentation, go to the docs subdirectory and run make:

.. code-block:: console
    
    cd lazer/docs
    make html

