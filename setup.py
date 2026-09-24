"""Thin packaging layer around Lazer's existing build system.

This does not reimplement the C build or the CFFI build: it just invokes
the same steps a developer runs by hand (see README: `make`, then
`cd python && make`) before setuptools packages the resulting flat
python/ modules. This lets `pip install -e .` (from a sibling checkout)
work as a developer workflow; it is not an attempt to make Lazer a
polished, stable PyPI package.
"""

import subprocess
import sys
from pathlib import Path

from setuptools import setup
from setuptools.command.build_py import build_py as _build_py

REPO_ROOT = Path(__file__).resolve().parent
PYTHON_DIR = REPO_ROOT / "python"


# liblabrador{32,36,38}.so are optional LaBRADOR backends: lazer_cffi_build.py
# picks up whichever of them exist. They use AVX512 intrinsics that simply fail 
# to compile on CPUs without AVX512, so these are built best-effort and never 
# block the rest of the install.
OPTIONAL_LABRADOR_TARGETS = ["liblabrador32.so", "liblabrador36.so", "liblabrador38.so"]


def _build_native():
    subprocess.run(["make"], cwd=REPO_ROOT, check=True)
    for target in OPTIONAL_LABRADOR_TARGETS:
        result = subprocess.run(["make", target], cwd=REPO_ROOT)
        if result.returncode != 0:
            print(
                f"warning: failed to build {target} (likely missing CPU features "
                "such as AVX512) -- continuing without this LaBRADOR backend",
                file=sys.stderr,
            )
    subprocess.run(
        [sys.executable, "lazer_cffi_build.py", ".."], cwd=PYTHON_DIR, check=True
    )


class build_py(_build_py):
    def run(self):
        _build_native()
        super().run()


setup(cmdclass={"build_py": build_py})
