"""
Tests select_architectures.py.
"""

import json
import os
import shutil
import sys
import tempfile

import pytest

from python_scripts.select_architectures import _main as select_architectures

SELECTED_ARCHES = ["x86_64", "ppc64le", "s390x", "aarch64"]


def _testdir(specfile):
    workdir = tempfile.mkdtemp()
    testdir = os.path.realpath(__file__)
    testdir = os.path.dirname(testdir)
    specfile = os.path.join(testdir, "specfiles", specfile)
    shutil.copy2(specfile, workdir)
    return workdir


@pytest.mark.xfail
def test_basic_noarch():
    """
    Norpm + exclusive_arch use-case.
    """

    testdir = _testdir("gdb-exploitable.spec")
    results = os.path.join(testdir, "results.json")
    sys.argv = ["this", "--hermetic", "--workdir", testdir,
                "--results-file", results] + SELECTED_ARCHES

    select_architectures()
    with open(results, "r", encoding="utf-8") as rfd:
        results = json.load(rfd)

    # This should build only on x86_64
    assert results == {
        "deps-x86_64": "linux/amd64",
        "deps-i686": "localhost",
        "deps-aarch64": "localhost",
        "deps-s390x": "localhost",
        "deps-ppc64le": "localhost",
        "build-x86_64": "linux/amd64",
        "build-i686": "localhost",
        "build-aarch64": "localhost",
        "build-s390x": "localhost",
        "build-ppc64le": "localhost"
    }
