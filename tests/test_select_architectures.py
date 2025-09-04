"""
Tests select_architectures.py.
"""

import json
import os
import shutil
import sys
import tempfile

from python_scripts.select_architectures import _main as select_architectures

SELECTED_ARCHES = ["x86_64", "ppc64le", "s390x", "aarch64"]


def _testdir(specfile):
    workdir = tempfile.mkdtemp()
    testdir = os.path.realpath(__file__)
    testdir = os.path.dirname(testdir)
    specfile = os.path.join(testdir, "specfiles", specfile)
    shutil.copy2(specfile, workdir)
    return workdir


def _run_selected_architectures(specfile, additional_args=None):
    testdir = _testdir(specfile)
    results = os.path.join(testdir, "results.json")
    sys.argv = ["this", "--workdir", testdir,
                "--results-file", results] + SELECTED_ARCHES
    if additional_args:
        sys.argv += additional_args
    select_architectures()
    with open(results, "r", encoding="utf-8") as rfd:
        return json.load(rfd)


def test_basic_noarch():
    """
    Norpm + exclusive_arch use-case.
    """
    results = _run_selected_architectures("gdb-exploitable.spec",
                                          ["--hermetic"])
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


def test_basic_multiarch_hermetic():
    """
    Without buildArch + exclusive_arch use-case.
    """
    results = _run_selected_architectures("dpdk.spec",
                                          ["--hermetic"])

    # This should build on x86_64, aarch64 and ppc64le
    assert results == {
        "deps-x86_64": "linux/amd64",
        "deps-i686": "localhost",
        "deps-aarch64": "linux/arm64",
        "deps-s390x": "localhost",
        "deps-ppc64le": "linux/ppc64le",
        "build-x86_64": "linux/amd64",
        "build-i686": "localhost",
        "build-aarch64": "linux/arm64",
        "build-s390x": "localhost",
        "build-ppc64le": "linux/ppc64le"
    }


def test_basic_multiarch_not_hermetic():
    """
    Without buildArch + exclusive_arch use-case and without hermetic option.
    """
    results = _run_selected_architectures("dpdk.spec")
    # This should build on x86_64, aarch64 and ppc64le
    assert results == {
        "deps-x86_64": "localhost",
        "deps-i686": "localhost",
        "deps-aarch64": "localhost",
        "deps-s390x": "localhost",
        "deps-ppc64le": "localhost",
        "build-x86_64": "linux/amd64",
        "build-i686": "localhost",
        "build-aarch64": "linux/arm64",
        "build-s390x": "localhost",
        "build-ppc64le": "linux/ppc64le"
    }


def test_exclude_arch():
    """
    Test package with both ExclusiveArch and ExcludeArch statements.
    """
    results = _run_selected_architectures("dummy-pkg-exclude-exclusive-arch.spec")
    # exclusivearch covers all architectures, but excludearch
    # drops s390x.
    assert results == {
        "deps-x86_64": "localhost",
        "deps-i686": "localhost",
        "deps-aarch64": "localhost",
        "deps-s390x": "localhost",
        "deps-ppc64le": "localhost",
        "build-x86_64": "linux/amd64",
        "build-i686": "localhost",
        "build-aarch64": "linux/arm64",
        "build-s390x": "localhost",
        "build-ppc64le": "linux/ppc64le"
    }


def test_noarch_and_exclusive_arch():
    """
    Test package with both ExclusiveArch and ExcludeArch statements.
    """
    results = _run_selected_architectures("dummy-pkg-noarch.spec",
                                          ["--hermetic"])
    # ExclusiveArch covers all available_architectures, but excludearch
    # filters-out s390x and ppc64le.  Noarch picks x86_64 or aarch64 randomly.
    assert results in [{
        "deps-x86_64": "localhost",
        "deps-aarch64": "linux/arm64",
        "deps-i686": "localhost",
        "deps-s390x": "localhost",
        "deps-ppc64le": "localhost",
        "build-x86_64": "localhost",
        "build-aarch64": "linux/arm64",
        "build-i686": "localhost",
        "build-s390x": "localhost",
        "build-ppc64le": "localhost"
    }, {
        "deps-x86_64": "linux/amd64",
        "deps-aarch64": "localhost",
        "deps-i686": "localhost",
        "deps-s390x": "localhost",
        "deps-ppc64le": "localhost",
        "build-x86_64": "linux/amd64",
        "build-aarch64": "localhost",
        "build-i686": "localhost",
        "build-s390x": "localhost",
        "build-ppc64le": "localhost"
    }]
