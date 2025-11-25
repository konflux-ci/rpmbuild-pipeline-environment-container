"""
Tests select_architectures.py.
"""

# disable W0201[attribute-defined-outside-init] in pylint
# pylint: disable=W0201

import json
import os
import shutil
import sys
import tempfile
from unittest import TestCase
from unittest.mock import patch

import pytest

from python_scripts.select_architectures import _main as select_architectures

SELECTED_ARCHES = ["x86_64", "ppc64le", "s390x", "aarch64"]


class TestSelectArchitectures(TestCase):
    """
    Unit tests for python_scripts/select_architectures.py.
    """
    def setUp(self):
        self.maxDiff = None
        self.workdir = tempfile.mkdtemp()
        self.capture = None
        self.testdir = os.path.realpath(__file__)
        self.testdir = os.path.dirname(self.testdir)
        self.patchers = [
            patch("python_scripts.select_architectures.CONFIG_DIR",
                  os.path.join(self.testdir, ".."))
        ]
        for patcher in self.patchers:
            patcher.start()

    def tearDown(self):
        shutil.rmtree(self.workdir)
        for patcher in self.patchers:
            patcher.stop()

    @pytest.fixture(autouse=True)
    def pytest_setup(self, capsys):
        """Setup capture of output/err."""
        self.capsys = capsys

    def _testdir(self, specfile):
        specfile = os.path.join(self.testdir, "specfiles", specfile)
        shutil.copy2(specfile, self.workdir)

    def _run_selected_architectures(self, specfile, additional_args=None):
        self._testdir(specfile)
        results = os.path.join(self.testdir, "results.json")
        sys.argv = ["this", "--workdir", self.workdir,
                    "--results-file", results] + SELECTED_ARCHES
        if additional_args:
            sys.argv += additional_args
        select_architectures()
        with open(results, "r", encoding="utf-8") as rfd:
            return json.load(rfd)

    def test_basic_noarch(self):
        """
        Norpm + exclusive_arch use-case.
        """
        results = self._run_selected_architectures("gdb-exploitable.spec",
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

    def test_basic_multiarch_hermetic(self):
        """
        Without buildArch + exclusive_arch use-case.
        """
        results = self._run_selected_architectures("dpdk.spec",
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

    def test_basic_multiarch_not_hermetic(self):
        """
        Without buildArch + exclusive_arch use-case and without hermetic option.
        """
        results = self._run_selected_architectures("dpdk.spec")
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

    def test_exclude_exlusive_arch(self):
        """
        Test package with both ExclusiveArch and ExcludeArch statements without hermetic option.
        """
        results = self._run_selected_architectures("dummy-pkg-exclude-exclusive-arch.spec")
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

    def test_exclude_exlusive_arch_hermetic(self):
        """
        Test package with both ExclusiveArch and ExcludeArch statements.
        """
        results = self._run_selected_architectures("dummy-pkg-exclude-exclusive-arch.spec",
                                                   ["--hermetic"])
        # exclusivearch covers all architectures, but excludearch
        # drops s390x.
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

    def test_noarch_and_exclusive_arch(self):
        """
        Test package with buildArch and ExclusiveArch statements.
        """
        results = self._run_selected_architectures("dummy-pkg-noarch.spec",
                                                   ["--hermetic"])
        # ExclusiveArch covers all available_architectures, but excludearch
        # filters-out s390x and ppc64le. Noarch picks x86_64 or aarch64 randomly.
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

    def test_exclusive_multiarch(self):
        """
        Test package with ExclusiveArch statement without hermetic option.
        """
        results = self._run_selected_architectures("dummy-exclusive-arch.spec")
        # exclusivearch cover s390x.
        assert results == {
            "deps-x86_64": "localhost",
            "deps-i686": "localhost",
            "deps-aarch64": "localhost",
            "deps-s390x": "localhost",
            "deps-ppc64le": "localhost",
            "build-x86_64": "localhost",
            "build-i686": "localhost",
            "build-aarch64": "localhost",
            "build-s390x": "linux/s390x",
            "build-ppc64le": "localhost"
        }

    def test_noarch_exclusive_exlude(self):
        """
        Test package with buildArch, ExclusiveArch and ExcludeArch statements
        without hermetic option.
        """
        results = self._run_selected_architectures("dummy-build-exclusive-exclude-arch.spec")
        # exclusivearch covers all architectures, but excludearch
        # drops s390x.
        assert results in [{
            "deps-x86_64": "localhost",
            "deps-aarch64": "localhost",
            "deps-i686": "localhost",
            "deps-s390x": "localhost",
            "deps-ppc64le": "localhost",
            "build-x86_64": "linux/amd64",
            "build-aarch64": "localhost",
            "build-i686": "localhost",
            "build-s390x": "localhost",
            "build-ppc64le": "localhost"
        }, {
            "deps-x86_64": "localhost",
            "deps-aarch64": "localhost",
            "deps-i686": "localhost",
            "deps-s390x": "localhost",
            "deps-ppc64le": "localhost",
            "build-x86_64": "localhost",
            "build-aarch64": "linux/arm64",
            "build-i686": "localhost",
            "build-s390x": "localhost",
            "build-ppc64le": "localhost"
        }, {
            "deps-x86_64": "localhost",
            "deps-aarch64": "localhost",
            "deps-i686": "localhost",
            "deps-s390x": "localhost",
            "deps-ppc64le": "localhost",
            "build-x86_64": "localhost",
            "build-aarch64": "localhost",
            "build-i686": "localhost",
            "build-s390x": "localhost",
            "build-ppc64le": "linux/ppc64le"
        }]

    def test_noarch_exclusive_exlude_hermetic(self):
        """
        Test package with buildArch, ExclusiveArch and ExcludeArch statements.
        """
        results = self._run_selected_architectures("dummy-build-exclusive-exclude-arch.spec",
                                                   ["--hermetic"])
        # exclusivearch covers all architectures, but excludearch
        # drops s390x.
        assert results in [{
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
        }, {
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
            "deps-x86_64": "localhost",
            "deps-aarch64": "localhost",
            "deps-i686": "localhost",
            "deps-s390x": "localhost",
            "deps-ppc64le": "linux/ppc64le",
            "build-x86_64": "localhost",
            "build-aarch64": "localhost",
            "build-i686": "localhost",
            "build-s390x": "localhost",
            "build-ppc64le": "linux/ppc64le"
        }]

    def test_exclude_hermetic(self):
        """
        Test package with ExcludeArch statement.
        """
        results = self._run_selected_architectures("dummy-exclude-arch.spec",
                                                   ["--hermetic"])
        # build on all architectures instead of ExcludeArch s390x and
        # i686 which is not in the list of selected architectures
        assert results in [{
            "deps-x86_64": "linux/amd64",
            "deps-aarch64": "linux/arm64",
            "deps-i686": "localhost",
            "deps-s390x": "localhost",
            "deps-ppc64le": "linux/ppc64le",
            "build-x86_64": "linux/amd64",
            "build-aarch64": "linux/arm64",
            "build-i686": "localhost",
            "build-s390x": "localhost",
            "build-ppc64le": "linux/ppc64le"
        }]

    def test_no_specfile(self):
        """
        Test when specfile is not in the directory.
        """
        testdir = '/path/to/test/dir'
        results = os.path.join(testdir, "results.json")
        sys.argv = ["this", "--workdir", testdir,
                    "--results-file", results] + SELECTED_ARCHES
        with self.assertRaises(RuntimeError) as re:
            select_architectures()
        self.assertEqual("no spec file available", str(re.exception))

    def test_more_specfiles(self):
        """
        Test when there are more specfiles in the directory.
        """
        specfiles = ['dpdk.spec', 'gdb-exploitable.spec']
        specfiles_paths = []
        for specfile in specfiles:
            self._testdir(specfile)
            specfiles_paths.append(os.path.join(self.workdir, specfile))
        results = os.path.join(self.testdir, "results.json")
        sys.argv = ["this", "--workdir", self.workdir,
                    "--results-file", results] + SELECTED_ARCHES
        with self.assertRaises(RuntimeError) as re:
            select_architectures()
        expected_err_message_1 = f"too many specfiles: {', '.join(sorted(specfiles_paths))}"
        expected_err_message_2 = f"too many specfiles: {', '.join(sorted(specfiles_paths, reverse=True))}"
        self.assertIn(str(re.exception), [expected_err_message_1, expected_err_message_2])

    def test_unknown_macros(self):
        """
        Test when in ExclusiveArch is unkwnown macros.
        """
        self._testdir("dummy-pkg-unknown-macros.spec")
        results = os.path.join(self.testdir, "results.json")
        sys.argv = ["this", "--workdir", self.workdir,
                    "--results-file", results] + SELECTED_ARCHES
        result = select_architectures()
        actual = self.capsys.readouterr()
        expected = "Unknown macros in"
        self.assertIn(expected, actual.out)
        self.assertEqual(result, None)

    def test_patch_n(self):
        """
        Test when %patchN is in the specfile.
        """
        self._run_selected_architectures("dummy-pkg-patch-n.spec",
                                         ["--hermetic"])
        actual = self.capsys.readouterr()
        expected = "Defining '%patch0 %dnl' macro"
        self.assertIn(expected, actual.out)

    def test_not_specfile(self):
        """
        Test when specfile is not specfile type.
        """
        self._testdir("no_spec_file.spec")
        results = os.path.join(self.testdir, "results.json")
        sys.argv = ["this", "--workdir", self.workdir,
                    "--results-file", results] + SELECTED_ARCHES
        with self.assertRaises(RuntimeError) as re:
            select_architectures()
        self.assertEqual("No .spec file", str(re.exception))
