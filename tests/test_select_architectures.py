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

import pytest

from select_architectures import _main as select_architectures
from select_architectures import get_arch_specific_tags

SELECTED_ARCHES = ["x86_64", "i686", "ppc64le", "s390", "s390x", "aarch64"]


class TestSelectArchitectures(TestCase):
    """
    Unit tests for python_scripts/select_architectures.py.
    """
    # pylint: disable=too-many-public-methods
    def setUp(self):
        self.maxDiff = None
        self.workdir = tempfile.mkdtemp()
        self.testdir = ''
        self.capture = None

    def tearDown(self):
        shutil.rmtree(self.workdir)

    @pytest.fixture(autouse=True)
    def pytest_setup(self, capsys):
        """Setup capture of output/err."""
        self.capsys = capsys

    def _testdir(self, specfile):
        self.testdir = os.path.realpath(__file__)
        self.testdir = os.path.dirname(self.testdir)
        specfile = os.path.join(self.testdir, "specfiles", specfile)
        shutil.copy2(specfile, self.workdir)

    def _run_selected_architectures(self, specfile, additional_args=None):
        self._testdir(specfile)
        results = os.path.join(self.testdir, "results.json")
        overrides = os.path.join(self.testdir, "..", "arch-specific-macro-overrides.json")
        sys.argv = ["this", "--workdir", self.workdir,
                    "--macro-overrides-file", overrides,
                    "--results-file", results] + SELECTED_ARCHES
        if additional_args:
            sys.argv += additional_args
        select_architectures()
        with open(results, "r", encoding="utf-8") as rfd:
            return json.load(rfd)

    def test_basic_noarch(self):
        """
        BuildArch: noarch + ExclusiveArch: x86_64 i386.
        Noarch task only, platform selected from ExclusiveArch-filtered arches.
        """
        results = self._run_selected_architectures("gdb-exploitable.spec",
                                                   ["--hermetic"])
        assert results == {
            "deps-x86_64": "localhost",
            "deps-i686": "localhost",
            "deps-aarch64": "localhost",
            "deps-s390": "localhost",
            "deps-s390x": "localhost",
            "deps-ppc64le": "localhost",
            "deps-noarch": "linux/amd64",
            "build-x86_64": "localhost",
            "build-i686": "localhost",
            "build-aarch64": "localhost",
            "build-s390": "localhost",
            "build-s390x": "localhost",
            "build-ppc64le": "localhost",
            "build-noarch": "linux/amd64",
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
            "deps-i686": "linux/amd64",
            "deps-aarch64": "linux/arm64",
            "deps-s390": "localhost",
            "deps-s390x": "localhost",
            "deps-ppc64le": "linux/ppc64le",
            "deps-noarch": "localhost",
            "build-i686": "linux/amd64",
            "build-x86_64": "linux/amd64",
            "build-aarch64": "linux/arm64",
            "build-s390": "localhost",
            "build-s390x": "localhost",
            "build-ppc64le": "linux/ppc64le",
            "build-noarch": "localhost",
        }

    def test_basic_multiarch_not_hermetic(self):
        """
        Without buildArch + exclusive_arch use-case and without hermetic option.
        """
        results = self._run_selected_architectures("dpdk.spec")
        # This should build on x86_64, aarch64 and ppc64le
        assert results == {
            "deps-i686": "localhost",
            "deps-x86_64": "localhost",
            "deps-aarch64": "localhost",
            "deps-s390": "localhost",
            "deps-s390x": "localhost",
            "deps-ppc64le": "localhost",
            "deps-noarch": "localhost",
            "build-i686": "linux/amd64",
            "build-x86_64": "linux/amd64",
            "build-aarch64": "linux/arm64",
            "build-s390": "localhost",
            "build-s390x": "localhost",
            "build-ppc64le": "linux/ppc64le",
            "build-noarch": "localhost",
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
            "deps-s390": "localhost",
            "deps-s390x": "localhost",
            "deps-ppc64le": "localhost",
            "deps-noarch": "localhost",
            "build-x86_64": "linux/amd64",
            "build-i686": "localhost",
            "build-aarch64": "linux/arm64",
            "build-s390": "localhost",
            "build-s390x": "localhost",
            "build-ppc64le": "linux/ppc64le",
            "build-noarch": "localhost",
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
            "deps-s390": "localhost",
            "deps-s390x": "localhost",
            "deps-ppc64le": "linux/ppc64le",
            "deps-noarch": "localhost",
            "build-x86_64": "linux/amd64",
            "build-i686": "localhost",
            "build-aarch64": "linux/arm64",
            "build-s390": "localhost",
            "build-s390x": "localhost",
            "build-ppc64le": "linux/ppc64le",
            "build-noarch": "localhost",
        }

    def test_noarch_and_exclusive_arch(self):
        """
        BuildArch: noarch + ExclusiveArch: x86_64 aarch64.
        Noarch task only, platform deterministically selects x86_64.
        """
        results = self._run_selected_architectures("dummy-pkg-noarch.spec",
                                                   ["--hermetic"])
        assert results == {
            "deps-i686": "localhost",
            "deps-x86_64": "localhost",
            "deps-aarch64": "localhost",
            "deps-s390": "localhost",
            "deps-s390x": "localhost",
            "deps-ppc64le": "localhost",
            "deps-noarch": "linux/amd64",
            "build-i686": "localhost",
            "build-x86_64": "localhost",
            "build-aarch64": "localhost",
            "build-s390": "localhost",
            "build-s390x": "localhost",
            "build-ppc64le": "localhost",
            "build-noarch": "linux/amd64",
        }

    def test_exclusive_multiarch(self):
        """
        Test package with ExclusiveArch statement without hermetic option.
        """
        results = self._run_selected_architectures("dummy-exclusive-arch.spec")
        # exclusivearch cover s390x. (non-hermetic - no deps tasks)
        assert results == {
            "deps-x86_64": "localhost",
            "deps-i686": "localhost",
            "deps-aarch64": "localhost",
            "deps-s390": "localhost",
            "deps-s390x": "localhost",
            "deps-ppc64le": "localhost",
            "deps-noarch": "localhost",
            "build-x86_64": "localhost",
            "build-i686": "localhost",
            "build-aarch64": "localhost",
            "build-s390": "localhost",
            "build-s390x": "linux/s390x",
            "build-ppc64le": "localhost",
            "build-noarch": "localhost",
        }

    def test_noarch_exclusive_exlude(self):
        """
        BuildArch: noarch + ExclusiveArch: %java_arches + ExcludeArch: s390x.
        Noarch task only, platform deterministically selects x86_64.
        """
        results = self._run_selected_architectures("dummy-build-exclusive-exclude-arch.spec")
        assert results == {
            "deps-x86_64": "localhost",
            "deps-aarch64": "localhost",
            "deps-i686": "localhost",
            "deps-s390": "localhost",
            "deps-s390x": "localhost",
            "deps-ppc64le": "localhost",
            "deps-noarch": "localhost",
            "build-x86_64": "localhost",
            "build-aarch64": "localhost",
            "build-i686": "localhost",
            "build-s390": "localhost",
            "build-s390x": "localhost",
            "build-ppc64le": "localhost",
            "build-noarch": "linux/amd64",
        }

    def test_noarch_exclusive_exlude_hermetic(self):
        """
        BuildArch: noarch + ExclusiveArch: %java_arches + ExcludeArch: s390x, hermetic.
        Noarch task only, platform deterministically selects x86_64.
        """
        results = self._run_selected_architectures("dummy-build-exclusive-exclude-arch.spec",
                                                   ["--hermetic"])
        assert results == {
            "deps-x86_64": "localhost",
            "deps-aarch64": "localhost",
            "deps-i686": "localhost",
            "deps-s390": "localhost",
            "deps-s390x": "localhost",
            "deps-ppc64le": "localhost",
            "deps-noarch": "linux/amd64",
            "build-x86_64": "localhost",
            "build-aarch64": "localhost",
            "build-i686": "localhost",
            "build-s390": "localhost",
            "build-s390x": "localhost",
            "build-ppc64le": "localhost",
            "build-noarch": "linux/amd64",
        }

    def test_exclude_hermetic(self):
        """
        Test package with ExcludeArch statement.
        """
        results = self._run_selected_architectures("dummy-exclude-arch.spec",
                                                   ["--hermetic"])
        # build on all architectures instead of ExcludeArch s390x
        assert results == {
            "deps-i686": "linux/amd64",
            "deps-x86_64": "linux/amd64",
            "deps-aarch64": "linux/arm64",
            "deps-s390": "linux/s390x",
            "deps-s390x": "localhost",
            "deps-ppc64le": "linux/ppc64le",
            "deps-noarch": "localhost",
            "build-i686": "linux/amd64",
            "build-x86_64": "linux/amd64",
            "build-aarch64": "linux/arm64",
            "build-s390": "linux/s390x",
            "build-s390x": "localhost",
            "build-ppc64le": "linux/ppc64le",
            "build-noarch": "localhost",
        }

    def test_no_specfile(self):
        """
        Test when specfile is not in the directory.
        """
        testdir = '/path/to/test/dir'
        results = os.path.join(testdir, "results.json")
        sys.argv = ["this", "--workdir", testdir,
                    "--results-file", results] + SELECTED_ARCHES
        with self.assertRaises(FileNotFoundError) as re:
            select_architectures()
        self.assertIn("No specfile found", str(re.exception))

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
        with self.assertRaises(OSError) as re:
            select_architectures()
        self.assertIn("Multiple specfiles found", str(re.exception))

    def test_unknown_macros(self):
        """
        Test when in ExclusiveArch is unkwnown macros.
        """
        self._testdir("dummy-pkg-unknown-macros.spec")
        results = os.path.join(self.testdir, "results.json")
        overrides = os.path.join(self.testdir, "..", "arch-specific-macro-overrides.json")
        sys.argv = ["this", "--workdir", self.workdir,
                    "--macro-overrides-file", overrides,
                    "--results-file", results] + SELECTED_ARCHES
        select_architectures()
        actual = self.capsys.readouterr()
        expected = "Unknown macros in"
        self.assertIn(expected, actual.out)

    def test_spec_syntax_error(self):
        """
        Norpm raises error.  We just ignore the error, and take the outcomes
        from the part of specfile that was successfully parsed.
        """
        results = self._run_selected_architectures("syntax-error.spec",
                                                   ["--hermetic"])
        assert results == {
            "build-aarch64": "linux/arm64",
            "build-i686": "localhost",
            "build-ppc64le": "localhost",
            "build-s390": "localhost",
            "build-s390x": "localhost",
            "build-x86_64": "localhost",
            "build-noarch": "localhost",
            "deps-aarch64": "linux/arm64",
            "deps-i686": "localhost",
            "deps-noarch": "localhost",
            "deps-ppc64le": "localhost",
            "deps-s390": "localhost",
            "deps-s390x": "localhost",
            "deps-x86_64": "localhost",
        }


    def test_macro_overrides(self):
        """
        Check that %rhel is defined if we override.  ROK-1036
        """
        results = self._run_selected_architectures("dummy-pkg-for-rhel.spec",
                                                   ["--hermetic", "--target-distribution", "rhel-10"])
        assert results == {
            "build-aarch64": "linux/arm64",
            "build-i686": "localhost",
            "build-ppc64le": "localhost",
            "build-s390": "localhost",
            "build-s390x": "localhost",
            "build-x86_64": "linux/amd64",
            "build-noarch": "localhost",
            "deps-aarch64": "linux/arm64",
            "deps-i686": "localhost",
            "deps-noarch": "localhost",
            "deps-ppc64le": "localhost",
            "deps-s390": "localhost",
            "deps-s390x": "localhost",
            "deps-x86_64": "linux/amd64",
        }


    def test_multiple_statements(self):
        """
        Test that we concatenate multiple Exclu*Arch statements.
        """
        testdir = os.path.dirname(os.path.realpath(__file__))
        specfile = os.path.join(testdir, "specfiles",
                                "dummy-pkg-multiple-tags.spec")
        overrides = os.path.join(testdir, "..", "arch-specific-macro-overrides.json")
        assert get_arch_specific_tags(specfile, overrides, "rhel-10") == {
            'buildarch': {
                'noarch',
            },
            'excludearch': {
                's390x',
                'weirdarch',
                'on-rhel-excludearch',
            },
            'exclusivearch': {
                'aarch64',
                'i686',
                'noarch',
                'on-rhel-exclusivearch',
                'ppc64le',
                'riscv64',
                's390x',
                'x86_64',
            }}

        assert get_arch_specific_tags(specfile, overrides, "fedora-42") == {
            'buildarch': {
                'noarch',
            },
            'excludearch': {
                's390x',
                'weirdarch',
                'on-fedora-excludearch',
            },
            'exclusivearch': {
                'aarch64',
                'i686',
                'noarch',
                'on-fedora-exclusivearch',
                'ppc64le',
                'riscv64',
                's390x',
                'x86_64',
            }}

    def test_platform_override(self):
        """
        Test platform override via --platform-labels argument.
        """
        results = self._run_selected_architectures("dpdk.spec",["--hermetic", "--platform-labels",
                                                                "linux-beefy/amd64", "linux-beefy/arm64"])
        expected_results = {
            "deps-i686": "linux/amd64",
            "deps-x86_64": "linux/amd64",
            "deps-aarch64": "linux/arm64",
            "deps-s390": "localhost",
            "deps-s390x": "localhost",
            "deps-ppc64le": "linux/ppc64le",
            "deps-noarch": "localhost",
            "build-i686": "linux-beefy/amd64",
            "build-x86_64": "linux-beefy/amd64",
            "build-aarch64": "linux-beefy/arm64",
            "build-s390": "localhost",
            "build-s390x": "localhost",
            "build-ppc64le": "linux/ppc64le",
            "build-noarch": "localhost",
        }

        assert results == expected_results

    def test_platform_override_invalid_format(self):
        """
        Test platform override with invalid format.
        """
        self._run_selected_architectures("dpdk.spec",
                                         ["--hermetic", "--platform-labels", "invalid-format-string"])
        captured = self.capsys.readouterr()
        assert "Warning: Unknown architecture suffix" in captured.out

    def test_non_noarch_buildarch(self):
        """
        BuildArch: x86_64 (non-noarch).
        Builds restricted to x86_64 only, matching Koji's behavior where
        BuildArch replaces the architecture list.
        """
        results = self._run_selected_architectures(
            "dummy-pkg-buildarch-x86_64.spec")
        assert results == {
            "deps-x86_64": "localhost",
            "deps-i686": "localhost",
            "deps-aarch64": "localhost",
            "deps-s390": "localhost",
            "deps-s390x": "localhost",
            "deps-ppc64le": "localhost",
            "deps-noarch": "localhost",
            "build-x86_64": "linux/amd64",
            "build-i686": "localhost",
            "build-aarch64": "localhost",
            "build-s390": "localhost",
            "build-s390x": "localhost",
            "build-ppc64le": "localhost",
            "build-noarch": "localhost",
        }

    def test_exclusive_noarch_only(self):
        """
        BuildArch: noarch + ExclusiveArch: noarch.
        Noarch re-addition fires via BuildArch.  ExclusiveArch: noarch empties
        the real arches but noarch is re-added.  Platform falls back to all
        allowed arches; x86_64 wins by priority.
        """
        results = self._run_selected_architectures(
            "dummy-pkg-exclusive-noarch.spec", ["--hermetic"])
        assert results == {
            "deps-x86_64": "localhost",
            "deps-i686": "localhost",
            "deps-aarch64": "localhost",
            "deps-s390": "localhost",
            "deps-s390x": "localhost",
            "deps-ppc64le": "localhost",
            "deps-noarch": "linux/amd64",
            "build-x86_64": "localhost",
            "build-i686": "localhost",
            "build-aarch64": "localhost",
            "build-s390": "localhost",
            "build-s390x": "localhost",
            "build-ppc64le": "localhost",
            "build-noarch": "linux/amd64",
        }

    def test_exclusive_noarch_with_real_arch(self):
        """
        BuildArch: noarch + ExclusiveArch: noarch x86_64.
        Noarch task only, platform from filtered arches: x86_64.
        """
        results = self._run_selected_architectures(
            "dummy-pkg-exclusive-noarch-x86_64.spec", ["--hermetic"])
        assert results == {
            "deps-x86_64": "localhost",
            "deps-i686": "localhost",
            "deps-aarch64": "localhost",
            "deps-s390": "localhost",
            "deps-s390x": "localhost",
            "deps-ppc64le": "localhost",
            "deps-noarch": "linux/amd64",
            "build-x86_64": "localhost",
            "build-i686": "localhost",
            "build-aarch64": "localhost",
            "build-s390": "localhost",
            "build-s390x": "localhost",
            "build-ppc64le": "localhost",
            "build-noarch": "linux/amd64",
        }

    def test_all_arches_excluded(self):
        """
        ExcludeArch lists all SELECTED_ARCHES.  Should raise SystemExit
        with a clear error instead of crashing with IndexError.
        """
        with self.assertRaises(SystemExit) as ctx:
            self._run_selected_architectures("dummy-pkg-exclude-all.spec")
        assert "No valid architectures remain" in str(ctx.exception)

    def test_exclusive_noarch_without_buildarch(self):
        """
        ExclusiveArch: noarch without BuildArch.
        Noarch re-addition fires via ExclusiveArch.  Only noarch task active.
        Matches Koji getArchList returning ['noarch'].
        """
        results = self._run_selected_architectures(
            "dummy-pkg-exclusive-noarch-no-buildarch.spec")
        assert results == {
            "deps-x86_64": "localhost",
            "deps-i686": "localhost",
            "deps-aarch64": "localhost",
            "deps-s390": "localhost",
            "deps-s390x": "localhost",
            "deps-ppc64le": "localhost",
            "deps-noarch": "localhost",
            "build-x86_64": "localhost",
            "build-i686": "localhost",
            "build-aarch64": "localhost",
            "build-s390": "localhost",
            "build-s390x": "localhost",
            "build-ppc64le": "localhost",
            "build-noarch": "linux/amd64",
        }

    def test_noarch_excluded(self):
        """
        BuildArch: noarch + ExcludeArch: noarch.
        ExcludeArch: noarch prevents noarch re-addition (Koji kojid line 1407).
        Should raise SystemExit.
        """
        with self.assertRaises(SystemExit) as ctx:
            self._run_selected_architectures("dummy-pkg-noarch-excluded.spec")
        assert "noarch is excluded" in str(ctx.exception)

    def test_mixed_arch_and_noarch(self):
        """
        ExclusiveArch: x86_64 noarch (no BuildArch).
        Both build-x86_64 and build-noarch should be active.
        """
        results = self._run_selected_architectures(
            "dummy-pkg-mixed-arch-noarch.spec")
        assert results == {
            "deps-x86_64": "localhost",
            "deps-i686": "localhost",
            "deps-aarch64": "localhost",
            "deps-s390": "localhost",
            "deps-s390x": "localhost",
            "deps-ppc64le": "localhost",
            "deps-noarch": "localhost",
            "build-x86_64": "linux/amd64",
            "build-i686": "localhost",
            "build-aarch64": "localhost",
            "build-s390": "localhost",
            "build-s390x": "localhost",
            "build-ppc64le": "localhost",
            "build-noarch": "linux/amd64",
        }
