"""
Tests check_noarch.py.
"""

# disable W0201[attribute-defined-outside-init] in pylint
# pylint: disable=W0201

import os
import sys
import unittest

import pytest

from python_scripts.check_noarch import _main as check_noarch


class TestCheckNoarch(unittest.TestCase):
    """
    Unit tests for python_scripts/check_noarch.py.
    """
    maxDiff = None

    @pytest.fixture(autouse=True)
    def pytest_setup(self, capsys):
        """Setup capture of output/err."""
        self.capsys = capsys

    def test_all_noarch_rpm_matches(self):
        """
        Test that all noarch rpm matches.
        """
        result_dir = os.path.realpath(__file__)
        dirname = os.path.dirname(result_dir).removesuffix('tests')
        path_test_source = os.path.join(os.path.dirname(dirname), 'test-source-rpms', 'valid-noarch-subpackage')
        sys.argv = ["this", "--results-dir", path_test_source]
        check_noarch()
        actual = self.capsys.readouterr()
        expected = "All noarch rpms matches each other.\n"
        self.assertIn(expected, actual.out)

    def test_broken_noarch(self):
        """
        Test that noarch rpm is broken.
        """
        result_dir = os.path.realpath(__file__)
        dirname = os.path.dirname(result_dir).removesuffix('tests')
        path_test_source = os.path.join(os.path.dirname(dirname), 'test-source-rpms', 'broken-noarch-subpackage')
        sys.argv = ["this", "--results-dir", path_test_source]
        with pytest.raises(SystemExit) as re:
            check_noarch()
        assert re.value.code == 1
        actual = self.capsys.readouterr()
        expected = "test-noarch-check-noarch-1-1.fc42.noarch.rpm\tmismatch"
        self.assertIn(expected, actual.out)
        expected = "1 errors found"
        self.assertIn(expected, actual.out)
