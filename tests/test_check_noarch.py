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
        path_test_source = os.path.join(os.path.dirname(dirname), 'test-source-rpms')
        sys.argv = ["this", "--results-dir", path_test_source]
        check_noarch()
        actual = self.capsys.readouterr()
        expected = "All noarch rpms matches each other.\n"
        self.assertEqual(expected, actual.out)
