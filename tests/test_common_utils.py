"""
Tests common_utils.py.
"""

# pylint: disable=W0201,C0116

import hashlib
import logging
import os
import tempfile
import unittest
from unittest.mock import patch

from common_utils import calc_checksum, setup_logging


class TestCalcChecksum(unittest.TestCase):
    """
    Unit tests for calc_checksum function.
    """

    def test_sha256_checksum(self):
        """Test calculating SHA256 checksum."""
        with tempfile.NamedTemporaryFile(mode='w', delete=False) as f:
            f.write("test content")
            temp_file = f.name

        try:
            checksum = calc_checksum(temp_file, "sha256")
            # SHA256 of "test content" is known
            self.assertEqual(len(checksum), 64)  # SHA256 is 64 hex chars
            self.assertTrue(all(c in '0123456789abcdef' for c in checksum))
        finally:
            os.unlink(temp_file)

    def test_different_algorithms(self):
        """Test different hash algorithms."""
        with tempfile.NamedTemporaryFile(mode='w', delete=False) as f:
            f.write("test")
            temp_file = f.name

        try:
            sha256 = calc_checksum(temp_file, "sha256")
            sha512 = calc_checksum(temp_file, "sha512")
            md5 = calc_checksum(temp_file, "md5")

            self.assertEqual(len(sha256), 64)
            self.assertEqual(len(sha512), 128)
            self.assertEqual(len(md5), 32)
        finally:
            os.unlink(temp_file)

    def test_consistent_checksum(self):
        """Test that same file produces same checksum."""
        with tempfile.NamedTemporaryFile(mode='w', delete=False) as f:
            f.write("consistent content")
            temp_file = f.name

        try:
            checksum1 = calc_checksum(temp_file, "sha256")
            checksum2 = calc_checksum(temp_file, "sha256")
            self.assertEqual(checksum1, checksum2)
        finally:
            os.unlink(temp_file)

    def test_different_content_different_checksum(self):
        """Test that different content produces different checksums."""
        with tempfile.NamedTemporaryFile(mode='w', delete=False) as f1:
            f1.write("content1")
            temp_file1 = f1.name

        with tempfile.NamedTemporaryFile(mode='w', delete=False) as f2:
            f2.write("content2")
            temp_file2 = f2.name

        try:
            checksum1 = calc_checksum(temp_file1, "sha256")
            checksum2 = calc_checksum(temp_file2, "sha256")
            self.assertNotEqual(checksum1, checksum2)
        finally:
            os.unlink(temp_file1)
            os.unlink(temp_file2)

    def test_large_file(self):
        """Test checksum calculation on larger file."""
        with tempfile.NamedTemporaryFile(mode='wb', delete=False) as f:
            # Write 2MB of data
            f.write(b'x' * (2 * 1024 * 1024))
            temp_file = f.name

        try:
            checksum = calc_checksum(temp_file, "sha256")
            self.assertEqual(len(checksum), 64)
        finally:
            os.unlink(temp_file)

    def test_empty_file(self):
        """Test checksum of empty file."""
        with tempfile.NamedTemporaryFile(mode='w', delete=False) as f:
            temp_file = f.name

        try:
            checksum = calc_checksum(temp_file, "sha256")
            # SHA256 of empty string is known
            empty_sha256 = hashlib.sha256(b'').hexdigest()
            self.assertEqual(checksum, empty_sha256)
        finally:
            os.unlink(temp_file)

    def test_case_insensitive_algorithm(self):
        """Test that algorithm name is case-insensitive."""
        with tempfile.NamedTemporaryFile(mode='w', delete=False) as f:
            f.write("test")
            temp_file = f.name

        try:
            lower = calc_checksum(temp_file, "sha256")
            upper = calc_checksum(temp_file, "SHA256")
            mixed = calc_checksum(temp_file, "Sha256")
            self.assertEqual(lower, upper)
            self.assertEqual(lower, mixed)
        finally:
            os.unlink(temp_file)


class TestSetupLogging(unittest.TestCase):
    """
    Unit tests for setup_logging function.
    """

    @patch("common_utils.logging.basicConfig")
    def test_default_level_is_info(self, mock_basic_config):
        """Test that default logging level is INFO."""
        setup_logging()
        mock_basic_config.assert_called_once_with(
            level=logging.INFO,
            format="[%(asctime)s] %(levelname)s: %(message)s",
            datefmt="%Y-%m-%d %H:%M:%S",
        )

    @patch("common_utils.logging.basicConfig")
    def test_debug_true_sets_debug_level(self, mock_basic_config):
        """Test that debug=True sets DEBUG level."""
        setup_logging(debug=True)
        mock_basic_config.assert_called_once_with(
            level=logging.DEBUG,
            format="[%(asctime)s] %(levelname)s: %(message)s",
            datefmt="%Y-%m-%d %H:%M:%S",
        )

    @patch("common_utils.logging.basicConfig")
    def test_debug_false_sets_info_level(self, mock_basic_config):
        """Test that debug=False explicitly sets INFO level."""
        setup_logging(debug=False)
        mock_basic_config.assert_called_once_with(
            level=logging.INFO,
            format="[%(asctime)s] %(levelname)s: %(message)s",
            datefmt="%Y-%m-%d %H:%M:%S",
        )


if __name__ == "__main__":
    unittest.main()
