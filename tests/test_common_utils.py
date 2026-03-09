"""
Tests common_utils.py.
"""

# pylint: disable=W0201,C0116

import hashlib
import logging
import os
import tempfile
import unittest
import urllib.error

from unittest.mock import MagicMock, patch

from common_utils import run_command, is_url_accessible, calc_checksum, setup_logging


class TestCalcChecksum(unittest.TestCase):
    """
    Unit tests for checksum calculation functions.
    """
    def test_calc_checksum_different_algorithms(self):
        """Test checksum calculation with different algorithms."""
        with tempfile.NamedTemporaryFile(mode="w", delete=False) as f:
            f.write("test data")
            temp_file = f.name

        try:
            # Test SHA-256
            sha256 = calc_checksum(temp_file, "sha256")
            self.assertEqual(len(sha256), 64)

            # Test SHA-512
            sha512 = calc_checksum(temp_file, "sha512")
            self.assertEqual(len(sha512), 128)

            # Test MD5
            md5 = calc_checksum(temp_file, "md5")
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

    def test_calc_checksum_large_file(self):
        """Test checksum calculation with chunked reading."""
        with tempfile.NamedTemporaryFile(mode="wb", delete=False) as f:
            # Write data larger than default chunk size
            data = b"x" * (1024 * 1024 + 100)  # > 1MB
            f.write(data)
            temp_file = f.name

        try:
            checksum = calc_checksum(temp_file, "sha256", chunk_size=1024)
            expected = hashlib.sha256(data).hexdigest()
            self.assertEqual(checksum, expected)
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


class TestIsUrlAccessible(unittest.TestCase):
    """
    Unit tests for is_url_accessible function.
    """

    def test_empty_url(self):
        """Test with empty URL."""
        result = is_url_accessible("")
        self.assertFalse(result)

    def test_none_url(self):
        """Test with None URL."""
        result = is_url_accessible(None)
        self.assertFalse(result)

    @patch("urllib.request.build_opener")
    def test_successful_url(self, mock_opener):
        """Test with accessible URL."""
        mock_response = MagicMock()
        mock_response.status = 200
        mock_response.__enter__ = MagicMock(return_value=mock_response)
        mock_response.__exit__ = MagicMock(return_value=False)

        mock_opener_instance = MagicMock()
        mock_opener_instance.open.return_value = mock_response
        mock_opener.return_value = mock_opener_instance

        result = is_url_accessible("https://example.com/file.tar.gz")
        self.assertTrue(result)

    @patch("urllib.request.build_opener")
    def test_failed_url(self, mock_opener):
        """Test with inaccessible URL."""
        mock_opener_instance = MagicMock()
        mock_opener_instance.open.side_effect = urllib.error.URLError("Not found")
        mock_opener.return_value = mock_opener_instance

        result = is_url_accessible("https://example.com/nonexistent.tar.gz")
        self.assertFalse(result)

    @patch("urllib.request.build_opener")
    def test_timeout_url(self, mock_opener):
        """Test URL request timeout."""
        mock_opener_instance = MagicMock()
        mock_opener_instance.open.side_effect = TimeoutError("Timeout")
        mock_opener.return_value = mock_opener_instance

        result = is_url_accessible("https://slow-server.com/file.tar.gz")
        self.assertFalse(result)

    @patch("urllib.request.build_opener")
    def test_non_200_status(self, mock_opener):
        """Test URL with non-200 status code."""
        mock_response = MagicMock()
        mock_response.status = 404
        mock_response.__enter__ = MagicMock(return_value=mock_response)
        mock_response.__exit__ = MagicMock(return_value=False)

        mock_opener_instance = MagicMock()
        mock_opener_instance.open.return_value = mock_response
        mock_opener.return_value = mock_opener_instance

        result = is_url_accessible("https://example.com/notfound.tar.gz")
        self.assertFalse(result)


class TestRunCommand(unittest.TestCase):
    """
    Unit tests for run_command function.
    """

    @patch("subprocess.run")
    def test_simple_command(self, mock_run):
        """Test running a simple command."""
        mock_result = MagicMock()
        mock_result.stdout = "output"
        mock_result.stderr = ""
        mock_result.returncode = 0
        mock_run.return_value = mock_result

        run_command(["echo", "test"])

        mock_run.assert_called_once()
        call_args = mock_run.call_args
        self.assertEqual(call_args[0][0], ["echo", "test"])
        self.assertTrue(call_args[1]["capture_output"])
        self.assertTrue(call_args[1]["text"])
        self.assertTrue(call_args[1]["check"])

    @patch("subprocess.run")
    def test_command_with_cwd(self, mock_run):
        """Test running command with custom working directory."""
        mock_result = MagicMock()
        mock_result.stdout = ""
        mock_result.stderr = ""
        mock_result.returncode = 0
        mock_run.return_value = mock_result

        run_command(["ls"], cwd="/tmp")

        call_args = mock_run.call_args
        self.assertEqual(call_args[1]["cwd"], "/tmp")

    @patch("subprocess.run")
    def test_shell_command(self, mock_run):
        """Test running shell command (string)."""
        mock_result = MagicMock()
        mock_result.stdout = ""
        mock_result.stderr = ""
        mock_result.returncode = 0
        mock_run.return_value = mock_result

        run_command("echo test")

        call_args = mock_run.call_args
        self.assertEqual(call_args[0][0], "echo test")
        self.assertTrue(call_args[1]["shell"])

    @patch("subprocess.run")
    def test_command_without_capture(self, mock_run):
        """Test running command without capturing output."""
        mock_result = MagicMock()
        mock_result.returncode = 0
        mock_run.return_value = mock_result

        run_command(["echo", "test"], capture_output=False)

        call_args = mock_run.call_args
        self.assertFalse(call_args[1]["capture_output"])


if __name__ == "__main__":
    unittest.main()
