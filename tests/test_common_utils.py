"""
Tests common_utils.py.
"""

# pylint: disable=W0201,C0116

import hashlib
import logging
import os
import tempfile
import unittest

from common_utils import (
    sanitize_error_message,
    WrappingFormatter,
    setup_logging,
    calc_checksum,
)


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


class TestSanitizeErrorMessage(unittest.TestCase):
    """
    Unit tests for sanitize_error_message function.
    """

    def test_redact_password_equals(self):
        """Test redacting password in key=value format."""
        msg = "Error: password=secretpass123"
        result = sanitize_error_message(msg)
        self.assertIn("<REDACTED>", result)
        self.assertNotIn("secretpass123", result)

    def test_redact_password_json(self):
        """Test redacting password in JSON format."""
        msg = '{"password": "secretpass123"}'
        result = sanitize_error_message(msg)
        self.assertIn("<REDACTED>", result)
        self.assertNotIn("secretpass123", result)

    def test_redact_multiple_sensitive_fields(self):
        """Test redacting multiple sensitive fields."""
        msg = "Error: password=secret123, api_key=key456, token=tok789"
        result = sanitize_error_message(msg)
        self.assertNotIn("secret123", result)
        self.assertNotIn("key456", result)
        self.assertNotIn("tok789", result)
        # Verify at least one REDACTED is present
        self.assertIn("<REDACTED>", result)

    def test_redact_token_json_format(self):
        """Test redacting token in JSON format."""
        msg = '{"access_token": "bearer_abc123xyz"}'
        result = sanitize_error_message(msg)
        self.assertIn("<REDACTED>", result)
        self.assertNotIn("bearer_abc123xyz", result)

    def test_case_insensitive_redaction(self):
        """Test that redaction is case-insensitive."""
        msg = "Error: PASSWORD=secret, Password=secret2"
        result = sanitize_error_message(msg)
        self.assertNotIn("secret", result)
        self.assertNotIn("secret2", result)

    def test_redact_client_secret(self):
        """Test redacting client_secret field."""
        msg = 'config: client_secret = "super_secret_value"'
        result = sanitize_error_message(msg)
        self.assertIn("<REDACTED>", result)
        self.assertNotIn("super_secret_value", result)

    def test_redact_private_key(self):
        """Test redacting private_key field."""
        msg = "private_key='-----BEGIN PRIVATE KEY-----'"
        result = sanitize_error_message(msg)
        self.assertIn("<REDACTED>", result)
        self.assertNotIn("BEGIN PRIVATE KEY", result)

    def test_no_sensitive_data(self):
        """Test that non-sensitive messages are unchanged."""
        msg = "Error: connection timeout, retrying..."
        result = sanitize_error_message(msg)
        self.assertEqual(msg, result)

    def test_empty_string(self):
        """Test with empty string."""
        msg = ""
        result = sanitize_error_message(msg)
        self.assertEqual(msg, result)

    def test_redact_with_quotes(self):
        """Test redacting values with different quote styles."""
        msg = 'password="quoted_secret", token=\'single_quoted\''
        result = sanitize_error_message(msg)
        self.assertNotIn("quoted_secret", result)
        self.assertNotIn("single_quoted", result)


class TestWrappingFormatter(unittest.TestCase):
    """
    Unit tests for WrappingFormatter class.
    """

    def test_short_message_no_wrapping(self):
        """Test that short messages are not wrapped."""
        formatter = WrappingFormatter(width=80)
        record = logging.LogRecord(
            name="test",
            level=logging.INFO,
            pathname="",
            lineno=0,
            msg="Short message",
            args=(),
            exc_info=None
        )
        result = formatter.format(record)
        self.assertNotIn("\n", result)

    def test_long_message_wrapping(self):
        """Test that long messages are wrapped."""
        formatter = WrappingFormatter(width=50)
        long_msg = "This is a very long message that should definitely be wrapped " * 3
        record = logging.LogRecord(
            name="test",
            level=logging.INFO,
            pathname="",
            lineno=0,
            msg=long_msg,
            args=(),
            exc_info=None
        )
        result = formatter.format(record)
        # Should have line breaks
        lines = result.split('\n')
        self.assertGreater(len(lines), 1)
        # Each line should be <= width
        for line in lines:
            self.assertLessEqual(len(line), 50)

    def test_custom_width(self):
        """Test formatter with custom width."""
        formatter = WrappingFormatter(width=40)
        self.assertEqual(formatter.width, 40)

    def test_format_with_timestamp(self):
        """Test formatting with timestamp."""
        formatter = WrappingFormatter(
            fmt='%(asctime)s - %(message)s',
            width=100
        )
        record = logging.LogRecord(
            name="test",
            level=logging.INFO,
            pathname="",
            lineno=0,
            msg="Test message",
            args=(),
            exc_info=None
        )
        result = formatter.format(record)
        self.assertIn("Test message", result)


class TestSetupLogging(unittest.TestCase):
    """
    Unit tests for setup_logging function.
    """

    def setUp(self):
        """Clear logging handlers before each test."""
        # Store original handlers
        self.original_handlers = logging.root.handlers[:]
        # Clear all handlers
        logging.root.handlers = []

    def tearDown(self):
        """Restore logging handlers after each test."""
        logging.root.handlers = self.original_handlers

    def test_debug_level(self):
        """Test setup with debug level."""
        setup_logging(debug=True)
        self.assertEqual(logging.root.level, logging.DEBUG)

    def test_info_level(self):
        """Test setup with info level."""
        setup_logging(debug=False)
        self.assertEqual(logging.root.level, logging.INFO)

    def test_basic_logging_setup(self):
        """Test basic logging setup."""
        setup_logging(debug=False, use_wrapping=False)
        self.assertEqual(logging.root.level, logging.INFO)
        self.assertGreater(len(logging.root.handlers), 0)

    def test_wrapping_logging_setup(self):
        """Test wrapping logging setup."""
        setup_logging(debug=True, use_wrapping=True)
        self.assertEqual(logging.root.level, logging.DEBUG)
        self.assertGreater(len(logging.root.handlers), 0)
        # Check that handler has wrapping formatter
        handler = logging.root.handlers[0]
        self.assertIsInstance(handler.formatter, WrappingFormatter)

    def test_logging_works_after_setup(self):
        """Test that logging actually works after setup."""
        setup_logging(debug=True)
        # This should not raise an exception
        logger = logging.getLogger(__name__)
        logger.debug("Test debug message")
        logger.info("Test info message")


if __name__ == "__main__":
    unittest.main()
