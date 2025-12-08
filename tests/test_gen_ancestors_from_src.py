"""
Tests for gen_ancestors_from_src.py.
"""

# pylint: disable=W0201,C0116

import hashlib
import os
import sys
import tempfile
import unittest
from unittest.mock import MagicMock, patch, Mock
import urllib.error
from urllib.parse import urlparse

# for the OS without dist-git-client
# Mock dist_git_client before importing gen_ancestors_from_src
sys.modules["dist_git_client"] = Mock()

from python_scripts.gen_ancestors_from_src import (  # pylint: disable=C0413 wrong-import-position
    calc_checksum,
    calc_sha256_checksum,
    split_archive_filename,
    parse_name_version,
    is_url_accessible,
    get_repo_name,
)


class TestCalcChecksum(unittest.TestCase):
    """
    Unit tests for checksum calculation functions.
    """

    def test_calc_sha256_checksum(self):
        """Test SHA-256 checksum calculation."""
        with tempfile.NamedTemporaryFile(mode="w", delete=False) as f:
            f.write("test content\n")
            temp_file = f.name

        try:
            checksum = calc_sha256_checksum(temp_file)
            # Verify it's a valid SHA-256 hex string (64 characters)
            self.assertEqual(len(checksum), 64)
            self.assertTrue(all(c in "0123456789abcdef" for c in checksum))

            # Verify the actual checksum
            expected = hashlib.sha256(b"test content\n").hexdigest()
            self.assertEqual(checksum, expected)
        finally:
            os.unlink(temp_file)

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


class TestSplitArchiveFilename(unittest.TestCase):
    """
    Unit tests for split_archive_filename function.
    """

    def test_tar_gz_extension(self):
        """Test splitting .tar.gz files."""
        base, ext = split_archive_filename("package-1.0.tar.gz")
        self.assertEqual(base, "package-1.0")
        self.assertEqual(ext, ".tar.gz")

    def test_tar_bz2_extension(self):
        """Test splitting .tar.bz2 files."""
        base, ext = split_archive_filename("package-2.1.tar.bz2")
        self.assertEqual(base, "package-2.1")
        self.assertEqual(ext, ".tar.bz2")

    def test_zip_extension(self):
        """Test splitting .zip files."""
        base, ext = split_archive_filename("archive.zip")
        self.assertEqual(base, "archive")
        self.assertEqual(ext, ".zip")

    def test_no_archive_extension(self):
        """Test files without archive extensions."""
        base, ext = split_archive_filename("README.txt")
        self.assertEqual(base, "README.txt")
        self.assertIsNone(ext)

    def test_case_insensitive(self):
        """Test case-insensitive extension matching."""
        base, ext = split_archive_filename("Package-1.0.TAR.GZ")
        self.assertEqual(base, "Package-1.0")
        self.assertEqual(ext, ".TAR.GZ")


class TestParseNameVersion(unittest.TestCase):
    """
    Unit tests for parse_name_version function.
    """

    def test_simple_name_version(self):
        """Test parsing simple name-version format."""
        name, version = parse_name_version("package-1.0")
        self.assertEqual(name, "package")
        self.assertEqual(version, "1.0")

    def test_hyphenated_name(self):
        """Test parsing hyphenated package names."""
        name, version = parse_name_version("my-package-2.1.3")
        self.assertEqual(name, "my-package")
        self.assertEqual(version, "2.1.3")

    def test_no_version(self):
        """Test parsing filename without version."""
        name, version = parse_name_version("package")
        self.assertEqual(name, "package")
        self.assertIsNone(version)

    def test_complex_version(self):
        """Test parsing complex version strings."""
        name, version = parse_name_version("foo-bar-1.2.3-rc1")
        self.assertEqual(name, "foo-bar-1.2.3")
        self.assertEqual(version, "rc1")


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


class TestGetRepoName(unittest.TestCase):
    """
    Unit tests for get_repo_name function.
    """

    def test_simple_repo_name(self):
        """Test extracting repo name from simple path."""
        url = urlparse("https://example.com/namespace/myrepo.git")
        name = get_repo_name(url)
        self.assertEqual(name, "myrepo")

    def test_repo_without_git_extension(self):
        """Test extracting repo name without .git extension."""
        url = urlparse("https://example.com/namespace/myrepo")
        name = get_repo_name(url)
        self.assertEqual(name, "myrepo")

    def test_nested_namespace(self):
        """Test extracting repo name from nested namespace."""
        url = urlparse("https://example.com/group/subgroup/myrepo.git")
        name = get_repo_name(url)
        self.assertEqual(name, "myrepo")

    def test_trailing_slash(self):
        """Test handling trailing slash in URL."""
        url = urlparse("https://example.com/namespace/myrepo.git/")
        name = get_repo_name(url)
        self.assertEqual(name, "myrepo")


if __name__ == "__main__":
    unittest.main()
