"""
Tests for gen_ancestors_from_src.py.
"""

# pylint: disable=W0201,C0116

import sys
import unittest
from unittest.mock import Mock
from urllib.parse import urlparse

# for the OS without dist-git-client
# Mock dist_git_client before importing gen_ancestors_from_src
sys.modules["dist_git_client"] = Mock()

from rpmbuild_utils.cli.gen_ancestors_from_src import (  # pylint: disable=C0413  # noqa: E402
    split_archive_filename,
    parse_name_version,
    get_repo_name,
)


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
