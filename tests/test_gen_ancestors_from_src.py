"""
Tests for gen_ancestors_from_src.py.
"""

# pylint: disable=W0201,C0116

import json
import os
import sys
import tempfile
import unittest
from unittest.mock import Mock, patch
from urllib.parse import urlparse

# for the OS without dist-git-client
# Mock dist_git_client before importing gen_ancestors_from_src
sys.modules["dist_git_client"] = Mock()

from gen_ancestors_from_src import (  # pylint: disable=C0413  # noqa: E402
    split_archive_filename,
    parse_name_version,
    get_repo_name,
    parse_dist_git_sources,
    list_spec_sources,
    list_sources,
    load_distgit_config,
    main,
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


class TestParseDistGitSources(unittest.TestCase):
    """
    Unit tests for parse_dist_git_sources function.
    """

    def test_missing_sources_file(self):
        """Test that missing sources file returns empty dict."""
        result = parse_dist_git_sources("/nonexistent/sources", "repo", {})
        self.assertEqual(result, {})

    def test_old_format(self):
        """Test parsing old format: checksum filename."""
        with tempfile.NamedTemporaryFile(mode='w', suffix='sources', delete=False) as f:
            f.write("abc123 myfile.tar.gz\n")
            sources_file = f.name

        try:
            config = {"default_sum": "md5"}
            result = parse_dist_git_sources(sources_file, "repo", config)
            self.assertIn("myfile.tar.gz", result)
            self.assertEqual(result["myfile.tar.gz"]["alg"], "MD5")
            self.assertEqual(result["myfile.tar.gz"]["checksum"], "abc123")
            self.assertNotIn("url", result["myfile.tar.gz"])
        finally:
            os.unlink(sources_file)

    def test_old_format_default_sum_fallback(self):
        """Test old format uses md5 when default_sum is not in config."""
        with tempfile.NamedTemporaryFile(mode='w', suffix='sources', delete=False) as f:
            f.write("abc123 myfile.tar.gz\n")
            sources_file = f.name

        try:
            result = parse_dist_git_sources(sources_file, "repo", {})
            self.assertEqual(result["myfile.tar.gz"]["alg"], "MD5")
        finally:
            os.unlink(sources_file)

    def test_new_format(self):
        """Test parsing new format: HASHTYPE (filename) = checksum."""
        with tempfile.NamedTemporaryFile(mode='w', suffix='sources', delete=False) as f:
            f.write("SHA512 (myfile.tar.gz) = deadbeef123\n")
            sources_file = f.name

        try:
            result = parse_dist_git_sources(sources_file, "repo", {})
            self.assertIn("myfile.tar.gz", result)
            self.assertEqual(result["myfile.tar.gz"]["alg"], "SHA512")
            self.assertEqual(result["myfile.tar.gz"]["checksum"], "deadbeef123")
        finally:
            os.unlink(sources_file)

    def test_skips_comments_and_blanks(self):
        """Test that comments and blank lines are skipped."""
        with tempfile.NamedTemporaryFile(mode='w', suffix='sources', delete=False) as f:
            f.write("# this is a comment\n")
            f.write("\n")
            f.write("   \n")
            f.write("abc123 real-file.tar.gz\n")
            sources_file = f.name

        try:
            result = parse_dist_git_sources(sources_file, "repo", {})
            self.assertEqual(len(result), 1)
            self.assertIn("real-file.tar.gz", result)
        finally:
            os.unlink(sources_file)

    def test_unexpected_format_skipped(self):
        """Test that lines with unexpected format are skipped."""
        with tempfile.NamedTemporaryFile(mode='w', suffix='sources', delete=False) as f:
            f.write("one two three\n")  # 3 parts - unexpected
            f.write("abc123 valid.tar.gz\n")
            sources_file = f.name

        try:
            result = parse_dist_git_sources(sources_file, "repo", {})
            self.assertEqual(len(result), 1)
            self.assertIn("valid.tar.gz", result)
        finally:
            os.unlink(sources_file)

    def test_lookaside_url_construction(self):
        """Test lookaside URL is constructed when config has required keys."""
        with tempfile.NamedTemporaryFile(mode='w', suffix='sources', delete=False) as f:
            f.write("SHA512 (myfile.tar.gz) = deadbeef\n")
            sources_file = f.name

        try:
            config = {
                "lookaside_location": "https://lookaside.example.com",
                "lookaside_uri_pattern": "repo/{name}/{filename}/{hashtype}/{hash}/{filename}",
            }
            result = parse_dist_git_sources(sources_file, "myrepo", config)
            self.assertIn("url", result["myfile.tar.gz"])
            url = result["myfile.tar.gz"]["url"]
            self.assertIn("https://lookaside.example.com", url)
            self.assertIn("myrepo", url)
            self.assertIn("myfile.tar.gz", url)
            self.assertIn("sha512", url)
            self.assertIn("deadbeef", url)
        finally:
            os.unlink(sources_file)

    def test_no_lookaside_url_without_config(self):
        """Test no URL when lookaside config keys are missing."""
        with tempfile.NamedTemporaryFile(mode='w', suffix='sources', delete=False) as f:
            f.write("SHA512 (myfile.tar.gz) = deadbeef\n")
            sources_file = f.name

        try:
            result = parse_dist_git_sources(sources_file, "repo", {})
            self.assertNotIn("url", result["myfile.tar.gz"])
        finally:
            os.unlink(sources_file)

    def test_multiple_sources(self):
        """Test parsing multiple source entries."""
        with tempfile.NamedTemporaryFile(mode='w', suffix='sources', delete=False) as f:
            f.write("SHA256 (file1.tar.gz) = aaa111\n")
            f.write("SHA256 (file2.tar.xz) = bbb222\n")
            sources_file = f.name

        try:
            result = parse_dist_git_sources(sources_file, "repo", {})
            self.assertEqual(len(result), 2)
            self.assertIn("file1.tar.gz", result)
            self.assertIn("file2.tar.xz", result)
        finally:
            os.unlink(sources_file)


class TestListSpecSources(unittest.TestCase):
    """
    Unit tests for list_spec_sources function.
    """

    @patch("gen_ancestors_from_src.parse_spec_source_tags")
    @patch("gen_ancestors_from_src.calc_checksum", return_value="fakechecksum")
    def test_url_source_with_existing_file(self, _mock_checksum, mock_parse):
        """Test source with HTTP URL and existing file."""
        mock_parse.return_value = {
            "0": "https://example.com/downloads/package-1.0.tar.gz"
        }
        with tempfile.TemporaryDirectory() as tmpdir:
            # Create a dummy source file
            source_path = os.path.join(tmpdir, "package-1.0.tar.gz")
            with open(source_path, 'w', encoding="utf-8") as f:
                f.write("dummy")

            sources = list_spec_sources("fake.spec", tmpdir)

        self.assertEqual(len(sources), 1)
        src = sources[0]
        self.assertEqual(src["url"], "https://example.com/downloads/package-1.0.tar.gz")
        self.assertEqual(src["filename"], "package-1.0.tar.gz")
        self.assertEqual(src["name"], "package")
        self.assertEqual(src["version"], "1.0")
        self.assertEqual(src["alg"], "SHA256")
        self.assertEqual(src["checksum"], "fakechecksum")

    @patch("gen_ancestors_from_src.parse_spec_source_tags")
    def test_url_source_with_missing_file(self, mock_parse):
        """Test source with URL but missing file raises FileNotFoundError."""
        mock_parse.return_value = {
            "0": "https://example.com/package-1.0.tar.gz"
        }
        with tempfile.TemporaryDirectory() as tmpdir:
            with self.assertRaises(FileNotFoundError) as ctx:
                list_spec_sources("fake.spec", tmpdir)
            self.assertIn("package-1.0.tar.gz", str(ctx.exception))

    @patch("gen_ancestors_from_src.parse_spec_source_tags")
    def test_local_source_missing_file(self, mock_parse):
        """Test local source with missing file raises FileNotFoundError."""
        mock_parse.return_value = {"0": "local-patch.tar.gz"}
        with tempfile.TemporaryDirectory() as tmpdir:
            with self.assertRaises(FileNotFoundError) as ctx:
                list_spec_sources("fake.spec", tmpdir)
            self.assertIn("local-patch.tar.gz", str(ctx.exception))

    @patch("gen_ancestors_from_src.parse_spec_source_tags")
    @patch("gen_ancestors_from_src.calc_checksum", return_value="fakechecksum")
    def test_local_source_existing_file(self, _mock_checksum, mock_parse):
        """Test local source with existing file (not a URL)."""
        mock_parse.return_value = {"0": "local-patch.tar.gz"}
        with tempfile.TemporaryDirectory() as tmpdir:
            source_path = os.path.join(tmpdir, "local-patch.tar.gz")
            with open(source_path, 'w', encoding="utf-8") as f:
                f.write("dummy")

            sources = list_spec_sources("fake.spec", tmpdir)

        self.assertEqual(len(sources), 1)
        src = sources[0]
        self.assertIsNone(src["url"])
        self.assertEqual(src["filename"], "local-patch.tar.gz")
        self.assertEqual(src["checksum"], "fakechecksum")

    @patch("gen_ancestors_from_src.parse_spec_source_tags")
    @patch("gen_ancestors_from_src.calc_checksum", return_value="abc123")
    def test_url_with_fragment(self, _mock_checksum, mock_parse):
        """Test URL with #/ fragment uses the renamed filename."""
        mock_parse.return_value = {
            "0": "https://example.com/pkg-2.0.tar.gz#/renamed.tar.gz"
        }
        with tempfile.TemporaryDirectory() as tmpdir:
            source_path = os.path.join(tmpdir, "renamed.tar.gz")
            with open(source_path, 'w', encoding="utf-8") as f:
                f.write("dummy")

            sources = list_spec_sources("fake.spec", tmpdir)

        self.assertEqual(sources[0]["filename"], "renamed.tar.gz")
        self.assertEqual(sources[0]["url"], "https://example.com/pkg-2.0.tar.gz#/renamed.tar.gz")

    @patch("gen_ancestors_from_src.parse_spec_source_tags")
    @patch("gen_ancestors_from_src.calc_checksum", return_value="abc123")
    def test_url_with_fragment_github_archive(self, _mock_checksum, mock_parse):
        """Test GitHub archive URL with #/ fragment rename (real-world pattern)."""
        mock_parse.return_value = {
            "0": "https://github.com/capstone-engine/capstone/archive/5.0.7.tar.gz#/capstone-5.0.7.tar.gz"
        }
        with tempfile.TemporaryDirectory() as tmpdir:
            source_path = os.path.join(tmpdir, "capstone-5.0.7.tar.gz")
            with open(source_path, 'w', encoding="utf-8") as f:
                f.write("dummy")

            sources = list_spec_sources("fake.spec", tmpdir)

        self.assertEqual(sources[0]["filename"], "capstone-5.0.7.tar.gz")
        self.assertEqual(sources[0]["name"], "capstone")
        self.assertEqual(sources[0]["version"], "5.0.7")

    @patch("gen_ancestors_from_src.parse_spec_source_tags")
    @patch("gen_ancestors_from_src.calc_checksum", return_value="fakechecksum")
    def test_multiple_sources(self, _mock_checksum, mock_parse):
        """Test multiple source entries from spec."""
        mock_parse.return_value = {
            "0": "https://example.com/main-1.0.tar.gz",
            "1": "extra-data.txt",
        }
        with tempfile.TemporaryDirectory() as tmpdir:
            # Create dummy source files
            for name in ["main-1.0.tar.gz", "extra-data.txt"]:
                with open(os.path.join(tmpdir, name), 'w', encoding="utf-8") as f:
                    f.write("dummy")

            sources = list_spec_sources("fake.spec", tmpdir)

        self.assertEqual(len(sources), 2)

    @patch("gen_ancestors_from_src.parse_spec_source_tags")
    @patch("gen_ancestors_from_src.calc_checksum", return_value="fakechecksum")
    def test_ftp_source(self, _mock_checksum, mock_parse):
        """Test source with FTP URL."""
        mock_parse.return_value = {
            "0": "ftp://ftp.example.com/pub/package-3.0.tar.bz2"
        }
        with tempfile.TemporaryDirectory() as tmpdir:
            with open(os.path.join(tmpdir, "package-3.0.tar.bz2"), 'w', encoding="utf-8") as f:
                f.write("dummy")

            sources = list_spec_sources("fake.spec", tmpdir)

        src = sources[0]
        self.assertEqual(src["url"], "ftp://ftp.example.com/pub/package-3.0.tar.bz2")
        self.assertEqual(src["filename"], "package-3.0.tar.bz2")

    @patch("gen_ancestors_from_src.parse_spec_source_tags")
    @patch("gen_ancestors_from_src.calc_checksum", return_value="fakechecksum")
    def test_signature_files_skipped(self, _mock_checksum, mock_parse):
        """Test that .sig and .asc signature files are skipped."""
        mock_parse.return_value = {
            "0": "https://example.com/pkg-1.0.tar.gz",
            "1": "https://example.com/pkg-1.0.tar.gz.sig",
            "2": "https://example.com/pkg-1.0.tar.gz.asc",
        }
        with tempfile.TemporaryDirectory() as tmpdir:
            for name in ["pkg-1.0.tar.gz", "pkg-1.0.tar.gz.sig", "pkg-1.0.tar.gz.asc"]:
                with open(os.path.join(tmpdir, name), 'w', encoding="utf-8") as f:
                    f.write("dummy")

            sources = list_spec_sources("fake.spec", tmpdir)

        self.assertEqual(len(sources), 1)
        self.assertEqual(sources[0]["filename"], "pkg-1.0.tar.gz")

    @patch("gen_ancestors_from_src.parse_spec_source_tags")
    @patch("gen_ancestors_from_src.calc_checksum", return_value="fakechecksum")
    def test_local_sig_files_skipped(self, _mock_checksum, mock_parse):
        """Test that local .sig and .asc files are skipped."""
        mock_parse.return_value = {
            "0": "pkg-1.0.tar.gz",
            "1": "pkg-1.0.tar.gz.sig",
            "2": "pkg-1.0.tar.gz.asc",
        }
        with tempfile.TemporaryDirectory() as tmpdir:
            for name in ["pkg-1.0.tar.gz", "pkg-1.0.tar.gz.sig", "pkg-1.0.tar.gz.asc"]:
                with open(os.path.join(tmpdir, name), 'w', encoding="utf-8") as f:
                    f.write("dummy")

            sources = list_spec_sources("fake.spec", tmpdir)

        self.assertEqual(len(sources), 1)
        self.assertEqual(sources[0]["filename"], "pkg-1.0.tar.gz")

    @patch("gen_ancestors_from_src.parse_spec_source_tags")
    @patch("gen_ancestors_from_src.calc_checksum", return_value="fakechecksum")
    def test_already_expanded_flag(self, _mock_checksum, mock_parse):
        """Test that already_expanded=True passes expand=False to parse_spec_source_tags."""
        mock_parse.return_value = {"0": "https://example.com/pkg-1.0.tar.gz"}
        with tempfile.TemporaryDirectory() as tmpdir:
            with open(os.path.join(tmpdir, "pkg-1.0.tar.gz"), 'w', encoding="utf-8") as f:
                f.write("dummy")

            list_spec_sources("fake.spec", tmpdir, already_expanded=True)

        # Verify parse_spec_source_tags was called with expand=False
        mock_parse.assert_called_once_with("fake.spec", tmpdir, expand=False)

    @patch("gen_ancestors_from_src.parse_spec_source_tags")
    @patch("gen_ancestors_from_src.calc_checksum", return_value="fakechecksum")
    def test_default_behavior_enables_expansion(self, _mock_checksum, mock_parse):
        """Test that default behavior passes expand=True to parse_spec_source_tags."""
        mock_parse.return_value = {"0": "https://example.com/pkg-1.0.tar.gz"}
        with tempfile.TemporaryDirectory() as tmpdir:
            with open(os.path.join(tmpdir, "pkg-1.0.tar.gz"), 'w', encoding="utf-8") as f:
                f.write("dummy")

            list_spec_sources("fake.spec", tmpdir)

        # Verify parse_spec_source_tags was called with expand=True (default)
        mock_parse.assert_called_once_with("fake.spec", tmpdir, expand=True)


class TestListSources(unittest.TestCase):
    """
    Unit tests for list_sources function.
    """

    @patch("gen_ancestors_from_src.parse_dist_git_sources")
    @patch("gen_ancestors_from_src.list_spec_sources")
    def test_midstream_info_added(self, mock_list_spec, mock_parse_dg):
        """Test that midstream info is merged into spec sources."""
        mock_list_spec.return_value = [
            {"filename": "pkg-1.0.tar.gz", "url": "https://example.com/pkg-1.0.tar.gz",
             "name": "pkg", "version": "1.0"},
        ]
        mock_parse_dg.return_value = {
            "pkg-1.0.tar.gz": {"alg": "SHA512", "checksum": "abc123"},
        }
        config = {"sources_file": "sources"}
        sources = list_sources("fake.spec", "/srcdir", "myrepo", config)

        self.assertEqual(len(sources), 1)
        self.assertIn("midstream", sources[0])
        self.assertEqual(sources[0]["midstream"]["alg"], "SHA512")
        self.assertEqual(sources[0]["midstream"]["checksum"], "abc123")

    @patch("gen_ancestors_from_src.parse_dist_git_sources")
    @patch("gen_ancestors_from_src.list_spec_sources")
    def test_no_midstream_when_not_in_sources(self, mock_list_spec, mock_parse_dg):
        """Test that sources without midstream entry have no midstream key."""
        mock_list_spec.return_value = [
            {"filename": "other.tar.gz", "url": None, "name": "other", "version": "1.0"},
        ]
        mock_parse_dg.return_value = {
            "pkg-1.0.tar.gz": {"alg": "SHA512", "checksum": "abc123"},
        }
        config = {"sources_file": "sources"}
        sources = list_sources("fake.spec", "/srcdir", "myrepo", config)

        self.assertNotIn("midstream", sources[0])

    @patch("gen_ancestors_from_src.parse_dist_git_sources")
    @patch("gen_ancestors_from_src.list_spec_sources")
    def test_sources_file_template_formatting(self, mock_list_spec, mock_parse_dg):
        """Test that sources_file template is formatted with repo name."""
        mock_list_spec.return_value = []
        mock_parse_dg.return_value = {}
        config = {"sources_file": ".{name}.metadata"}
        list_sources("fake.spec", "/srcdir", "myrepo", config)

        # Verify parse_dist_git_sources was called with the formatted path
        call_args = mock_parse_dg.call_args
        sources_file_arg = call_args[0][0]
        self.assertEqual(sources_file_arg, "/srcdir/.myrepo.metadata")

    @patch("gen_ancestors_from_src.parse_dist_git_sources")
    @patch("gen_ancestors_from_src.list_spec_sources")
    def test_default_sources_file(self, mock_list_spec, mock_parse_dg):
        """Test default sources filename when not in config."""
        mock_list_spec.return_value = []
        mock_parse_dg.return_value = {}
        list_sources("fake.spec", "/srcdir", "myrepo", {})

        call_args = mock_parse_dg.call_args
        sources_file_arg = call_args[0][0]
        self.assertEqual(sources_file_arg, "/srcdir/sources")


class TestLoadDistgitConfig(unittest.TestCase):
    """
    Unit tests for load_distgit_config function.
    """

    @patch("gen_ancestors_from_src.get_distgit_config")
    @patch("gen_ancestors_from_src.load_dist_git_config")
    def test_restores_cwd(self, mock_load, mock_get):
        """Test that original working directory is restored."""
        mock_load.return_value = {"section": {}}
        mock_url = urlparse("https://example.com/repo.git")
        mock_get.return_value = (mock_url, {"key": "val"})

        original_cwd = os.getcwd()
        with tempfile.TemporaryDirectory() as tmpdir:
            load_distgit_config(tmpdir, "/etc/dist-git-client")

        self.assertEqual(os.getcwd(), original_cwd)

    @patch("gen_ancestors_from_src.get_distgit_config")
    @patch("gen_ancestors_from_src.load_dist_git_config")
    def test_restores_cwd_on_error(self, mock_load, _mock_get):
        """Test that original cwd is restored even on error."""
        mock_load.side_effect = RuntimeError("config error")

        original_cwd = os.getcwd()
        with tempfile.TemporaryDirectory() as tmpdir:
            with self.assertRaises(RuntimeError):
                load_distgit_config(tmpdir, "/etc/dist-git-client")

        self.assertEqual(os.getcwd(), original_cwd)

    @patch("gen_ancestors_from_src.get_distgit_config")
    @patch("gen_ancestors_from_src.load_dist_git_config")
    def test_returns_parsed_url_and_config(self, mock_load, mock_get):
        """Test return value is (parsed_url, distgit_config)."""
        mock_load.return_value = {"section": {}}
        mock_url = urlparse("https://example.com/ns/repo.git")
        expected_config = {"lookaside_location": "https://lookaside.example.com"}
        mock_get.return_value = (mock_url, expected_config)

        with tempfile.TemporaryDirectory() as tmpdir:
            parsed_url, config = load_distgit_config(tmpdir, "/etc/dist-git-client")

        self.assertEqual(parsed_url, mock_url)
        self.assertEqual(config, expected_config)

    @patch("gen_ancestors_from_src.get_distgit_config")
    @patch("gen_ancestors_from_src.load_dist_git_config")
    def test_forked_from_to_get_distgit_cfg(self, mock_load, mock_get):
        """Test that forked_from is forwarded to get_distgit_config."""
        mock_load.return_value = {"section": {}}
        mock_url = urlparse("https://src.fedoraproject.org/rpms/coreutils.git")
        mock_get.return_value = (mock_url, {})
        forked_from_url = "https://src.fedoraproject.org/rpms/coreutils.git"

        with tempfile.TemporaryDirectory() as tmpdir:
            load_distgit_config(tmpdir, "/etc/dist-git-client", forked_from=forked_from_url)

        mock_get.assert_called_once()
        _, kwargs = mock_get.call_args
        self.assertEqual(kwargs["forked_from"], forked_from_url)

    @patch("gen_ancestors_from_src.get_distgit_config")
    @patch("gen_ancestors_from_src.load_dist_git_config")
    def test_forked_from_none_by_default(self, mock_load, mock_get):
        """Test that forked_from defaults to None."""
        mock_load.return_value = {"section": {}}
        mock_url = urlparse("https://example.com/ns/repo.git")
        mock_get.return_value = (mock_url, {})

        with tempfile.TemporaryDirectory() as tmpdir:
            load_distgit_config(tmpdir, "/etc/dist-git-client")

        _, kwargs = mock_get.call_args
        self.assertIsNone(kwargs["forked_from"])


class TestMain(unittest.TestCase):
    """
    Unit tests for main function.
    """

    @patch("gen_ancestors_from_src.list_sources")
    @patch("gen_ancestors_from_src.search_specfile", return_value="/tmp/fake.spec")
    @patch("gen_ancestors_from_src.load_distgit_config")
    def test_output_to_file(self, mock_load_config, _mock_search, mock_list_sources):
        """Test main writes JSON output to file."""
        mock_url = urlparse("https://example.com/ns/myrepo.git")
        mock_load_config.return_value = (mock_url, {"sources_file": "sources"})
        mock_list_sources.return_value = [
            {"url": "https://example.com/pkg-1.0.tar.gz", "name": "pkg",
             "version": "1.0", "filename": "pkg-1.0.tar.gz",
             "alg": "SHA256", "checksum": "abc123"}
        ]

        with tempfile.TemporaryDirectory() as tmpdir:
            output_file = os.path.join(tmpdir, "output.json")
            sys.argv = ["gen_ancestors_from_src",
                         "-s", tmpdir,
                         "-o", output_file,
                         "--dist-git-config-dir", "/tmp"]
            main()

            self.assertTrue(os.path.exists(output_file))
            with open(output_file, 'r', encoding='utf-8') as f:
                result = json.load(f)
            self.assertIn("sources", result)
            self.assertEqual(len(result["sources"]), 1)
            self.assertEqual(result["sources"][0]["name"], "pkg")

    @patch("gen_ancestors_from_src.list_sources")
    @patch("gen_ancestors_from_src.search_specfile", return_value="/tmp/fake.spec")
    @patch("gen_ancestors_from_src.load_distgit_config")
    def test_output_to_stdout(self, mock_load_config, _mock_search, mock_list_sources):
        """Test main writes JSON output to stdout when no output file."""
        mock_url = urlparse("https://example.com/ns/myrepo.git")
        mock_load_config.return_value = (mock_url, {})
        mock_list_sources.return_value = []

        with tempfile.TemporaryDirectory() as tmpdir:
            sys.argv = ["gen_ancestors_from_src",
                         "-s", tmpdir,
                         "--dist-git-config-dir", "/tmp"]
            with patch("sys.stdout") as mock_stdout:
                main()
                mock_stdout.write.assert_called()

    @patch("gen_ancestors_from_src.list_sources")
    @patch("gen_ancestors_from_src.load_distgit_config")
    def test_provided_specfile(self, mock_load_config, mock_list_sources):
        """Test main uses --specfile when provided."""
        mock_url = urlparse("https://example.com/ns/myrepo.git")
        mock_load_config.return_value = (mock_url, {})
        mock_list_sources.return_value = []

        with tempfile.TemporaryDirectory() as tmpdir:
            specfile = os.path.join(tmpdir, "test.spec")
            with open(specfile, 'w', encoding='utf-8') as f:
                f.write("Name: test\n")

            sys.argv = ["gen_ancestors_from_src",
                         "-s", tmpdir,
                         "--specfile", specfile,
                         "--dist-git-config-dir", "/tmp"]
            with patch("sys.stdout"):
                main()

            # Verify list_sources was called with the provided specfile
            call_args = mock_list_sources.call_args
            self.assertEqual(call_args[0][0], os.path.abspath(specfile))

    @patch("gen_ancestors_from_src.load_distgit_config")
    def test_nonexistent_specfile_raises(self, mock_load_config):
        """Test main raises ValueError for nonexistent --specfile."""
        mock_url = urlparse("https://example.com/ns/myrepo.git")
        mock_load_config.return_value = (mock_url, {})

        with tempfile.TemporaryDirectory() as tmpdir:
            sys.argv = ["gen_ancestors_from_src",
                         "-s", tmpdir,
                         "--specfile", "/nonexistent/test.spec",
                         "--dist-git-config-dir", "/tmp"]
            with self.assertRaises(ValueError) as ctx:
                main()
            self.assertIn("does not exist", str(ctx.exception))

    def test_nonexistent_source_dir_raises(self):
        """Test main raises ValueError for nonexistent source directory."""
        sys.argv = ["gen_ancestors_from_src",
                     "-s", "/nonexistent/dir",
                     "--dist-git-config-dir", "/tmp"]
        with self.assertRaises(ValueError) as ctx:
            main()
        self.assertIn("does not exist", str(ctx.exception))

    @patch("gen_ancestors_from_src.list_sources")
    @patch("gen_ancestors_from_src.search_specfile", return_value="/tmp/fake.spec")
    @patch("gen_ancestors_from_src.load_distgit_config")
    def test_dist_git_config_env_fallback(self, mock_load_config, _mock_search, mock_list_sources):
        """Test main uses COPR_DISTGIT_CLIENT_CONFDIR env var fallback."""
        mock_url = urlparse("https://example.com/ns/myrepo.git")
        mock_load_config.return_value = (mock_url, {})
        mock_list_sources.return_value = []

        with tempfile.TemporaryDirectory() as tmpdir:
            sys.argv = ["gen_ancestors_from_src", "-s", tmpdir]
            with patch.dict(os.environ, {"COPR_DISTGIT_CLIENT_CONFDIR": "/custom/config"}):
                with patch("sys.stdout"):
                    main()

            # Verify load_distgit_config was called with the env var path
            call_args = mock_load_config.call_args
            self.assertEqual(call_args[0][1], "/custom/config")

    @patch("gen_ancestors_from_src.list_sources")
    @patch("gen_ancestors_from_src.search_specfile", return_value="/tmp/fake.spec")
    @patch("gen_ancestors_from_src.load_distgit_config")
    def test_forked_from_to_load_distgit_cfg(self, mock_load_config, _mock_search, mock_list_sources):
        """Test --forked-from CLI arg is passed to load_distgit_config."""
        mock_url = urlparse("https://src.fedoraproject.org/rpms/coreutils.git")
        mock_load_config.return_value = (mock_url, {})
        mock_list_sources.return_value = []
        forked_from_url = "https://src.fedoraproject.org/rpms/coreutils.git"

        with tempfile.TemporaryDirectory() as tmpdir:
            sys.argv = ["gen_ancestors_from_src",
                         "-s", tmpdir,
                         "--dist-git-config-dir", "/tmp",
                         "--forked-from", forked_from_url]
            with patch("sys.stdout"):
                main()

            _, kwargs = mock_load_config.call_args
            self.assertEqual(kwargs["forked_from"], forked_from_url)

    @patch("gen_ancestors_from_src.list_sources")
    @patch("gen_ancestors_from_src.search_specfile", return_value="/tmp/fake.spec")
    @patch("gen_ancestors_from_src.load_distgit_config")
    def test_forked_from_default_none(self, mock_load_config, _mock_search, mock_list_sources):
        """Test --forked-from defaults to None when not provided."""
        mock_url = urlparse("https://example.com/ns/myrepo.git")
        mock_load_config.return_value = (mock_url, {})
        mock_list_sources.return_value = []

        with tempfile.TemporaryDirectory() as tmpdir:
            sys.argv = ["gen_ancestors_from_src",
                         "-s", tmpdir,
                         "--dist-git-config-dir", "/tmp"]
            with patch("sys.stdout"):
                main()

            _, kwargs = mock_load_config.call_args
            self.assertIsNone(kwargs["forked_from"])

    @patch("gen_ancestors_from_src.list_sources")
    @patch("gen_ancestors_from_src.search_specfile", return_value="/tmp/fake.spec")
    @patch("gen_ancestors_from_src.load_distgit_config")
    def test_overwrite_existing_output(self, mock_load_config, _mock_search, mock_list_sources):
        """Test main overwrites existing output file with warning."""
        mock_url = urlparse("https://example.com/ns/myrepo.git")
        mock_load_config.return_value = (mock_url, {})
        mock_list_sources.return_value = [{"name": "new"}]

        with tempfile.TemporaryDirectory() as tmpdir:
            output_file = os.path.join(tmpdir, "output.json")
            # Create pre-existing file
            with open(output_file, 'w', encoding='utf-8') as f:
                json.dump({"sources": [{"name": "old"}]}, f)

            sys.argv = ["gen_ancestors_from_src",
                         "-s", tmpdir,
                         "-o", output_file,
                         "--dist-git-config-dir", "/tmp"]
            main()

            with open(output_file, 'r', encoding='utf-8') as f:
                result = json.load(f)
            self.assertEqual(result["sources"][0]["name"], "new")

    @patch("gen_ancestors_from_src.list_sources")
    @patch("gen_ancestors_from_src.search_specfile", return_value="/tmp/fake.spec")
    @patch("gen_ancestors_from_src.load_distgit_config")
    def test_already_expanded_flag_vs_list_sources(self, mock_load_config, _mock_search, mock_list_sources):
        """Test --already-expanded CLI flag is passed to list_sources."""
        mock_url = urlparse("https://example.com/ns/myrepo.git")
        mock_load_config.return_value = (mock_url, {})
        mock_list_sources.return_value = []

        with tempfile.TemporaryDirectory() as tmpdir:
            sys.argv = ["gen_ancestors_from_src",
                         "-s", tmpdir,
                         "--dist-git-config-dir", "/tmp",
                         "--already-expanded"]
            with patch("sys.stdout"):
                main()

            # Verify list_sources was called with already_expanded=True
            call_args = mock_list_sources.call_args
            _, kwargs = call_args
            self.assertTrue(kwargs["already_expanded"])

    @patch("gen_ancestors_from_src.list_sources")
    @patch("gen_ancestors_from_src.search_specfile", return_value="/tmp/fake.spec")
    @patch("gen_ancestors_from_src.load_distgit_config")
    def test_already_expanded_default_false(self, mock_load_config, _mock_search, mock_list_sources):
        """Test already_expanded defaults to False when flag not provided."""
        mock_url = urlparse("https://example.com/ns/myrepo.git")
        mock_load_config.return_value = (mock_url, {})
        mock_list_sources.return_value = []

        with tempfile.TemporaryDirectory() as tmpdir:
            sys.argv = ["gen_ancestors_from_src",
                         "-s", tmpdir,
                         "--dist-git-config-dir", "/tmp"]
            with patch("sys.stdout"):
                main()

            # Verify list_sources was called with already_expanded=False (default)
            call_args = mock_list_sources.call_args
            _, kwargs = call_args
            self.assertFalse(kwargs["already_expanded"])


if __name__ == "__main__":
    unittest.main()
