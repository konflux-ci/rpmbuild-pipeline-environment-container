"""
Tests for sbom_utils.py.
"""

# pylint: disable=W0201,C0116

import hashlib
import os
import subprocess
import tempfile
import unittest
import urllib.error
from unittest.mock import MagicMock, patch

from rpmbuild_utils.sbom import (
    calc_checksum,
    to_spdx_license,
    get_generic_purl,
    get_rpm_purl,
    is_url_accessible,
    run_command,
)


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


class TestGetGenericPurl(unittest.TestCase):
    """
    Unit tests for get_generic_purl function.
    """

    def test_minimal_purl(self):
        """Test purl with only name."""
        purl = get_generic_purl(name="foo")
        self.assertEqual(purl, "pkg:generic/foo")

    def test_purl_with_version(self):
        """Test purl with name and version."""
        purl = get_generic_purl(name="foo", version="1.0")
        self.assertEqual(purl, "pkg:generic/foo@1.0")

    def test_purl_with_url(self):
        """Test purl with name and download URL."""
        purl = get_generic_purl(name="foo", url="https://example.com/foo.tar.gz")
        self.assertEqual(purl, "pkg:generic/foo?download_url=https://example.com/foo.tar.gz")

    def test_purl_with_version_and_url(self):
        """Test purl with name, version, and URL."""
        purl = get_generic_purl(
            name="foo",
            version="1.0",
            url="https://example.com/foo-1.0.tar.gz"
        )
        self.assertEqual(purl, "pkg:generic/foo@1.0?download_url=https://example.com/foo-1.0.tar.gz")

    def test_purl_with_checksum(self):
        """Test purl with checksum."""
        purl = get_generic_purl(
            name="foo",
            version="1.0",
            url="https://example.com/foo.tar.gz",
            checksum="abc123",
            alg="SHA256"
        )
        self.assertEqual(
            purl,
            "pkg:generic/foo@1.0?download_url=https://example.com/foo.tar.gz&checksum=sha256:abc123"
        )

    def test_purl_checksum_default_algorithm(self):
        """Test purl with checksum but no algorithm specified."""
        purl = get_generic_purl(
            name="foo",
            url="https://example.com/foo.tar.gz",
            checksum="abc123"
        )
        self.assertEqual(
            purl,
            "pkg:generic/foo?download_url=https://example.com/foo.tar.gz&checksum=sha256:abc123"
        )

    def test_purl_algorithm_lowercase(self):
        """Test that algorithm is converted to lowercase."""
        purl = get_generic_purl(
            name="foo",
            url="https://example.com/foo.tar.gz",
            checksum="abc123",
            alg="SHA512"
        )
        self.assertIn("checksum=sha512:abc123", purl)


class TestGetRpmPurl(unittest.TestCase):
    """
    Unit tests for get_rpm_purl function.
    """

    def test_minimal_rpm_purl(self):
        """Test RPM purl with minimal fields."""
        purl = get_rpm_purl(
            name="gcc",
            version="11.3.1",
            release="4.el9",
            arch="x86_64"
        )
        self.assertEqual(purl, "pkg:rpm/redhat/gcc@11.3.1-4.el9?arch=x86_64")

    def test_rpm_purl_with_epoch(self):
        """Test RPM purl with epoch."""
        purl = get_rpm_purl(
            name="systemd",
            version="252",
            release="13.el9",
            arch="aarch64",
            epoch="2"
        )
        self.assertEqual(purl, "pkg:rpm/redhat/systemd@2:252-13.el9?arch=aarch64")

    def test_rpm_purl_noarch(self):
        """Test RPM purl with noarch architecture."""
        purl = get_rpm_purl(
            name="python3-pip",
            version="21.2.3",
            release="7.el9",
            arch="noarch"
        )
        self.assertEqual(purl, "pkg:rpm/redhat/python3-pip@21.2.3-7.el9?arch=noarch")


class TestToSpdxLicense(unittest.TestCase):
    """
    Unit tests for to_spdx_license function.
    """

    @patch("rpmbuild_utils.sbom.run_command")
    def test_convert_gpl_license(self, mock_run_command):
        """Test converting GPL license."""
        mock_run_command.return_value = MagicMock(stdout="GPL-3.0-or-later\n", returncode=0)
        result = to_spdx_license("GPL-3.0-or-later")
        self.assertEqual(result, "GPL-3.0-or-later")
        mock_run_command.assert_called_once_with(
            ["license-fedora2spdx", "GPL-3.0-or-later"],
            timeout=5
        )

    @patch("rpmbuild_utils.sbom.run_command")
    def test_convert_lgpl_license(self, mock_run_command):
        """Test converting LGPL license."""
        mock_run_command.return_value = MagicMock(stdout="LGPL-2.1-or-later\n", returncode=0)
        result = to_spdx_license("LGPL-2.1-or-later")
        self.assertEqual(result, "LGPL-2.1-or-later")

    @patch("rpmbuild_utils.sbom.run_command")
    def test_empty_license(self, mock_run_command):
        """Test with empty license string."""
        result = to_spdx_license("")
        self.assertEqual(result, "NOASSERTION")
        mock_run_command.assert_not_called()

    @patch("rpmbuild_utils.sbom.run_command")
    def test_none_license(self, mock_run_command):
        """Test with None license."""
        result = to_spdx_license(None)
        self.assertEqual(result, "NOASSERTION")
        mock_run_command.assert_not_called()

    @patch("rpmbuild_utils.sbom.run_command")
    def test_conversion_failure(self, mock_run_command):
        """Test handling of conversion failure."""
        mock_run_command.side_effect = subprocess.CalledProcessError(1, "license-fedora2spdx")
        result = to_spdx_license("InvalidLicense")
        self.assertEqual(result, "NOASSERTION")

    @patch("rpmbuild_utils.sbom.run_command")
    def test_command_not_found(self, mock_run_command):
        """Test handling when license-fedora2spdx is not found."""
        mock_run_command.side_effect = FileNotFoundError("license-fedora2spdx not found")
        result = to_spdx_license("GPL-2.0")
        self.assertEqual(result, "NOASSERTION")

    @patch("rpmbuild_utils.sbom.run_command")
    def test_timeout(self, mock_run_command):
        """Test handling of command timeout."""
        mock_run_command.side_effect = subprocess.TimeoutExpired("license-fedora2spdx", 5)
        result = to_spdx_license("GPL-2.0")
        self.assertEqual(result, "NOASSERTION")

    @patch("rpmbuild_utils.sbom.run_command")
    def test_empty_output(self, mock_run_command):
        """Test handling of empty output from command."""
        mock_run_command.return_value = MagicMock(stdout="", returncode=0)
        result = to_spdx_license("UnknownLicense")
        self.assertEqual(result, "NOASSERTION")


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

        result = run_command(["echo", "test"])

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
