"""
Tests for SBOM utility functions in sbom_utils.py.
"""

# pylint: disable=W0201,C0116

import subprocess
import unittest
from unittest.mock import MagicMock, patch

from sbom_utils import (
    to_spdx_license,
    get_generic_purl,
    get_rpm_purl,
)


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

    @patch("sbom_utils.run_command")
    def test_convert_gpl_license(self, mock_run_command):
        """Test converting GPL license."""
        mock_run_command.return_value = MagicMock(stdout="GPL-3.0-or-later\n", returncode=0)
        result = to_spdx_license("GPL-3.0-or-later")
        self.assertEqual(result, "GPL-3.0-or-later")
        mock_run_command.assert_called_once_with(
            ["license-fedora2spdx", "GPL-3.0-or-later"],
            timeout=5
        )

    @patch("sbom_utils.run_command")
    def test_convert_lgpl_license(self, mock_run_command):
        """Test converting LGPL license."""
        mock_run_command.return_value = MagicMock(stdout="LGPL-2.1-or-later\n", returncode=0)
        result = to_spdx_license("LGPL-2.1-or-later")
        self.assertEqual(result, "LGPL-2.1-or-later")

    @patch("sbom_utils.run_command")
    def test_empty_license(self, mock_run_command):
        """Test with empty license string."""
        result = to_spdx_license("")
        self.assertEqual(result, "NOASSERTION")
        mock_run_command.assert_not_called()

    @patch("sbom_utils.run_command")
    def test_none_license(self, mock_run_command):
        """Test with None license."""
        result = to_spdx_license(None)
        self.assertEqual(result, "NOASSERTION")
        mock_run_command.assert_not_called()

    @patch("sbom_utils.run_command")
    def test_conversion_failure(self, mock_run_command):
        """Test handling of conversion failure."""
        mock_run_command.side_effect = subprocess.CalledProcessError(1, "license-fedora2spdx")
        result = to_spdx_license("InvalidLicense")
        self.assertEqual(result, "NOASSERTION")

    @patch("sbom_utils.run_command")
    def test_command_not_found(self, mock_run_command):
        """Test handling when license-fedora2spdx is not found."""
        mock_run_command.side_effect = FileNotFoundError("license-fedora2spdx not found")
        result = to_spdx_license("GPL-2.0")
        self.assertEqual(result, "NOASSERTION")

    @patch("sbom_utils.run_command")
    def test_timeout(self, mock_run_command):
        """Test handling of command timeout."""
        mock_run_command.side_effect = subprocess.TimeoutExpired("license-fedora2spdx", 5)
        result = to_spdx_license("GPL-2.0")
        self.assertEqual(result, "NOASSERTION")

    @patch("sbom_utils.run_command")
    def test_empty_output(self, mock_run_command):
        """Test handling of empty output from command."""
        mock_run_command.return_value = MagicMock(stdout="", returncode=0)
        result = to_spdx_license("UnknownLicense")
        self.assertEqual(result, "NOASSERTION")

    @patch("sbom_utils.run_command")
    def test_multiline_output_returns_first_line(self, mock_run_command):
        """Test that only the first line of output is used."""
        mock_run_command.return_value = MagicMock(
            stdout="GPL-3.0-or-later\nsome extra output\n", returncode=0)
        result = to_spdx_license("GPLv3+")
        self.assertEqual(result, "GPL-3.0-or-later")

    @patch("sbom_utils.run_command")
    def test_blank_first_line_returns_noassertion(self, mock_run_command):
        """Test that a blank first line results in NOASSERTION."""
        mock_run_command.return_value = MagicMock(
            stdout="  \nactual license\n", returncode=0)
        result = to_spdx_license("SomeLicense")
        self.assertEqual(result, "NOASSERTION")


if __name__ == "__main__":
    unittest.main()
