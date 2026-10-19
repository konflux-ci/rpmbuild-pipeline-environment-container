"""
Tests for SBOM utility functions in sbom_utils.py.
"""

# pylint: disable=W0201,C0116

import subprocess
import unittest
from unittest.mock import MagicMock, patch

import sbom_utils
from sbom_utils import (
    get_generic_purl,
    get_rpm_purl,
    to_spdx_license,
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
        self.assertEqual(purl, "pkg:rpm/fedora/gcc@11.3.1-4.el9?arch=x86_64")

    def test_rpm_purl_with_epoch(self):
        """Test RPM purl with epoch."""
        purl = get_rpm_purl(
            name="systemd",
            version="252",
            release="13.el9",
            arch="aarch64",
            epoch="2"
        )
        self.assertEqual(purl, "pkg:rpm/fedora/systemd@252-13.el9?arch=aarch64&epoch=2")

    def test_rpm_purl_noarch(self):
        """Test RPM purl with noarch architecture."""
        purl = get_rpm_purl(
            name="python3-pip",
            version="21.2.3",
            release="7.el9",
            arch="noarch"
        )
        self.assertEqual(purl, "pkg:rpm/fedora/python3-pip@21.2.3-7.el9?arch=noarch")


class LicenseTestCase(unittest.TestCase):
    """Base class for license tests that manages cache state."""

    def setUp(self):
        sbom_utils.reset_license_caches()

    def tearDown(self):
        sbom_utils.reset_license_caches()


class TestToSpdxLicense(LicenseTestCase):
    """
    Unit tests for to_spdx_license function.
    """

    @patch("sbom_utils.run_command")
    def test_valid_spdx_license_returned_directly(self, mock_run_command):
        """Test that a valid SPDX license is returned without conversion."""
        mock_run_command.return_value = MagicMock(returncode=0)
        result = to_spdx_license("GPL-3.0-or-later")
        self.assertEqual(result, "GPL-3.0-or-later")
        mock_run_command.assert_called_once_with(
            ["license-validate", "GPL-3.0-or-later"],
            timeout=15
        )

    @patch("sbom_utils.run_command")
    def test_convert_gpl_license(self, mock_run_command):
        """Test converting non-SPDX license via license-fedora2spdx."""
        mock_run_command.side_effect = [
            subprocess.CalledProcessError(1, ["license-validate", "GPLv3+"]),
            MagicMock(stdout="GPL-3.0-or-later\n", returncode=0),
        ]
        result = to_spdx_license("GPLv3+")
        self.assertEqual(result, "GPL-3.0-or-later")
        self.assertEqual(mock_run_command.call_count, 2)

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
        """Test handling when license-validate is not found."""
        mock_run_command.side_effect = FileNotFoundError("license-validate not found")
        result = to_spdx_license("GPL-2.0")
        self.assertEqual(result, "NOASSERTION")
        # Should not attempt fedora2spdx conversion when validator is unavailable
        self.assertEqual(mock_run_command.call_count, 1)

    @patch("sbom_utils.run_command")
    def test_timeout(self, mock_run_command):
        """Test handling of command timeout."""
        mock_run_command.side_effect = subprocess.TimeoutExpired("license-validate", 15)
        result = to_spdx_license("GPL-2.0")
        self.assertEqual(result, "NOASSERTION")
        # Should not attempt fedora2spdx conversion when validator times out
        self.assertEqual(mock_run_command.call_count, 1)

    @patch("sbom_utils.run_command")
    def test_empty_output(self, mock_run_command):
        """Test handling of empty output from license-fedora2spdx."""
        mock_run_command.side_effect = [
            subprocess.CalledProcessError(1, ["license-validate", "UnknownLicense"]),
            MagicMock(stdout="", returncode=0),
        ]
        result = to_spdx_license("UnknownLicense")
        self.assertEqual(result, "NOASSERTION")

    @patch("sbom_utils.run_command")
    def test_multiline_output_returns_first_line(self, mock_run_command):
        """Test that only the first line of output is used."""
        mock_run_command.side_effect = [
            subprocess.CalledProcessError(1, ["license-validate", "GPLv3+"]),
            MagicMock(stdout="GPL-3.0-or-later\nsome extra output\n", returncode=0),
        ]
        result = to_spdx_license("GPLv3+")
        self.assertEqual(result, "GPL-3.0-or-later")

    @patch("sbom_utils.run_command")
    def test_blank_first_line_returns_noassertion(self, mock_run_command):
        """Test that a blank first line results in NOASSERTION."""
        mock_run_command.side_effect = [
            subprocess.CalledProcessError(1, ["license-validate", "SomeLicense"]),
            MagicMock(stdout="  \nactual license\n", returncode=0),
        ]
        result = to_spdx_license("SomeLicense")
        self.assertEqual(result, "NOASSERTION")

    @patch("sbom_utils.run_command")
    def test_invalid_license_validated_once(self, mock_run_command):
        """Test that caching works: invalid license validated only once."""
        mock_run_command.side_effect = [
            subprocess.CalledProcessError(1, ["license-validate", "GPLv3+"]),
            MagicMock(stdout="GPL-3.0-or-later\n", returncode=0),
        ]
        # Call twice with the same license
        result1 = to_spdx_license("GPLv3+")
        result2 = to_spdx_license("GPLv3+")
        self.assertEqual(result1, "GPL-3.0-or-later")
        self.assertEqual(result2, "GPL-3.0-or-later")
        # Should only call run_command twice total (once validate, once convert), not four
        self.assertEqual(mock_run_command.call_count, 2)

    @patch("sbom_utils.run_command")
    def test_failed_conversion_cached(self, mock_run_command):
        """Test that failed conversions are cached."""
        mock_run_command.side_effect = [
            subprocess.CalledProcessError(1, ["license-validate", "Bogus"]),
            subprocess.CalledProcessError(1, ["license-fedora2spdx", "Bogus"]),
        ]
        # Call twice with the same invalid license
        result1 = to_spdx_license("Bogus")
        result2 = to_spdx_license("Bogus")
        self.assertEqual(result1, "NOASSERTION")
        self.assertEqual(result2, "NOASSERTION")
        # Should only call run_command twice total, not four
        self.assertEqual(mock_run_command.call_count, 2)

    @patch("sbom_utils.run_command")
    def test_fedora2spdx_reached(self, mock_run_command):
        """Test that license-fedora2spdx is actually called for invalid licenses."""
        mock_run_command.side_effect = [
            subprocess.CalledProcessError(1, ["license-validate", "GPLv3+"]),
            MagicMock(stdout="GPL-3.0-or-later\n", returncode=0),
        ]
        result = to_spdx_license("GPLv3+")
        self.assertEqual(result, "GPL-3.0-or-later")
        # Verify the second call was to license-fedora2spdx
        self.assertEqual(mock_run_command.call_args_list[1][0][0],
                         ["license-fedora2spdx", "GPLv3+"])

    @patch("sbom_utils.run_command")
    def test_usage_error_is_not_invalid(self, mock_run_command):
        """Test that usage errors (exit 2) don't trigger conversion."""
        mock_run_command.side_effect = subprocess.CalledProcessError(
            2, ["license-validate", "GPL-2.0"])
        result = to_spdx_license("GPL-2.0")
        self.assertEqual(result, "NOASSERTION")
        # Should not attempt fedora2spdx conversion
        self.assertEqual(mock_run_command.call_count, 1)

    @patch("sbom_utils.run_command")
    def test_multiline_output_logs_notes(self, mock_run_command):
        """Test that multiline output from fedora2spdx logs important notes."""
        mock_run_command.side_effect = [
            subprocess.CalledProcessError(1, ["license-validate", "GPLv3+"]),
            MagicMock(stdout="GPL-3.0-or-later\nNote: some important info\n", returncode=0),
        ]
        with self.assertLogs(level='WARNING') as cm:
            result = to_spdx_license("GPLv3+")
        self.assertEqual(result, "GPL-3.0-or-later")
        # Check that the warning about important notes was logged
        self.assertTrue(any("important" in msg for msg in cm.output))
        self.assertTrue(any("some important info" in msg for msg in cm.output))

    @patch("sbom_utils.run_command")
    def test_warning_logged_once(self, mock_run_command):
        """Test that warnings are logged only once per distinct license."""
        mock_run_command.side_effect = [
            subprocess.CalledProcessError(1, ["license-validate", "BadLicense"]),
            subprocess.CalledProcessError(1, ["license-fedora2spdx", "BadLicense"]),
        ]
        with self.assertLogs(level='WARNING') as cm:
            to_spdx_license("BadLicense")
            to_spdx_license("BadLicense")  # Second call
        critical_count = sum(1 for msg in cm.output if "failed" in msg)
        # Should only be logged once due to caching
        self.assertEqual(critical_count, 1)


if __name__ == "__main__":
    unittest.main()
