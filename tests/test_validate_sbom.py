"""
Tests for validate_sbom.py.
"""

# pylint: disable=W0201,C0116

import json
import os
import tempfile
import unittest
from unittest.mock import patch

from validate_sbom import (
    is_url_accessible,
    validate_source_urls,
    validate_sbom,
)


class TestIsUrlAccessible(unittest.TestCase):
    """
    Unit tests for is_url_accessible function.
    """

    def test_empty_url(self):
        """Test that empty URL returns False."""
        self.assertFalse(is_url_accessible(""))

    def test_none_url(self):
        """Test that None URL returns False."""
        self.assertFalse(is_url_accessible(None))

    @patch('urllib.request.build_opener')
    def test_successful_url(self, mock_opener):
        """Test successful URL check."""
        mock_response = unittest.mock.MagicMock()
        mock_response.status = 200
        mock_opener.return_value.open.return_value.__enter__.return_value = mock_response

        self.assertTrue(is_url_accessible("https://example.com/file.tar.gz"))

    @patch('urllib.request.build_opener')
    def test_failed_url(self, mock_opener):
        """Test failed URL check (exception raised)."""
        mock_opener.return_value.open.side_effect = Exception("Connection failed")

        self.assertFalse(is_url_accessible("https://example.com/nonexistent"))

    @patch('urllib.request.build_opener')
    def test_non_200_status(self, mock_opener):
        """Test URL returning non-200 status."""
        mock_response = unittest.mock.MagicMock()
        mock_response.status = 404
        mock_opener.return_value.open.return_value.__enter__.return_value = mock_response

        self.assertFalse(is_url_accessible("https://example.com/notfound"))


class TestValidateSourceUrls(unittest.TestCase):
    """
    Unit tests for validate_source_urls function.
    """

    def test_no_source_packages(self):
        """Test SBOM with no source packages."""
        sbom_data = {
            'packages': [
                {
                    'SPDXID': 'SPDXRef-SRPM',
                    'name': 'test-package',
                    'downloadLocation': 'NOASSERTION'
                }
            ]
        }

        results = validate_source_urls(sbom_data, url_verify=False)

        self.assertEqual(results['total_sources'], 0)
        self.assertEqual(results['sources_with_urls'], 0)

    def test_source_with_noassertion(self):
        """Test source package with NOASSERTION URL."""
        sbom_data = {
            'packages': [
                {
                    'SPDXID': 'SPDXRef-Source0',
                    'name': 'test-source',
                    'downloadLocation': 'NOASSERTION'
                }
            ]
        }

        results = validate_source_urls(sbom_data, url_verify=False)

        self.assertEqual(results['total_sources'], 1)
        self.assertEqual(results['sources_with_urls'], 0)

    def test_source_with_valid_url(self):
        """Test source package with valid URL."""
        sbom_data = {
            'packages': [
                {
                    'SPDXID': 'SPDXRef-Source0',
                    'name': 'test-source',
                    'downloadLocation': 'https://example.com/file.tar.gz'
                }
            ]
        }

        results = validate_source_urls(sbom_data, url_verify=False)

        self.assertEqual(results['total_sources'], 1)
        self.assertEqual(results['sources_with_urls'], 1)

    @patch('validate_sbom.is_url_accessible')
    def test_url_validation_success(self, mock_is_accessible):
        """Test URL validation with accessible URL."""
        mock_is_accessible.return_value = True

        sbom_data = {
            'packages': [
                {
                    'SPDXID': 'SPDXRef-Source0',
                    'name': 'test-source',
                    'downloadLocation': 'https://example.com/file.tar.gz'
                }
            ]
        }

        results = validate_source_urls(sbom_data, url_verify=True)

        self.assertEqual(results['accessible_urls'], 1)
        self.assertEqual(results['inaccessible_urls'], 0)
        self.assertEqual(len(results['failed_urls']), 0)

    @patch('validate_sbom.is_url_accessible')
    def test_url_validation_failure(self, mock_is_accessible):
        """Test URL validation with inaccessible URL."""
        mock_is_accessible.return_value = False

        sbom_data = {
            'packages': [
                {
                    'SPDXID': 'SPDXRef-Source0',
                    'name': 'test-source',
                    'downloadLocation': 'https://example.com/nonexistent.tar.gz'
                }
            ]
        }

        results = validate_source_urls(sbom_data, url_verify=True)

        self.assertEqual(results['accessible_urls'], 0)
        self.assertEqual(results['inaccessible_urls'], 1)
        self.assertEqual(len(results['failed_urls']), 1)
        self.assertEqual(results['failed_urls'][0]['spdx_id'], 'SPDXRef-Source0')

    def test_multiple_source_packages(self):
        """Test SBOM with multiple source packages."""
        sbom_data = {
            'packages': [
                {
                    'SPDXID': 'SPDXRef-Source0',
                    'name': 'test-source',
                    'downloadLocation': 'https://example.com/source0.tar.gz'
                },
                {
                    'SPDXID': 'SPDXRef-Source0-origin',
                    'name': 'test-source',
                    'downloadLocation': 'https://upstream.com/source0.tar.gz'
                },
                {
                    'SPDXID': 'SPDXRef-Source1',
                    'name': 'patch',
                    'downloadLocation': 'https://example.com/patch.tar.gz'
                }
            ]
        }

        results = validate_source_urls(sbom_data, url_verify=False)

        self.assertEqual(results['total_sources'], 3)
        self.assertEqual(results['sources_with_urls'], 3)


class TestValidateSbom(unittest.TestCase):
    """
    Unit tests for validate_sbom function.
    """

    def test_file_not_found(self):
        """Test validation with non-existent file."""
        result = validate_sbom('/nonexistent/file.json', url_verify=False)
        self.assertFalse(result)

    def test_invalid_json(self):
        """Test validation with invalid JSON file."""
        with tempfile.NamedTemporaryFile(mode='w', suffix='.json', delete=False) as f:
            f.write("{ invalid json }")
            temp_file = f.name

        try:
            result = validate_sbom(temp_file, url_verify=False)
            self.assertFalse(result)
        finally:
            os.unlink(temp_file)

    def test_missing_spdx_version(self):
        """Test validation with SBOM missing spdxVersion."""
        sbom_data = {
            'name': 'test-sbom',
            'packages': []
        }

        with tempfile.NamedTemporaryFile(mode='w', suffix='.json', delete=False) as f:
            json.dump(sbom_data, f)
            temp_file = f.name

        try:
            result = validate_sbom(temp_file, url_verify=False)
            self.assertFalse(result)
        finally:
            os.unlink(temp_file)

    @patch('validate_sbom.is_url_accessible')
    def test_valid_sbom_with_url_check(self, mock_is_accessible):
        """Test validation with valid SBOM and URL checking."""
        mock_is_accessible.return_value = True

        sbom_data = {
            'spdxVersion': 'SPDX-2.3',
            'name': 'test-sbom',
            'packages': [
                {
                    'SPDXID': 'SPDXRef-Source0',
                    'name': 'test-source',
                    'downloadLocation': 'https://example.com/file.tar.gz'
                }
            ]
        }

        with tempfile.NamedTemporaryFile(mode='w', suffix='.json', delete=False) as f:
            json.dump(sbom_data, f)
            temp_file = f.name

        try:
            result = validate_sbom(temp_file, url_verify=True)
            self.assertTrue(result)
        finally:
            os.unlink(temp_file)

    @patch('validate_sbom.is_url_accessible')
    def test_valid_sbom_with_failed_url(self, mock_is_accessible):
        """Test validation with valid SBOM but inaccessible URL."""
        mock_is_accessible.return_value = False

        sbom_data = {
            'spdxVersion': 'SPDX-2.3',
            'name': 'test-sbom',
            'packages': [
                {
                    'SPDXID': 'SPDXRef-Source0',
                    'name': 'test-source',
                    'downloadLocation': 'https://example.com/nonexistent.tar.gz'
                }
            ]
        }

        with tempfile.NamedTemporaryFile(mode='w', suffix='.json', delete=False) as f:
            json.dump(sbom_data, f)
            temp_file = f.name

        try:
            result = validate_sbom(temp_file, url_verify=True)
            self.assertFalse(result)
        finally:
            os.unlink(temp_file)


if __name__ == "__main__":
    unittest.main()
