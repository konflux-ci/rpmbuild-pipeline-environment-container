"""
Tests for validate_sbom.py.
"""

# pylint: disable=W0201,C0116

import json
import os
import tempfile
import unittest
from unittest.mock import patch

from common_utils import calc_checksum
from validate_sbom import (
    main,
    validate_source_checksums,
    validate_source_urls,
    validate_sbom,
)


class TestValidateSourceChecksums(unittest.TestCase):
    """
    Unit tests for validate_source_checksums function.
    """

    def test_no_source_dir(self):
        """Test validation when source_dir is None."""
        sbom_data = {'packages': []}
        results = validate_source_checksums(sbom_data, None, True)

        self.assertEqual(results['no_checksum_sources'], 0)
        self.assertEqual(results['verified_checksums'], 0)

    def test_checksum_verify_disabled(self):
        """Test validation when checksum_verify is False."""
        sbom_data = {'packages': []}
        results = validate_source_checksums(sbom_data, "/tmp", False)

        self.assertEqual(results['no_checksum_sources'], 0)

    def test_source_without_checksums(self):
        """Test source package without checksums."""
        sbom_data = {
            'packages': [
                {
                    'SPDXID': 'SPDXRef-Source0',
                    'name': 'test-source',
                    'packageFileName': 'test.tar.gz'
                }
            ]
        }

        with tempfile.TemporaryDirectory() as tmpdir:
            results = validate_source_checksums(sbom_data, tmpdir, True)
            self.assertEqual(results['no_checksum_sources'], 1)
            self.assertEqual(len(results['failed_checksums']), 1)
            self.assertEqual(results['failed_checksums'][0]['reason'], 'No checksums provided')

    def test_checksum_validation_success(self):
        """Test successful checksum validation."""
        # Create a test file
        with tempfile.TemporaryDirectory() as tmpdir:
            test_file = os.path.join(tmpdir, "test.tar.gz")
            with open(test_file, 'w', encoding='utf-8') as f:
                f.write("test content")

            # Calculate actual checksum
            actual_checksum = calc_checksum(test_file, "sha256")

            sbom_data = {
                'packages': [
                    {
                        'SPDXID': 'SPDXRef-Source0',
                        'name': 'test-source',
                        'packageFileName': 'test.tar.gz',
                        'checksums': [
                            {
                                'algorithm': 'SHA256',
                                'checksumValue': actual_checksum
                            }
                        ]
                    }
                ]
            }

            results = validate_source_checksums(sbom_data, tmpdir, True)

            self.assertEqual(results['no_checksum_sources'], 0)
            self.assertEqual(results['verified_checksums'], 1)
            self.assertEqual(results['mismatched_checksums'], 0)
            self.assertEqual(len(results['failed_checksums']), 0)

    def test_checksum_validation_mismatch(self):
        """Test checksum validation with mismatch."""
        with tempfile.TemporaryDirectory() as tmpdir:
            test_file = os.path.join(tmpdir, "test.tar.gz")
            with open(test_file, 'w', encoding='utf-8') as f:
                f.write("test content")

            sbom_data = {
                'packages': [
                    {
                        'SPDXID': 'SPDXRef-Source0',
                        'name': 'test-source',
                        'packageFileName': 'test.tar.gz',
                        'checksums': [
                            {
                                'algorithm': 'SHA256',
                                'checksumValue': 'wrongchecksum123'
                            }
                        ]
                    }
                ]
            }

            results = validate_source_checksums(sbom_data, tmpdir, True)

            self.assertEqual(results['no_checksum_sources'], 0)
            self.assertEqual(results['verified_checksums'], 0)
            self.assertEqual(results['mismatched_checksums'], 1)
            self.assertEqual(len(results['failed_checksums']), 1)
            self.assertEqual(results['failed_checksums'][0]['spdx_id'], 'SPDXRef-Source0')

    def test_missing_file(self):
        """Test validation when file is missing."""
        with tempfile.TemporaryDirectory() as tmpdir:
            sbom_data = {
                'packages': [
                    {
                        'SPDXID': 'SPDXRef-Source0',
                        'name': 'test-source',
                        'packageFileName': 'nonexistent.tar.gz',
                        'checksums': [
                            {
                                'algorithm': 'SHA256',
                                'checksumValue': 'abc123'
                            }
                        ]
                    }
                ]
            }

            results = validate_source_checksums(sbom_data, tmpdir, True)

            self.assertEqual(results['no_checksum_sources'], 0)
            self.assertEqual(results['missing_files'], 1)

    def test_source_without_package_filename(self):
        """Test source package with checksums but no packageFileName."""
        with tempfile.TemporaryDirectory() as tmpdir:
            sbom_data = {
                'packages': [
                    {
                        'SPDXID': 'SPDXRef-Source0',
                        'name': 'test-source',
                        'checksums': [
                            {
                                'algorithm': 'SHA256',
                                'checksumValue': 'abc123'
                            }
                        ]
                    }
                ]
            }

            results = validate_source_checksums(sbom_data, tmpdir, True)

            self.assertEqual(results['no_package_filename_sources'], 1)
            self.assertEqual(len(results['failed_checksums']), 1)
            self.assertIn('packageFileName', results['failed_checksums'][0]['reason'])

    def test_empty_algorithm_or_checksum(self):
        """Test checksum entry with empty algorithm or checksumValue is skipped."""
        with tempfile.TemporaryDirectory() as tmpdir:
            test_file = os.path.join(tmpdir, "test.tar.gz")
            with open(test_file, 'w', encoding='utf-8') as f:
                f.write("test content")

            sbom_data = {
                'packages': [
                    {
                        'SPDXID': 'SPDXRef-Source0',
                        'name': 'test-source',
                        'packageFileName': 'test.tar.gz',
                        'checksums': [
                            {
                                'algorithm': '',
                                'checksumValue': 'abc123'
                            },
                            {
                                'algorithm': 'SHA256',
                                'checksumValue': ''
                            }
                        ]
                    }
                ]
            }

            results = validate_source_checksums(sbom_data, tmpdir, True)

            self.assertEqual(results['verified_checksums'], 0)
            self.assertEqual(results['mismatched_checksums'], 0)
            self.assertEqual(results['invalid_checksum_entries'], 2)
            self.assertEqual(len(results['failed_checksums']), 2)

    @patch('validate_sbom.calc_checksum')
    def test_checksum_calculation_exception(self, mock_calc_checksum):
        """Test exception during checksum calculation."""
        mock_calc_checksum.side_effect = Exception("hash error")

        with tempfile.TemporaryDirectory() as tmpdir:
            test_file = os.path.join(tmpdir, "test.tar.gz")
            with open(test_file, 'w', encoding='utf-8') as f:
                f.write("test content")

            sbom_data = {
                'packages': [
                    {
                        'SPDXID': 'SPDXRef-Source0',
                        'name': 'test-source',
                        'packageFileName': 'test.tar.gz',
                        'checksums': [
                            {
                                'algorithm': 'SHA256',
                                'checksumValue': 'abc123'
                            }
                        ]
                    }
                ]
            }

            results = validate_source_checksums(sbom_data, tmpdir, True)

            self.assertEqual(results['verified_checksums'], 0)
            self.assertEqual(results['mismatched_checksums'], 0)


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

    def test_checksum_validation_with_source_dir(self):
        """Test SBOM validation with checksum verification."""
        with tempfile.TemporaryDirectory() as tmpdir:
            # Create a test file
            test_file = os.path.join(tmpdir, "test.tar.gz")
            with open(test_file, 'w', encoding='utf-8') as f:
                f.write("test content")

            # Calculate checksum
            checksum = calc_checksum(test_file, "sha256")

            sbom_data = {
                'spdxVersion': 'SPDX-2.3',
                'name': 'test-sbom',
                'packages': [
                    {
                        'SPDXID': 'SPDXRef-Source0',
                        'name': 'test-source',
                        'packageFileName': 'test.tar.gz',
                        'downloadLocation': 'NOASSERTION',
                        'checksums': [
                            {
                                'algorithm': 'SHA256',
                                'checksumValue': checksum
                            }
                        ]
                    }
                ]
            }

            with tempfile.NamedTemporaryFile(mode='w', suffix='.json', delete=False) as f:
                json.dump(sbom_data, f)
                sbom_file = f.name

            try:
                result = validate_sbom(sbom_file, source_dir=tmpdir, checksum_verify=True)
                self.assertTrue(result)
            finally:
                os.unlink(sbom_file)

    def test_checksum_validation_failed(self):
        """Test SBOM validation with mismatched checksum."""
        with tempfile.TemporaryDirectory() as tmpdir:
            # Create a test file
            test_file = os.path.join(tmpdir, "test.tar.gz")
            with open(test_file, 'w', encoding='utf-8') as f:
                f.write("test content")

            sbom_data = {
                'spdxVersion': 'SPDX-2.3',
                'name': 'test-sbom',
                'packages': [
                    {
                        'SPDXID': 'SPDXRef-Source0',
                        'name': 'test-source',
                        'packageFileName': 'test.tar.gz',
                        'downloadLocation': 'NOASSERTION',
                        'checksums': [
                            {
                                'algorithm': 'SHA256',
                                'checksumValue': 'wrongchecksum123'
                            }
                        ]
                    }
                ]
            }

            with tempfile.NamedTemporaryFile(mode='w', suffix='.json', delete=False) as f:
                json.dump(sbom_data, f)
                sbom_file = f.name

            try:
                result = validate_sbom(sbom_file, source_dir=tmpdir, checksum_verify=True)
                self.assertFalse(result)
            finally:
                os.unlink(sbom_file)


    def test_valid_sbom_no_sources(self):
        """Test validation passes with warning when no source packages exist."""
        sbom_data = {
            'spdxVersion': 'SPDX-2.3',
            'name': 'test-sbom',
            'packages': [
                {
                    'SPDXID': 'SPDXRef-SRPM',
                    'name': 'test-pkg',
                    'downloadLocation': 'NOASSERTION'
                }
            ]
        }

        with tempfile.NamedTemporaryFile(mode='w', suffix='.json', delete=False) as f:
            json.dump(sbom_data, f)
            temp_file = f.name

        try:
            result = validate_sbom(temp_file, url_verify=False)
            self.assertTrue(result)
        finally:
            os.unlink(temp_file)


class TestMain(unittest.TestCase):
    """
    Unit tests for main() entry point function.
    """

    def test_main_success_exits_zero(self):
        """Test main() exits with 0 on successful validation."""
        sbom_data = {
            'spdxVersion': 'SPDX-2.3',
            'name': 'test-sbom',
            'packages': []
        }

        with tempfile.NamedTemporaryFile(mode='w', suffix='.json', delete=False) as f:
            json.dump(sbom_data, f)
            sbom_file = f.name

        try:
            with patch('sys.argv', ['validate_sbom', sbom_file, '--no-url-verify']):
                with self.assertRaises(SystemExit) as cm:
                    main()
            self.assertEqual(cm.exception.code, 0)
        finally:
            os.unlink(sbom_file)

    def test_main_failure_exits_one(self):
        """Test main() exits with 1 on validation failure."""
        sbom_data = {
            'spdxVersion': 'SPDX-2.3',
            'name': 'test-sbom',
            'packages': [
                {
                    'SPDXID': 'SPDXRef-Source0',
                    'name': 'test-source',
                    'packageFileName': 'test.tar.gz',
                    'downloadLocation': 'NOASSERTION',
                    'checksums': [
                        {
                            'algorithm': 'SHA256',
                            'checksumValue': 'wrongchecksum'
                        }
                    ]
                }
            ]
        }

        with tempfile.TemporaryDirectory() as tmpdir:
            # Create test file with different content
            test_file = os.path.join(tmpdir, 'test.tar.gz')
            with open(test_file, 'w', encoding='utf-8') as f:
                f.write("test content")

            sbom_file = os.path.join(tmpdir, 'sbom.json')
            with open(sbom_file, 'w', encoding='utf-8') as f:
                json.dump(sbom_data, f)

            with patch('sys.argv', ['validate_sbom', sbom_file,
                                    '--source-dir', tmpdir, '--no-url-verify']):
                with self.assertRaises(SystemExit) as cm:
                    main()
            self.assertEqual(cm.exception.code, 1)

    @patch('validate_sbom.is_url_accessible', return_value=True)
    def test_main_with_url_verify(self, mock_is_accessible):
        """Test main() with URL verification enabled (default)."""
        sbom_data = {
            'spdxVersion': 'SPDX-2.3',
            'name': 'test-sbom',
            'packages': [
                {
                    'SPDXID': 'SPDXRef-Source0',
                    'name': 'test-source',
                    'downloadLocation': 'https://example.com/test.tar.gz'
                }
            ]
        }

        with tempfile.NamedTemporaryFile(mode='w', suffix='.json', delete=False) as f:
            json.dump(sbom_data, f)
            sbom_file = f.name

        try:
            with patch('sys.argv', ['validate_sbom', sbom_file]):
                with self.assertRaises(SystemExit) as cm:
                    main()
            self.assertEqual(cm.exception.code, 0)
            # Verify URL check was called
            mock_is_accessible.assert_called()
        finally:
            os.unlink(sbom_file)

    def test_main_with_source_dir(self):
        """Test main() with --source-dir for checksum verification."""
        with tempfile.TemporaryDirectory() as tmpdir:
            # Create test file
            test_file = os.path.join(tmpdir, 'test.tar.gz')
            with open(test_file, 'w', encoding='utf-8') as f:
                f.write("test content")

            checksum = calc_checksum(test_file, 'sha256')

            sbom_data = {
                'spdxVersion': 'SPDX-2.3',
                'name': 'test-sbom',
                'packages': [
                    {
                        'SPDXID': 'SPDXRef-Source0',
                        'name': 'test-source',
                        'packageFileName': 'test.tar.gz',
                        'downloadLocation': 'NOASSERTION',
                        'checksums': [
                            {
                                'algorithm': 'SHA256',
                                'checksumValue': checksum
                            }
                        ]
                    }
                ]
            }

            sbom_file = os.path.join(tmpdir, 'sbom.json')
            with open(sbom_file, 'w', encoding='utf-8') as f:
                json.dump(sbom_data, f)

            with patch('sys.argv', ['validate_sbom', sbom_file,
                                    '--source-dir', tmpdir, '--no-url-verify']):
                with self.assertRaises(SystemExit) as cm:
                    main()
            self.assertEqual(cm.exception.code, 0)

    def test_main_no_checksum_verify_flag(self):
        """Test main() with --no-checksum-verify flag."""
        sbom_data = {
            'spdxVersion': 'SPDX-2.3',
            'name': 'test-sbom',
            'packages': [
                {
                    'SPDXID': 'SPDXRef-Source0',
                    'name': 'test-source',
                    'packageFileName': 'test.tar.gz',
                    'downloadLocation': 'NOASSERTION',
                    'checksums': [
                        {
                            'algorithm': 'SHA256',
                            'checksumValue': 'anychecksum'
                        }
                    ]
                }
            ]
        }

        with tempfile.TemporaryDirectory() as tmpdir:
            sbom_file = os.path.join(tmpdir, 'sbom.json')
            with open(sbom_file, 'w', encoding='utf-8') as f:
                json.dump(sbom_data, f)

            # Should pass even without source-dir when checksums disabled
            with patch('sys.argv', ['validate_sbom', sbom_file,
                                    '--no-url-verify', '--no-checksum-verify']):
                with self.assertRaises(SystemExit) as cm:
                    main()
            self.assertEqual(cm.exception.code, 0)

    def test_main_debug_flag(self):
        """Test main() with --debug flag enables debug logging."""
        sbom_data = {
            'spdxVersion': 'SPDX-2.3',
            'name': 'test-sbom',
            'packages': []
        }

        with tempfile.NamedTemporaryFile(mode='w', suffix='.json', delete=False) as f:
            json.dump(sbom_data, f)
            sbom_file = f.name

        try:
            with patch('sys.argv', ['validate_sbom', sbom_file,
                                    '--no-url-verify', '--debug']):
                with self.assertRaises(SystemExit) as cm:
                    main()
            self.assertEqual(cm.exception.code, 0)
        finally:
            os.unlink(sbom_file)

    def test_main_checksum_verify_wo_source_dir(self):
        """Test main() warns when checksum verify enabled but no source-dir."""
        sbom_data = {
            'spdxVersion': 'SPDX-2.3',
            'name': 'test-sbom',
            'packages': []
        }

        with tempfile.NamedTemporaryFile(mode='w', suffix='.json', delete=False) as f:
            json.dump(sbom_data, f)
            sbom_file = f.name

        try:
            # No --no-checksum-verify and no --source-dir should trigger warning
            with patch('sys.argv', ['validate_sbom', sbom_file, '--no-url-verify']):
                with self.assertRaises(SystemExit) as cm:
                    main()
            self.assertEqual(cm.exception.code, 0)
        finally:
            os.unlink(sbom_file)


if __name__ == "__main__":
    unittest.main()
