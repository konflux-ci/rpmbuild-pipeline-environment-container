"""
Tests merge_syft_sbom.py.
"""

# pylint: disable=W0201,C0116

import json
import os
import sys
import tempfile
import unittest

from merge_syft_sbom import (
    _main as merge_syft_sbom,
    get_generic_purl,
    attach_sources,
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


class TestAttachSources(unittest.TestCase):
    """
    Unit tests for attach_sources function.
    """

    def test_attach_sources_with_midstream(self):
        """Test attaching sources with midstream data."""
        sbom_root = {
            "packages": [],
            "relationships": []
        }

        source_data = {
            "sources": [
                {
                    "name": "foo",
                    "version": "1.0",
                    "filename": "foo-1.0.tar.gz",
                    "url": "https://upstream.com/foo-1.0.tar.gz",
                    "alg": "SHA256",
                    "checksum": "abc123",
                    "midstream": {
                        "url": "https://lookaside.com/foo-1.0.tar.gz",
                        "alg": "MD5",
                        "checksum": "def456"
                    }
                }
            ]
        }

        with tempfile.NamedTemporaryFile(mode='w', delete=False, suffix='.json') as f:
            json.dump(source_data, f)
            temp_file = f.name

        try:
            attach_sources(sbom_root, temp_file)

            # Should have 2 packages: source and origin
            self.assertEqual(len(sbom_root['packages']), 2)

            # Check main source package
            source_pkg = sbom_root['packages'][0]
            self.assertEqual(source_pkg['SPDXID'], 'SPDXRef-Source0')
            self.assertEqual(source_pkg['name'], 'foo')
            self.assertEqual(source_pkg['versionInfo'], '1.0')
            self.assertEqual(source_pkg['packageFileName'], 'foo-1.0.tar.gz')
            self.assertEqual(source_pkg['downloadLocation'], 'https://lookaside.com/foo-1.0.tar.gz')
            self.assertEqual(len(source_pkg['checksums']), 1)
            self.assertEqual(source_pkg['checksums'][0]['algorithm'], 'SHA256')
            self.assertEqual(source_pkg['checksums'][0]['checksumValue'], 'abc123')

            # Check origin package
            origin_pkg = sbom_root['packages'][1]
            self.assertEqual(origin_pkg['SPDXID'], 'SPDXRef-Source0-origin')
            self.assertEqual(origin_pkg['downloadLocation'], 'https://upstream.com/foo-1.0.tar.gz')

            # Check relationships
            self.assertEqual(len(sbom_root['relationships']), 2)
            # SRPM CONTAINS Source0
            self.assertEqual(sbom_root['relationships'][0]['spdxElementId'], 'SPDXRef-SRPM')
            self.assertEqual(sbom_root['relationships'][0]['relationshipType'], 'CONTAINS')
            self.assertEqual(sbom_root['relationships'][0]['relatedSpdxElement'], 'SPDXRef-Source0')
            # Source0 GENERATED_FROM Source0-origin
            self.assertEqual(sbom_root['relationships'][1]['spdxElementId'], 'SPDXRef-Source0')
            self.assertEqual(sbom_root['relationships'][1]['relationshipType'], 'GENERATED_FROM')
            self.assertEqual(sbom_root['relationships'][1]['relatedSpdxElement'], 'SPDXRef-Source0-origin')
        finally:
            os.unlink(temp_file)

    def test_attach_sources_without_midstream(self):
        """Test attaching sources without midstream data."""
        sbom_root = {
            "packages": [],
            "relationships": []
        }

        source_data = {
            "sources": [
                {
                    "name": "bar",
                    "version": "2.0",
                    "filename": "bar-2.0.tar.gz",
                    "url": "https://upstream.com/bar-2.0.tar.gz",
                    "alg": "SHA256",
                    "checksum": "xyz789"
                }
            ]
        }

        with tempfile.NamedTemporaryFile(mode='w', delete=False, suffix='.json') as f:
            json.dump(source_data, f)
            temp_file = f.name

        try:
            attach_sources(sbom_root, temp_file)

            # Should have 2 packages: source and origin (both point to upstream)
            self.assertEqual(len(sbom_root['packages']), 2)

            # Check main source package uses NOASSERTION for download location
            source_pkg = sbom_root['packages'][0]
            self.assertEqual(source_pkg['SPDXID'], 'SPDXRef-Source0')
            self.assertEqual(source_pkg['downloadLocation'], 'NOASSERTION')

            # Check origin package
            origin_pkg = sbom_root['packages'][1]
            self.assertEqual(origin_pkg['SPDXID'], 'SPDXRef-Source0-origin')
            self.assertEqual(origin_pkg['downloadLocation'], 'https://upstream.com/bar-2.0.tar.gz')

            # Should have 2 relationships
            self.assertEqual(len(sbom_root['relationships']), 2)
        finally:
            os.unlink(temp_file)

    def test_attach_multiple_sources(self):
        """Test attaching multiple sources."""
        sbom_root = {
            "packages": [],
            "relationships": []
        }

        source_data = {
            "sources": [
                {
                    "name": "foo",
                    "version": "1.0",
                    "filename": "foo-1.0.tar.gz",
                    "url": "https://example.com/foo-1.0.tar.gz",
                    "alg": "SHA256",
                    "checksum": "abc123",
                    "midstream": {
                        "url": "https://lookaside.com/foo-1.0.tar.gz",
                        "alg": "MD5",
                        "checksum": "def456"
                    }
                },
                {
                    "name": "bar",
                    "version": "2.0",
                    "filename": "bar-2.0.tar.gz",
                    "url": "https://example.com/bar-2.0.tar.gz",
                    "alg": "SHA256",
                    "checksum": "xyz789"
                }
            ]
        }

        with tempfile.NamedTemporaryFile(mode='w', delete=False, suffix='.json') as f:
            json.dump(source_data, f)
            temp_file = f.name

        try:
            attach_sources(sbom_root, temp_file)

            # Should have 4 packages: 2 sources + 2 origins
            self.assertEqual(len(sbom_root['packages']), 4)

            # Check SPDXIDs
            spdx_ids = [pkg['SPDXID'] for pkg in sbom_root['packages']]
            self.assertIn('SPDXRef-Source0', spdx_ids)
            self.assertIn('SPDXRef-Source0-origin', spdx_ids)
            self.assertIn('SPDXRef-Source1', spdx_ids)
            self.assertIn('SPDXRef-Source1-origin', spdx_ids)

            # Should have 4 relationships
            self.assertEqual(len(sbom_root['relationships']), 4)
        finally:
            os.unlink(temp_file)

    def test_attach_sources_unknown_version(self):
        """Test that missing version defaults to 'unknown'."""
        sbom_root = {
            "packages": [],
            "relationships": []
        }

        source_data = {
            "sources": [
                {
                    "name": "foo",
                    "filename": "foo.tar.gz",
                    "url": "https://example.com/foo.tar.gz",
                    "alg": "SHA256",
                    "checksum": "abc123"
                }
            ]
        }

        with tempfile.NamedTemporaryFile(mode='w', delete=False, suffix='.json') as f:
            json.dump(source_data, f)
            temp_file = f.name

        try:
            attach_sources(sbom_root, temp_file)

            source_pkg = sbom_root['packages'][0]
            self.assertEqual(source_pkg['versionInfo'], 'unknown')

            origin_pkg = sbom_root['packages'][1]
            self.assertEqual(origin_pkg['versionInfo'], 'unknown')
        finally:
            os.unlink(temp_file)


class TestMergeSyftSbom(unittest.TestCase):
    """
    Unit tests for python_scripts/merge_syft_sbom.py.
    """
    def setUp(self):
        self.maxDiff = None

    def test_valid(self):
        """
        Unit test for valid case of merge_syft_sbom python script.
        """
        testdir = os.path.realpath(__file__)
        testdir = os.path.dirname(testdir)
        sbom_spdx = os.path.join(testdir, "sbom_sources", 'sbom-spdx.json')
        syft_sbom = os.path.join(testdir, "sbom_sources", 'syft_sbom.json')
        sbom_merged = os.path.join(testdir, 'sbom_merged.json')
        sys.argv = ["this", "--sbom-spdx", sbom_spdx, '--syft-sbom', syft_sbom, '--sbom-merged', sbom_merged]
        merge_syft_sbom()
        with open(sbom_merged, "r", encoding="utf-8") as rfd:
            results = json.load(rfd)
        assert results == {
            "spdxVersion": "SPDX-2.3",
            "dataLicense": "CC0-1.0",
            "SPDXID": "SPDXRef-DOCUMENT",
            "creationInfo": {"created": "2025-09-20T21:50:00.325906",
                             "creators": ["Tool: Konflux"]},
            "name": "test-pkg-1.1.1-1.el9",
            "documentNamespace": "TODO",
            "packages": [{"SPDXID": "SPDXRef-noarch-test-pkg",
                          "name": "test-pkg",
                          "versionInfo": "1.1.1-1.el9",
                          "supplier": "Organization: Red Hat",
                          "downloadLocation": "NOASSERTION",
                          "packageFileName": "test-pkg-1.1.1-1.el9.src.rpm",
                          "builtDate": "2025-09-23",
                          "licenseConcluded": "LGPL-2.1-only AND GPL-2.0-or-later",
                          "externalRefs": [{"referenceCategory": "PACKAGE-MANAGER",
                                            "referenceType": "purl",
                                            "referenceLocator": "pkg:rpm/redhat/test-pkg@1.1.1-1.el9?arch=noarch"}],
                          "checksums": [{"algorithm": "SHA256",
                                         "checksumValue": "186deeb746c0802fae513f3429cc9f600b08702b1d188fd597c"}]},
                         {"SPDXID": "SPDXRef-noarch-test-pkg",
                          "name": "test-pkg",
                          "versionInfo": "1.1.1-1.el8",
                          "supplier": "Organization: Red Hat",
                          "downloadLocation": "NOASSERTION",
                          "packageFileName": "test-pkg-1.1.1-1.el8.src.rpm",
                          "builtDate": "2025-09-23",
                          "licenseConcluded": "LGPL-2.1-only AND GPL-2.0-or-later",
                          "externalRefs": [{"referenceCategory": "PACKAGE-MANAGER",
                                            "referenceType": "purl",
                                            "referenceLocator": "pkg:rpm/redhat/test-pkg@1.1.1-1.el8?arch=noarch"}],
                          "checksums": [{"algorithm": "SHA256",
                                         "checksumValue": "186deeb746c0802fae513f3429cc9f600b08702b1d188fd597c"}]}],
            "files": [],
            "relationships": [{"spdxElementId": "SPDXRef-DOCUMENT",
                               "relationshipType": "DESCRIBES",
                               "relatedSpdxElement": "SPDXRef-SRPM"},
                              {"spdxElementId": "SPDXRef-noarch-test-pkg",
                               "relationshipType": "GENERATED_FROM",
                               "relatedSpdxElement": "SPDXRef-SRPM"},
                              {"spdxElementId": "SPDXRef-Source0",
                               "relationshipType": "CONTAINS",
                               "relatedSpdxElement": "SPDXRef-SRPM"},
                              {"spdxElementId": "SPDXRef-noarch-test-pkg",
                               "relationshipType": "GENERATED_FROM",
                               "relatedSpdxElement": "SPDXRef-SRPM"}
                              ],
            "documentDescribes": ["SPDXRef-noarch-test-pkg"]
        }


if __name__ == "__main__":
    unittest.main()
