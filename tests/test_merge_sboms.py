"""
Tests merge_sboms.py.
"""

# pylint: disable=W0201,C0116

import json
import os
import sys
import tempfile
import unittest
from unittest.mock import patch

from merge_sboms import (
    _main as merge_sboms,
    CONFIG,
    init_config,
    create_base_sbom,
    attach_sources,
    attach_buildroot_packages,
    attach_syft_sboms,
    _find_rpm_packages,
    _rename_doc_root_id,
    DEFAULT_SBOM_CREATORS,
    DEFAULT_ANNOTATOR,
    DEFAULT_DOCUMENT_NAMESPACE,
    DEFAULT_SUPPLIER,
)


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


class TestAttachBuildrootPackages(unittest.TestCase):
    """
    Unit tests for attach_buildroot_packages function.
    """

    @patch("merge_sboms.to_spdx_license")
    def test_attach_single_lockfile(self, mock_convert_license):
        """Test attaching buildroot packages from single lockfile."""
        # Mock license conversion to return SPDX format
        mock_convert_license.side_effect = lambda x: x if x else "NOASSERTION"

        sbom_root = {
            "name": "test-pkg-1.1.1-1.el9",
            "packages": [],
            "relationships": []
        }

        lockfile_data = {
            "config": {
                "target_arch": "x86_64"
            },
            "buildroot": {
                "rpms": [
                    {
                        "name": "gcc",
                        "version": "11.3.1",
                        "release": "4.el9",
                        "arch": "x86_64",
                        "epoch": None,
                        "license": "GPL-3.0-or-later",
                        "url": "https://example.com/gcc-11.3.1-4.el9.x86_64.rpm",
                        "sigmd5": "abc123def456"
                    },
                    {
                        "name": "glibc",
                        "version": "2.34",
                        "release": "60.el9",
                        "arch": "x86_64",
                        "epoch": None,
                        "license": "LGPL-2.1-or-later",
                        "url": "https://example.com/glibc-2.34-60.el9.x86_64.rpm",
                        "sigmd5": "def456ghi789"
                    }
                ]
            }
        }

        with tempfile.NamedTemporaryFile(mode='w', delete=False, suffix='.json') as f:
            json.dump(lockfile_data, f)
            lockfile_path = f.name

        # Create buildroot arch list JSON
        broot_arch_list_data = {
            "x86_64": {
                "filelist": ["gcc-11.3.1-4.el9.x86_64.rpm", "glibc-2.34-60.el9.x86_64.rpm"],
                "lockfile": lockfile_path
            }
        }

        with tempfile.NamedTemporaryFile(mode='w', delete=False, suffix='.json') as f:
            json.dump(broot_arch_list_data, f)
            broot_arch_list_file = f.name

        try:
            attach_buildroot_packages(sbom_root, broot_arch_list_file, "test-pkg")

            # Should have 3 packages: 1 virtual + 2 buildroot
            self.assertEqual(len(sbom_root['packages']), 3)

            # Check virtual buildroot package
            virtual_pkg = sbom_root['packages'][0]
            self.assertEqual(virtual_pkg['SPDXID'], 'SPDXRef-Buildroot-test-pkg-x86_64')
            self.assertEqual(virtual_pkg['name'], 'test-pkg-buildroot-x86_64')
            self.assertEqual(virtual_pkg['downloadLocation'], 'NOASSERTION')
            self.assertEqual(virtual_pkg['filesAnalyzed'], False)

            # Check first buildroot package
            gcc_pkg = sbom_root['packages'][1]
            self.assertEqual(gcc_pkg['SPDXID'], 'SPDXRef-Buildroot-Package-gcc-x86_64')
            self.assertEqual(gcc_pkg['name'], 'gcc')
            self.assertEqual(gcc_pkg['versionInfo'], '11.3.1-4.el9')
            self.assertEqual(gcc_pkg['licenseDeclared'], 'GPL-3.0-or-later')
            self.assertEqual(gcc_pkg['supplier'], 'Organization: Fedora')

            # Check annotations (sigmd5 is stored as annotation)
            self.assertEqual(len(gcc_pkg['annotations']), 1)
            self.assertEqual(gcc_pkg['annotations'][0]['annotationType'], 'OTHER')
            self.assertIn('sigmd5: abc123def456', gcc_pkg['annotations'][0]['comment'])

            # Check purl
            self.assertEqual(len(gcc_pkg['externalRefs']), 1)
            self.assertIn('pkg:rpm/fedora/gcc@11.3.1-4.el9?arch=x86_64',
                          gcc_pkg['externalRefs'][0]['referenceLocator'])

            # Check relationships - should have 2 CONTAINS relationships
            contains_rels = [r for r in sbom_root['relationships'] if r['relationshipType'] == 'CONTAINS']
            self.assertEqual(len(contains_rels), 2)

            # Verify CONTAINS relationships
            for rel in contains_rels:
                self.assertEqual(rel['spdxElementId'], 'SPDXRef-Buildroot-test-pkg-x86_64')
                self.assertIn(rel['relatedSpdxElement'],
                              ['SPDXRef-Buildroot-Package-gcc-x86_64',
                               'SPDXRef-Buildroot-Package-glibc-x86_64'])
        finally:
            os.unlink(lockfile_path)
            os.unlink(broot_arch_list_file)

    @patch("merge_sboms.to_spdx_license")
    def test_attach_multiple_lockfiles(self, mock_convert_license):
        """Test attaching buildroot packages from multiple lockfiles (different architectures)."""
        # Mock license conversion to return SPDX format
        mock_convert_license.side_effect = lambda x: x if x else "NOASSERTION"

        sbom_root = {
            "name": "test-pkg-1.1.1-1.el9",
            "packages": [
                {
                    "SPDXID": "SPDXRef-x86-64-test-pkg",
                    "name": "test-pkg",
                    "externalRefs": [{
                        "referenceLocator": "pkg:rpm/redhat/test-pkg@1.1.1-1.el9?arch=x86_64"
                    }]
                },
                {
                    "SPDXID": "SPDXRef-aarch64-test-pkg",
                    "name": "test-pkg",
                    "externalRefs": [{
                        "referenceLocator": "pkg:rpm/redhat/test-pkg@1.1.1-1.el9?arch=aarch64"
                    }]
                }
            ],
            "relationships": []
        }

        lockfile_x86_64 = {
            "config": {"target_arch": "x86_64"},
            "buildroot": {
                "rpms": [{
                    "name": "gcc",
                    "version": "11.3.1",
                    "release": "4.el9",
                    "arch": "x86_64",
                    "epoch": None,
                    "license": "GPL-3.0-or-later",
                    "url": "https://example.com/gcc.rpm",
                    "sigmd5": "abc123"
                }]
            }
        }

        lockfile_aarch64 = {
            "config": {"target_arch": "aarch64"},
            "buildroot": {
                "rpms": [{
                    "name": "gcc",
                    "version": "11.3.1",
                    "release": "4.el9",
                    "arch": "aarch64",
                    "epoch": None,
                    "license": "GPL-3.0-or-later",
                    "url": "https://example.com/gcc-aarch64.rpm",
                    "sigmd5": "def456"
                }]
            }
        }

        with tempfile.NamedTemporaryFile(mode='w', delete=False, suffix='.json') as f1:
            json.dump(lockfile_x86_64, f1)
            lockfile_path1 = f1.name

        with tempfile.NamedTemporaryFile(mode='w', delete=False, suffix='.json') as f2:
            json.dump(lockfile_aarch64, f2)
            lockfile_path2 = f2.name

        # Create buildroot arch list JSON with both architectures
        broot_arch_list_data = {
            "x86_64": {
                "filelist": ["gcc-11.3.1-4.el9.x86_64.rpm"],
                "lockfile": lockfile_path1
            },
            "aarch64": {
                "filelist": ["gcc-11.3.1-4.el9.aarch64.rpm"],
                "lockfile": lockfile_path2
            }
        }

        with tempfile.NamedTemporaryFile(mode='w', delete=False, suffix='.json') as f:
            json.dump(broot_arch_list_data, f)
            broot_arch_list_file = f.name

        try:
            attach_buildroot_packages(sbom_root, broot_arch_list_file, "test-pkg")

            # Should have 2 original + 2 virtual + 2 buildroot = 6 packages
            self.assertEqual(len(sbom_root['packages']), 6)

            # Check virtual packages exist for both architectures
            virtual_ids = [pkg['SPDXID'] for pkg in sbom_root['packages']
                           if pkg['SPDXID'].startswith('SPDXRef-Buildroot-') and '-buildroot-' in pkg['name']]
            self.assertIn('SPDXRef-Buildroot-test-pkg-x86_64', virtual_ids)
            self.assertIn('SPDXRef-Buildroot-test-pkg-aarch64', virtual_ids)

            # Check buildroot packages exist for both architectures
            buildroot_ids = [pkg['SPDXID'] for pkg in sbom_root['packages']
                             if pkg['SPDXID'].startswith('SPDXRef-Buildroot-Package-')]
            self.assertIn('SPDXRef-Buildroot-Package-gcc-x86_64', buildroot_ids)
            self.assertIn('SPDXRef-Buildroot-Package-gcc-aarch64', buildroot_ids)

            # Check BUILD_TOOL_OF relationships
            build_tool_rels = [r for r in sbom_root['relationships']
                               if r['relationshipType'] == 'BUILD_TOOL_OF']
            self.assertEqual(len(build_tool_rels), 2)

            # Verify x86_64 BUILD_TOOL_OF relationship
            x86_rel = [r for r in build_tool_rels
                       if r['spdxElementId'] == 'SPDXRef-Buildroot-test-pkg-x86_64'][0]
            self.assertEqual(x86_rel['relatedSpdxElement'], 'SPDXRef-x86-64-test-pkg')

            # Verify aarch64 BUILD_TOOL_OF relationship
            aarch_rel = [r for r in build_tool_rels
                         if r['spdxElementId'] == 'SPDXRef-Buildroot-test-pkg-aarch64'][0]
            self.assertEqual(aarch_rel['relatedSpdxElement'], 'SPDXRef-aarch64-test-pkg')
        finally:
            os.unlink(lockfile_path1)
            os.unlink(lockfile_path2)
            os.unlink(broot_arch_list_file)

    @patch("merge_sboms.to_spdx_license")
    def test_attach_buildroot_with_epoch(self, mock_convert_license):
        """Test buildroot package with epoch in version."""
        # Mock license conversion to return SPDX format
        mock_convert_license.side_effect = lambda x: x if x else "NOASSERTION"

        sbom_root = {
            "name": "test-pkg-1.1.1-1.el9",
            "packages": [],
            "relationships": []
        }

        lockfile_data = {
            "config": {"target_arch": "x86_64"},
            "buildroot": {
                "rpms": [{
                    "name": "systemd",
                    "version": "252",
                    "release": "13.el9",
                    "arch": "x86_64",
                    "epoch": "2",
                    "license": "LGPL-2.1-or-later",
                    "url": "https://example.com/systemd.rpm"
                }]
            }
        }

        with tempfile.NamedTemporaryFile(mode='w', delete=False, suffix='.json') as f:
            json.dump(lockfile_data, f)
            lockfile_path = f.name

        # Create buildroot arch list JSON
        broot_arch_list_data = {
            "x86_64": {
                "filelist": ["systemd-252-13.el9.x86_64.rpm"],
                "lockfile": lockfile_path
            }
        }

        with tempfile.NamedTemporaryFile(mode='w', delete=False, suffix='.json') as f:
            json.dump(broot_arch_list_data, f)
            broot_arch_list_file = f.name

        try:
            attach_buildroot_packages(sbom_root, broot_arch_list_file, "test-pkg")

            # Find systemd package
            systemd_pkg = [pkg for pkg in sbom_root['packages']
                           if pkg['name'] == 'systemd'][0]

            # Check version includes epoch
            self.assertEqual(systemd_pkg['versionInfo'], '2:252-13.el9')

            # Check purl includes epoch
            purl = systemd_pkg['externalRefs'][0]['referenceLocator']
            self.assertIn('2:252-13.el9', purl)
        finally:
            os.unlink(lockfile_path)
            os.unlink(broot_arch_list_file)

    @patch("merge_sboms.to_spdx_license")
    def test_lockfile_without_target_arch(self, mock_convert_license):
        """Test that lockfiles without target_arch still work (using arch key from buildroot arch list)."""
        # Mock license conversion to return SPDX format
        mock_convert_license.side_effect = lambda x: x if x else "NOASSERTION"

        sbom_root = {
            "name": "test-pkg-1.1.1-1.el9",
            "packages": [],
            "relationships": []
        }

        lockfile_data = {
            "config": {},  # No target_arch
            "buildroot": {
                "rpms": [{
                    "name": "gcc",
                    "version": "11.3.1",
                    "release": "4.el9",
                    "arch": "x86_64",
                    "epoch": None,
                    "license": "GPL-3.0-or-later",
                    "url": "https://example.com/gcc.rpm",
                    "sigmd5": "abc123"
                }]
            }
        }

        with tempfile.NamedTemporaryFile(mode='w', delete=False, suffix='.json') as f:
            json.dump(lockfile_data, f)
            lockfile_path = f.name

        # Create buildroot arch list JSON
        broot_arch_list_data = {
            "x86_64": {
                "filelist": ["gcc-11.3.1-4.el9.x86_64.rpm"],
                "lockfile": lockfile_path
            }
        }

        with tempfile.NamedTemporaryFile(mode='w', delete=False, suffix='.json') as f:
            json.dump(broot_arch_list_data, f)
            broot_arch_list_file = f.name

        try:
            attach_buildroot_packages(sbom_root, broot_arch_list_file, "test-pkg")

            # Should have packages added (uses arch key from buildroot arch list)
            self.assertEqual(len(sbom_root['packages']), 2)  # 1 virtual + 1 buildroot

            # Check virtual buildroot package uses x86_64 from JSON key
            virtual_pkg = sbom_root['packages'][0]
            self.assertEqual(virtual_pkg['SPDXID'], 'SPDXRef-Buildroot-test-pkg-x86_64')
        finally:
            os.unlink(lockfile_path)
            os.unlink(broot_arch_list_file)


class TestCreateBaseSbom(unittest.TestCase):
    """
    Unit tests for create_base_sbom - verifies SRPM detection via sourcepackage header.
    """

    @patch('merge_sboms.to_spdx_license', return_value="MIT")
    @patch('merge_sboms.calc_checksum', return_value="abc123")
    @patch('merge_sboms.koji')
    def test_srpm_detected_by_sourcepackage_header(self, mock_koji, _mock_checksum, _mock_license):
        """Test that SRPM is detected via sourcepackage header field.

        SRPM header arch is the buildarch (e.g. x86_64), not 'src'.
        The code uses sourcepackage header to identify SRPMs and sets
        arch to 'src' accordingly.
        """
        with tempfile.TemporaryDirectory() as tmpdir:
            for name in ["foo-1.0-1.el9.src.rpm", "foo-1.0-1.el9.noarch.rpm"]:
                with open(os.path.join(tmpdir, name), 'w', encoding='utf-8'):
                    pass

            # SRPM: sourcepackage=1, header arch=x86_64 (buildarch)
            # noarch RPM: sourcepackage=None, header arch=noarch, sourcerpm matches
            mock_koji.get_header_fields.side_effect = [
                {"name": "foo", "version": "1.0", "release": "1.el9",
                 "arch": "x86_64", "description": "test", "license": "MIT",
                 "sigmd5": "aaa", "sha256header": "bbb",
                 "sourcepackage": 1, "sourcerpm": None},
                {"name": "foo", "version": "1.0", "release": "1.el9",
                 "arch": "noarch", "description": "test", "license": "MIT",
                 "sigmd5": "aaa", "sha256header": "bbb",
                 "sourcepackage": None, "sourcerpm": "foo-1.0-1.el9.src.rpm"},
            ]

            sbom = create_base_sbom(tmpdir)

        # SRPM: arch overridden to 'src', gets SPDXRef-SRPM
        srpm_pkg = sbom['packages'][0]
        self.assertEqual(srpm_pkg['SPDXID'], "SPDXRef-SRPM")
        self.assertIn("arch=src", srpm_pkg['externalRefs'][0]['referenceLocator'])

        # noarch RPM uses header arch directly
        bin_pkg = sbom['packages'][1]
        self.assertEqual(bin_pkg['SPDXID'], "SPDXRef-noarch-foo")
        self.assertIn("arch=noarch", bin_pkg['externalRefs'][0]['referenceLocator'])

        # GENERATED_FROM relationship for binary RPM only
        gen_rels = [r for r in sbom['relationships']
                    if r['relationshipType'] == 'GENERATED_FROM']
        self.assertEqual(len(gen_rels), 1)
        self.assertEqual(gen_rels[0]['spdxElementId'], "SPDXRef-noarch-foo")

    @patch('merge_sboms.to_spdx_license', return_value="MIT")
    @patch('merge_sboms.calc_checksum', return_value="abc123")
    @patch('merge_sboms.koji')
    def test_sourcerpm_mismatch_raises(self, mock_koji, _mock_checksum, _mock_license):
        """Test that mismatched sourcerpm header raises ValueError."""
        with tempfile.TemporaryDirectory() as tmpdir:
            for name in ["foo-1.0-1.el9.src.rpm", "foo-1.0-1.el9.noarch.rpm"]:
                with open(os.path.join(tmpdir, name), 'w', encoding='utf-8'):
                    pass

            mock_koji.get_header_fields.side_effect = [
                {"name": "foo", "version": "1.0", "release": "1.el9",
                 "arch": "x86_64", "description": "test", "license": "MIT",
                 "sigmd5": "aaa", "sha256header": "bbb",
                 "sourcepackage": 1, "sourcerpm": None},
                {"name": "foo", "version": "1.0", "release": "1.el9",
                 "arch": "noarch", "description": "test", "license": "MIT",
                 "sigmd5": "aaa", "sha256header": "bbb",
                 "sourcepackage": None, "sourcerpm": "bar-2.0-1.el9.src.rpm"},
            ]

            with self.assertRaises(ValueError) as ve:
                create_base_sbom(tmpdir)
            self.assertEqual(
                str(ve.exception),
                "[CRITICAL] Binary RPM foo-1.0-1.el9.noarch.rpm has sourcerpm header bar-2.0-1.el9.src.rpm"
                " that does not match expected SRPM foo-1.0-1.el9.src.rpm",
            )


class TestMergeSboms(unittest.TestCase):
    """
    Unit tests for python_scripts/merge__sboms.py.
    """
    def setUp(self):
        self.maxDiff = None

    @patch('merge_sboms.create_base_sbom')
    def test_valid(self, mock_create_base_sbom):
        """
        Unit test for valid case of merge_sboms python script.
        """
        testdir = os.path.realpath(__file__)
        testdir = os.path.dirname(testdir)
        sbom_spdx_path = os.path.join(testdir, "sbom_sources", 'sbom-spdx.json')
        with open(sbom_spdx_path, 'r', encoding='utf-8') as f:
            mock_create_base_sbom.return_value = json.load(f)

        rpm_dir = os.path.join(testdir, "sbom_sources")
        syft_sbom = os.path.join(testdir, "sbom_sources", 'syft_sbom.json')
        sbom_merged = os.path.join(testdir, 'sbom_merged.json')
        sys.argv = ["this", "--rpm-dir", rpm_dir, '--syft-sbom', syft_sbom, '--sbom-merged', sbom_merged]
        merge_sboms()
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
                         {"SPDXID": "SPDXRef-DocumentRoot-Directory",
                          "name": "test-pkg-1.1.1-1.el9.src",
                          "downloadLocation": "NOASSERTION",
                          "filesAnalyzed": False,
                          "primaryPackagePurpose": "SOURCE"},
                         {"SPDXID": "SPDXRef-Package-python-setuptools-59.6.0",
                          "name": "python-setuptools",
                          "versionInfo": "59.6.0",
                          "supplier": "NOASSERTION",
                          "downloadLocation": "NOASSERTION",
                          "filesAnalyzed": False,
                          "externalRefs": [{"referenceCategory": "PACKAGE-MANAGER",
                                            "referenceType": "purl",
                                            "referenceLocator": "pkg:pypi/setuptools@59.6.0"}]}],
            "files": [],
            "relationships": [{"spdxElementId": "SPDXRef-DOCUMENT",
                               "relationshipType": "DESCRIBES",
                               "relatedSpdxElement": "SPDXRef-SRPM"},
                              {"spdxElementId": "SPDXRef-noarch-test-pkg",
                               "relationshipType": "GENERATED_FROM",
                               "relatedSpdxElement": "SPDXRef-SRPM"},
                              {"spdxElementId": "SPDXRef-SRPM",
                               "relationshipType": "CONTAINS",
                               "relatedSpdxElement": "SPDXRef-DocumentRoot-Directory"},
                              {"spdxElementId": "SPDXRef-DocumentRoot-Directory",
                               "relationshipType": "CONTAINS",
                               "relatedSpdxElement": "SPDXRef-Package-python-setuptools-59.6.0"}
                              ],
            "documentDescribes": ["SPDXRef-noarch-test-pkg"]
        }


class TestAttachSyftSboms(unittest.TestCase):
    """
    Unit tests for attach_syft_sboms function and related helpers.
    """

    def test_find_rpm_packages(self):
        """Test _find_rpm_packages builds correct NVRA mapping."""
        sbom_root = {
            "packages": [
                {
                    "SPDXID": "SPDXRef-SRPM",
                    "packageFileName": "test-pkg-1.0-1.el9.src.rpm"
                },
                {
                    "SPDXID": "SPDXRef-x86_64-foo",
                    "packageFileName": "foo-1.0-1.el9.x86_64.rpm"
                },
                {
                    "SPDXID": "SPDXRef-x86_64-bar",
                    "packageFileName": "bar-2.0-1.el9.x86_64.rpm"
                },
                {
                    "SPDXID": "SPDXRef-noarch-baz",
                    "packageFileName": "baz-3.0-1.el9.noarch.rpm"
                }
            ]
        }

        rpm_packages = _find_rpm_packages(sbom_root)

        # Should include both SRPM and binary RPMs
        self.assertEqual(len(rpm_packages), 4)
        self.assertIn("test-pkg-1.0-1.el9.src", rpm_packages)
        self.assertIn("foo-1.0-1.el9.x86_64", rpm_packages)
        self.assertIn("bar-2.0-1.el9.x86_64", rpm_packages)
        self.assertIn("baz-3.0-1.el9.noarch", rpm_packages)

        # Verify package references
        self.assertEqual(rpm_packages["test-pkg-1.0-1.el9.src"]["SPDXID"], "SPDXRef-SRPM")
        self.assertEqual(rpm_packages["foo-1.0-1.el9.x86_64"]["SPDXID"], "SPDXRef-x86_64-foo")

    def test_rename_doc_root_id(self):
        """Test _rename_doc_root_id generates correct new ID."""
        syft_sbom = {
            "packages": [],
            "relationships": [
                {
                    "spdxElementId": "SPDXRef-DOCUMENT",
                    "relationshipType": "DESCRIBES",
                    "relatedSpdxElement": "SPDXRef-RootDirectory"
                }
            ]
        }

        old_id, new_id = _rename_doc_root_id(syft_sbom, "foo-1.0-1.el9.x86_64")

        self.assertEqual(old_id, "SPDXRef-RootDirectory")
        self.assertEqual(new_id, "SPDXRef-Directory-Root-foo-1.0-1.el9.x86_64")

    def test_rename_doc_root_id_no_describes(self):
        """Test _rename_doc_root_id returns None when no DESCRIBES relationship."""
        syft_sbom = {
            "packages": [],
            "relationships": []
        }

        old_id, new_id = _rename_doc_root_id(syft_sbom, "foo-1.0-1.el9.x86_64")

        self.assertIsNone(old_id)
        self.assertIsNone(new_id)

    def test_attach_syft_sboms_basic(self):
        """Test attaching a single RPM SBOM."""
        sbom_root = {
            "packages": [
                {
                    "SPDXID": "SPDXRef-x86_64-python3-requests",
                    "packageFileName": "python3-requests-2.28.1-1.el9.x86_64.rpm",
                    "name": "python3-requests"
                }
            ],
            "files": [],
            "relationships": []
        }

        # Create temporary directory with RPM SBOM file
        with tempfile.TemporaryDirectory() as tmpdir:
            syft_sbom_file = os.path.join(tmpdir, "python3-requests-2.28.1-1.el9.x86_64.sbom.json")

            syft_sbom_data = {
                "packages": [
                    {
                        "SPDXID": "SPDXRef-RootDir",
                        "name": "python3-requests-root"
                    },
                    {
                        "SPDXID": "SPDXRef-Package-urllib3",
                        "name": "urllib3",
                        "versionInfo": "1.26.5"
                    }
                ],
                "files": [],
                "relationships": [
                    {
                        "spdxElementId": "SPDXRef-DOCUMENT",
                        "relationshipType": "DESCRIBES",
                        "relatedSpdxElement": "SPDXRef-RootDir"
                    },
                    {
                        "spdxElementId": "SPDXRef-RootDir",
                        "relationshipType": "CONTAINS",
                        "relatedSpdxElement": "SPDXRef-Package-urllib3"
                    }
                ]
            }

            with open(syft_sbom_file, 'w', encoding="utf-8") as f:
                json.dump(syft_sbom_data, f)

            attach_syft_sboms(sbom_root, tmpdir)

        # Should have 3 packages: original RPM + 2 from RPM SBOM
        self.assertEqual(len(sbom_root["packages"]), 3)

        # Check root directory was renamed
        root_pkg = [p for p in sbom_root["packages"] if "Directory-Root" in p["SPDXID"]][0]
        self.assertEqual(root_pkg["SPDXID"], "SPDXRef-Directory-Root-python3-requests-2.28.1-1.el9.x86_64")

        # Check other package is included
        urllib3_pkg = [p for p in sbom_root["packages"] if p.get("name") == "urllib3"][0]
        self.assertEqual(urllib3_pkg["SPDXID"], "SPDXRef-Package-urllib3")

        # Check CONTAINS relationship from RPM to root directory
        rpm_contains_rel = [r for r in sbom_root["relationships"]
                            if r["spdxElementId"] == "SPDXRef-x86_64-python3-requests"
                            and r["relationshipType"] == "CONTAINS"][0]
        self.assertEqual(rpm_contains_rel["relatedSpdxElement"],
                         "SPDXRef-Directory-Root-python3-requests-2.28.1-1.el9.x86_64")

        # Check internal relationships are preserved
        internal_rel = [r for r in sbom_root["relationships"]
                        if "Directory-Root" in r["spdxElementId"]
                        and r["relationshipType"] == "CONTAINS"][0]
        self.assertEqual(internal_rel["relatedSpdxElement"], "SPDXRef-Package-urllib3")

    def test_attach_syft_sboms_multiple(self):
        """Test attaching multiple RPM SBOMs."""
        sbom_root = {
            "packages": [
                {
                    "SPDXID": "SPDXRef-x86_64-foo",
                    "packageFileName": "foo-1.0-1.el9.x86_64.rpm"
                },
                {
                    "SPDXID": "SPDXRef-x86_64-bar",
                    "packageFileName": "bar-2.0-1.el9.x86_64.rpm"
                }
            ],
            "files": [],
            "relationships": []
        }

        with tempfile.TemporaryDirectory() as tmpdir:
            # Create first RPM SBOM
            syft_sbom1 = os.path.join(tmpdir, "foo-1.0-1.el9.x86_64.sbom.json")
            with open(syft_sbom1, 'w', encoding="utf-8") as f:
                json.dump({
                    "packages": [{"SPDXID": "SPDXRef-Root", "name": "foo-root"}],
                    "files": [],
                    "relationships": [
                        {
                            "spdxElementId": "SPDXRef-DOCUMENT",
                            "relationshipType": "DESCRIBES",
                            "relatedSpdxElement": "SPDXRef-Root"
                        }
                    ]
                }, f)

            # Create second RPM SBOM
            syft_sbom2 = os.path.join(tmpdir, "bar-2.0-1.el9.x86_64.sbom.json")
            with open(syft_sbom2, 'w', encoding="utf-8") as f:
                json.dump({
                    "packages": [{"SPDXID": "SPDXRef-Root", "name": "bar-root"}],
                    "files": [],
                    "relationships": [
                        {
                            "spdxElementId": "SPDXRef-DOCUMENT",
                            "relationshipType": "DESCRIBES",
                            "relatedSpdxElement": "SPDXRef-Root"
                        }
                    ]
                }, f)

            attach_syft_sboms(sbom_root, tmpdir)

        # Should have 4 packages: 2 original + 2 from RPM SBOMs
        self.assertEqual(len(sbom_root["packages"]), 4)

        # Verify both roots were renamed uniquely
        spdx_ids = [p["SPDXID"] for p in sbom_root["packages"]]
        self.assertIn("SPDXRef-Directory-Root-foo-1.0-1.el9.x86_64", spdx_ids)
        self.assertIn("SPDXRef-Directory-Root-bar-2.0-1.el9.x86_64", spdx_ids)

    def test_attach_syft_sboms_srpm(self):
        """Test attaching a syft SBOM for an SRPM."""
        sbom_root = {
            "packages": [
                {
                    "SPDXID": "SPDXRef-SRPM",
                    "packageFileName": "test-pkg-1.0-1.el9.src.rpm",
                    "name": "test-pkg"
                }
            ],
            "files": [],
            "relationships": []
        }

        with tempfile.TemporaryDirectory() as tmpdir:
            # SRPM syft SBOM filename: NVR.src.sbom.json
            syft_sbom_file = os.path.join(tmpdir, "test-pkg-1.0-1.el9.src.sbom.json")
            syft_sbom_data = {
                "packages": [
                    {
                        "SPDXID": "SPDXRef-RootDir",
                        "name": "test-pkg-root"
                    },
                    {
                        "SPDXID": "SPDXRef-Package-src-file",
                        "name": "source-file",
                        "versionInfo": "1.0"
                    }
                ],
                "files": [],
                "relationships": [
                    {
                        "spdxElementId": "SPDXRef-DOCUMENT",
                        "relationshipType": "DESCRIBES",
                        "relatedSpdxElement": "SPDXRef-RootDir"
                    },
                    {
                        "spdxElementId": "SPDXRef-RootDir",
                        "relationshipType": "CONTAINS",
                        "relatedSpdxElement": "SPDXRef-Package-src-file"
                    }
                ]
            }

            with open(syft_sbom_file, 'w', encoding="utf-8") as f:
                json.dump(syft_sbom_data, f)

            attach_syft_sboms(sbom_root, tmpdir)

        # Should have 3 packages: original SRPM + 2 from syft SBOM
        self.assertEqual(len(sbom_root["packages"]), 3)

        # Check root directory was renamed with SRPM NVRA
        root_pkg = [p for p in sbom_root["packages"] if "Directory-Root" in p["SPDXID"]][0]
        self.assertEqual(root_pkg["SPDXID"], "SPDXRef-Directory-Root-test-pkg-1.0-1.el9.src")

        # Check CONTAINS relationship from SRPM to root directory
        srpm_contains_rel = [r for r in sbom_root["relationships"]
                             if r["spdxElementId"] == "SPDXRef-SRPM"
                             and r["relationshipType"] == "CONTAINS"][0]
        self.assertEqual(srpm_contains_rel["relatedSpdxElement"],
                         "SPDXRef-Directory-Root-test-pkg-1.0-1.el9.src")

    def test_attach_syft_sboms_no_match(self):
        """Test handling of RPM SBOM with no matching binary RPM."""
        sbom_root = {
            "packages": [
                {
                    "SPDXID": "SPDXRef-x86_64-foo",
                    "packageFileName": "foo-1.0-1.el9.x86_64.rpm"
                }
            ],
            "files": [],
            "relationships": []
        }

        with tempfile.TemporaryDirectory() as tmpdir:
            # Create SBOM for non-existent RPM
            syft_sbom = os.path.join(tmpdir, "nonexistent-1.0-1.el9.x86_64.sbom.json")
            with open(syft_sbom, 'w', encoding="utf-8") as f:
                json.dump({
                    "packages": [{"SPDXID": "SPDXRef-Root"}],
                    "files": [],
                    "relationships": [
                        {
                            "spdxElementId": "SPDXRef-DOCUMENT",
                            "relationshipType": "DESCRIBES",
                            "relatedSpdxElement": "SPDXRef-Root"
                        }
                    ]
                }, f)

            # Should log warning but not crash
            attach_syft_sboms(sbom_root, tmpdir)

        # Should still have only original package
        self.assertEqual(len(sbom_root["packages"]), 1)

    def test_attach_syft_sboms_empty_dir(self):
        """Test handling of empty RPM SBOM directory."""
        sbom_root = {
            "packages": [
                {
                    "SPDXID": "SPDXRef-x86_64-foo",
                    "packageFileName": "foo-1.0-1.el9.x86_64.rpm"
                }
            ],
            "files": [],
            "relationships": []
        }

        with tempfile.TemporaryDirectory() as tmpdir:
            # Empty directory
            attach_syft_sboms(sbom_root, tmpdir)

        # Should not modify SBOM
        self.assertEqual(len(sbom_root["packages"]), 1)

    def test_attach_syft_sboms_none_dir(self):
        """Test handling of None syft_sbom_dir."""
        sbom_root = {
            "packages": [],
            "files": [],
            "relationships": []
        }

        # Should raise ValueError
        with self.assertRaises(ValueError) as cm:
            attach_syft_sboms(sbom_root, None)
        self.assertIn("syft_sbom_dir parameter is required", str(cm.exception))


class TestInitConfig(unittest.TestCase):
    """Unit tests for init_config function."""

    def _reset_config(self):
        """Reset CONFIG to defaults."""
        CONFIG.update({
            "sbom_creators": list(DEFAULT_SBOM_CREATORS),
            "annotator": DEFAULT_ANNOTATOR,
            "document_namespace": DEFAULT_DOCUMENT_NAMESPACE,
            "supplier": DEFAULT_SUPPLIER,
            "purl_rpm_namespace": "fedora",
        })

    def setUp(self):
        self._reset_config()

    def tearDown(self):
        self._reset_config()

    def test_loads_valid_config(self):
        """Test loading a valid config file overrides defaults."""
        config_data = {
            "sbom_creators": ["Tool: MyTool", "Tool: Other"],
            "supplier": "Organization: ACME",
        }

        with tempfile.NamedTemporaryFile(mode='w', delete=False, suffix='.json') as f:
            json.dump(config_data, f)
            config_path = f.name

        try:
            init_config(config_path)
            self.assertEqual(CONFIG["sbom_creators"], ["Tool: MyTool", "Tool: Other"])
            self.assertEqual(CONFIG["supplier"], "Organization: ACME")
            # Unchanged keys keep defaults
            self.assertEqual(CONFIG["document_namespace"], DEFAULT_DOCUMENT_NAMESPACE)
            self.assertEqual(CONFIG["purl_rpm_namespace"], "fedora")
        finally:
            os.unlink(config_path)

    def test_ignores_unknown_keys(self):
        """Test that unknown keys in config file are ignored."""
        config_data = {
            "sbom_creators": ["Tool: Custom"],
            "unknown_key": "should be ignored",
        }

        with tempfile.NamedTemporaryFile(mode='w', delete=False, suffix='.json') as f:
            json.dump(config_data, f)
            config_path = f.name

        try:
            init_config(config_path)
            self.assertEqual(CONFIG["sbom_creators"], ["Tool: Custom"])
            self.assertNotIn("unknown_key", CONFIG)
        finally:
            os.unlink(config_path)

    def test_missing_explicit_path_keeps_defaults(self):
        """Test that a nonexistent explicit path logs warning and keeps defaults."""
        init_config("/nonexistent/path/config.json")
        self.assertEqual(CONFIG["sbom_creators"], list(DEFAULT_SBOM_CREATORS))
        self.assertEqual(CONFIG["supplier"], DEFAULT_SUPPLIER)

    def test_missing_default_path_keeps_defaults(self):
        """Test that missing default config path keeps defaults silently."""
        init_config(None)
        self.assertEqual(CONFIG["sbom_creators"], list(DEFAULT_SBOM_CREATORS))
        self.assertEqual(CONFIG["supplier"], DEFAULT_SUPPLIER)

    def test_invalid_json_keeps_defaults(self):
        """Test that invalid JSON in config file keeps defaults."""
        with tempfile.NamedTemporaryFile(mode='w', delete=False, suffix='.json') as f:
            f.write("not valid json{{{")
            config_path = f.name

        try:
            init_config(config_path)
            self.assertEqual(CONFIG["sbom_creators"], list(DEFAULT_SBOM_CREATORS))
            self.assertEqual(CONFIG["supplier"], DEFAULT_SUPPLIER)
        finally:
            os.unlink(config_path)

    def test_all_keys_configurable(self):
        """Test that all CONFIG keys can be overridden."""
        config_data = {
            "sbom_creators": ["Tool: X", "Tool: Y"],
            "annotator": "Tool: X",
            "document_namespace": "https://example.com/{nvr}.spdx.json",
            "supplier": "Organization: X",
            "purl_rpm_namespace": "centos",
        }

        with tempfile.NamedTemporaryFile(mode='w', delete=False, suffix='.json') as f:
            json.dump(config_data, f)
            config_path = f.name

        try:
            init_config(config_path)
            self.assertEqual(CONFIG["sbom_creators"], ["Tool: X", "Tool: Y"])
            self.assertEqual(CONFIG["annotator"], "Tool: X")
            self.assertEqual(CONFIG["document_namespace"], "https://example.com/{nvr}.spdx.json")
            self.assertEqual(CONFIG["supplier"], "Organization: X")
            self.assertEqual(CONFIG["purl_rpm_namespace"], "centos")
        finally:
            os.unlink(config_path)


if __name__ == "__main__":
    unittest.main()
