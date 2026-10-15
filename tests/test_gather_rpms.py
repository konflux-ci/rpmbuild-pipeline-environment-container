"""
Tests gather_rpms.py.
"""

# pylint: disable=W0201,C0116,R0801

from argparse import ArgumentTypeError, Namespace
import json
import os
import shutil
import tempfile
import unittest
from unittest.mock import patch

import gather_rpms
from gather_rpms import (
    prepare_koji_broot,
    create_broot_arch_rpms_file,
    handle_archdir,
    pick_sbom,
    pick_ancestors,
    STAGING_DIR,
    ANCESTORS_JSON,
    BROOT_ARCH_RPMS_JSON,
)


class TestPrepareKojiBroot(unittest.TestCase):
    """
    Unit tests for prepare_koji_broot function.
    """

    def setUp(self):
        """Reset global buildroots dict before each test."""
        gather_rpms.buildroots.clear()

    def test_prepare_koji_broot_with_lockfile(self):
        """Test prepare_koji_broot with valid lockfile."""
        lockfile_data = {
            "buildroot": {
                "rpms": [
                    {
                        "name": "gcc",
                        "version": "11.3.1",
                        "release": "4.el9",
                        "arch": "x86_64",
                        "epoch": None,
                        "sigmd5": "abc123def456",
                        "signature": "RSA/SHA256",
                        "license": "GPL-3.0-or-later",
                        "url": "https://example.com/gcc.rpm"
                    },
                    {
                        "name": "glibc",
                        "version": "2.34",
                        "release": "60.el9",
                        "arch": "x86_64",
                        "epoch": None,
                        "sigmd5": "def456ghi789",
                        "signature": "RSA/SHA256",
                        "license": "LGPL-2.1-or-later"
                    }
                ]
            }
        }

        with tempfile.NamedTemporaryFile(mode='w', delete=False, suffix='.json') as f:
            json.dump(lockfile_data, f)
            lockfile_path = f.name

        try:
            prepare_koji_broot("x86_64", "test-pipeline-123", lockfile_path=lockfile_path)

            # Verify buildroot was created
            self.assertIn("x86_64", gather_rpms.buildroots)
            buildroot = gather_rpms.buildroots["x86_64"]

            # Verify buildroot structure
            self.assertEqual(buildroot["content_generator"]["name"], "konflux")
            self.assertEqual(buildroot["content_generator"]["version"], "0.1")
            self.assertEqual(buildroot["container"]["type"], "docker")
            self.assertEqual(buildroot["container"]["arch"], "x86_64")
            self.assertEqual(buildroot["host"]["os"], "RHEL")
            self.assertEqual(buildroot["host"]["arch"], "x86_64")
            self.assertEqual(buildroot["extra"]["konflux"]["pipeline_id"], "test-pipeline-123")

            # Verify components were extracted
            self.assertEqual(len(buildroot["components"]), 2)

            # Verify first component
            gcc_component = buildroot["components"][0]
            self.assertEqual(gcc_component["name"], "gcc")
            self.assertEqual(gcc_component["version"], "11.3.1")
            self.assertEqual(gcc_component["release"], "4.el9")
            self.assertEqual(gcc_component["arch"], "x86_64")
            self.assertEqual(gcc_component["sigmd5"], "abc123def456")
            self.assertEqual(gcc_component["signature"], "RSA/SHA256")
            self.assertEqual(gcc_component["type"], "rpm")
            # Verify extra fields are not included
            self.assertNotIn("license", gcc_component)
            self.assertNotIn("url", gcc_component)

            # Verify second component
            glibc_component = buildroot["components"][1]
            self.assertEqual(glibc_component["name"], "glibc")
            self.assertEqual(glibc_component["type"], "rpm")

            # Verify tools list exists
            self.assertIsInstance(buildroot["tools"], list)
        finally:
            os.unlink(lockfile_path)

    def test_prepare_koji_broot_no_lockfile(self):
        """Test prepare_koji_broot with no lockfile path provided."""
        prepare_koji_broot("aarch64", "test-pipeline-456", lockfile_path=None)

        # Verify buildroot was created
        self.assertIn("aarch64", gather_rpms.buildroots)
        buildroot = gather_rpms.buildroots["aarch64"]

        # Verify basic structure
        self.assertEqual(buildroot["container"]["arch"], "aarch64")
        self.assertEqual(buildroot["extra"]["konflux"]["pipeline_id"], "test-pipeline-456")

        # Verify components list is empty
        self.assertEqual(buildroot["components"], [])

    def test_prepare_koji_broot_missing_file(self):
        """Test prepare_koji_broot with lockfile path that doesn't exist."""
        nonexistent_path = "/tmp/nonexistent_lockfile_12345.json"

        prepare_koji_broot("ppc64le", "test-pipeline-789", lockfile_path=nonexistent_path)

        # Verify buildroot was created
        self.assertIn("ppc64le", gather_rpms.buildroots)
        buildroot = gather_rpms.buildroots["ppc64le"]

        # Verify components list is empty when lockfile doesn't exist
        self.assertEqual(buildroot["components"], [])

    def test_prepare_koji_broot_with_epoch(self):
        """Test prepare_koji_broot correctly handles RPMs with epoch."""
        lockfile_data = {
            "buildroot": {
                "rpms": [
                    {
                        "name": "systemd",
                        "version": "252",
                        "release": "13.el9",
                        "arch": "x86_64",
                        "epoch": "2",
                        "sigmd5": "xyz789abc123"
                    }
                ]
            }
        }

        with tempfile.NamedTemporaryFile(mode='w', delete=False, suffix='.json') as f:
            json.dump(lockfile_data, f)
            lockfile_path = f.name

        try:
            prepare_koji_broot("x86_64", "test-pipeline-epoch", lockfile_path=lockfile_path)

            buildroot = gather_rpms.buildroots["x86_64"]
            component = buildroot["components"][0]

            # Verify epoch is included
            self.assertEqual(component["epoch"], "2")
            self.assertEqual(component["name"], "systemd")
        finally:
            os.unlink(lockfile_path)


class TestCreateBrootArchRpmsFile(unittest.TestCase):
    """
    Unit tests for create_broot_arch_rpms_file function.
    """

    def setUp(self):
        """Reset global broot_arch_rpms dict and create temp dir before each test."""
        gather_rpms.broot_arch_rpms.clear()
        self.temp_dir = tempfile.mkdtemp()
        self.original_cwd = os.getcwd()
        # Create staging directory in temp dir
        self.staging_dir = os.path.join(self.temp_dir, STAGING_DIR)
        os.makedirs(self.staging_dir, exist_ok=True)
        # Change to temp directory
        os.chdir(self.temp_dir)

    def tearDown(self):
        """Clean up temp directory and restore cwd."""
        os.chdir(self.original_cwd)
        if os.path.exists(self.temp_dir):
            shutil.rmtree(self.temp_dir)

    def test_create_broot_arch_rpms_file(self):
        """Test create_broot_arch_rpms_file creates correct JSON."""
        # Populate broot_arch_rpms
        gather_rpms.broot_arch_rpms["x86_64"] = {
            "filelist": ["foo-1.0-1.el9.x86_64.rpm", "bar-2.0-1.el9.x86_64.rpm"],
            "lockfile": "x86_64/results/buildroot_lock.json"
        }
        gather_rpms.broot_arch_rpms["aarch64"] = {
            "filelist": ["foo-1.0-1.el9.aarch64.rpm"],
            "lockfile": "aarch64/results/buildroot_lock.json"
        }

        create_broot_arch_rpms_file()

        # Verify file was created
        output_file = os.path.join(STAGING_DIR, BROOT_ARCH_RPMS_JSON)
        self.assertTrue(os.path.exists(output_file))

        # Verify file contents
        with open(output_file, 'r', encoding='utf-8') as f:
            result = json.load(f)

        self.assertEqual(len(result), 2)
        self.assertIn("x86_64", result)
        self.assertIn("aarch64", result)

        # Verify x86_64 data
        self.assertEqual(len(result["x86_64"]["filelist"]), 2)
        self.assertIn("foo-1.0-1.el9.x86_64.rpm", result["x86_64"]["filelist"])
        self.assertEqual(result["x86_64"]["lockfile"], "x86_64/results/buildroot_lock.json")

        # Verify aarch64 data
        self.assertEqual(len(result["aarch64"]["filelist"]), 1)
        self.assertEqual(result["aarch64"]["lockfile"], "aarch64/results/buildroot_lock.json")

    def test_create_broot_arch_rpms_file_empty(self):
        """Test create_broot_arch_rpms_file with empty broot_arch_rpms."""
        # broot_arch_rpms is empty
        create_broot_arch_rpms_file()

        # Verify file was created
        output_file = os.path.join(STAGING_DIR, BROOT_ARCH_RPMS_JSON)
        self.assertTrue(os.path.exists(output_file))

        # Verify file contains empty dict
        with open(output_file, 'r', encoding='utf-8') as f:
            result = json.load(f)

        self.assertEqual(result, {})


class TestPickSbom(unittest.TestCase):
    """Unit tests for pick_sbom function."""

    def setUp(self):
        """Create temp dir and staging directory before each test."""
        self.temp_dir = tempfile.mkdtemp()
        self.original_cwd = os.getcwd()
        self.staging_dir = os.path.join(self.temp_dir, STAGING_DIR)
        os.makedirs(self.staging_dir, exist_ok=True)
        os.chdir(self.temp_dir)

    def tearDown(self):
        """Clean up temp directory and restore cwd."""
        os.chdir(self.original_cwd)
        if os.path.exists(self.temp_dir):
            shutil.rmtree(self.temp_dir)

    @patch('gather_rpms.symlink')
    def test_pick_sbom_when_exists(self, mock_symlink):
        """Test pick_sbom calls symlink when SBOM file exists."""
        arch = "x86_64"
        arch_dir = os.path.join(self.temp_dir, arch)
        os.makedirs(arch_dir, exist_ok=True)

        # Create the expected SBOM file
        with open(os.path.join(arch_dir, "foo-1.0-1.el9.x86_64.sbom.json"),
                  'w', encoding='utf-8'):
            pass

        pick_sbom("foo-1.0-1.el9.x86_64.rpm", arch)

        mock_symlink.assert_called_once_with(
            "foo-1.0-1.el9.x86_64.sbom.json", arch)

    @patch('gather_rpms.symlink')
    def test_pick_sbom_warns_when_missing(self, mock_symlink):
        """Test pick_sbom warns and skips when SBOM file is missing."""
        arch = "x86_64"
        arch_dir = os.path.join(self.temp_dir, arch)
        os.makedirs(arch_dir, exist_ok=True)

        with self.assertLogs('root', level='WARNING') as cm:
            pick_sbom("foo-1.0-1.el9.x86_64.rpm", arch)

        self.assertTrue(
            any("not found" in msg for msg in cm.output),
            f"Expected warning about missing SBOM, got: {cm.output}"
        )
        mock_symlink.assert_not_called()

    @patch('gather_rpms.symlink')
    def test_pick_sbom_src_rpm(self, mock_symlink):
        """Test pick_sbom generates correct SBOM name for src.rpm."""
        arch = "x86_64"
        arch_dir = os.path.join(self.temp_dir, arch)
        os.makedirs(arch_dir, exist_ok=True)

        with open(os.path.join(arch_dir, "test-1.0-1.el9.src.sbom.json"),
                  'w', encoding='utf-8'):
            pass

        pick_sbom("test-1.0-1.el9.src.rpm", arch)

        mock_symlink.assert_called_once_with(
            "test-1.0-1.el9.src.sbom.json", arch)


class TestPickAncestors(unittest.TestCase):
    """Unit tests for pick_ancestors function."""

    def setUp(self):
        """Create temp dir, staging directory, and change CWD before each test."""
        self.temp_dir = tempfile.mkdtemp()
        self.addCleanup(shutil.rmtree, self.temp_dir)
        self.original_cwd = os.getcwd()
        self.addCleanup(os.chdir, self.original_cwd)
        os.makedirs(os.path.join(self.temp_dir, STAGING_DIR), exist_ok=True)
        os.chdir(self.temp_dir)

    def test_pick_ancestors_symlinks_when_exists(self):
        """Test pick_ancestors creates symlink when ancestors.json exists."""
        arch = "x86_64"
        results_dir = os.path.join(self.temp_dir, arch, "results")
        os.makedirs(results_dir, exist_ok=True)

        ancestors_data = [{"uri": "pkg:rpm/test-source@1.0"}]
        with open(os.path.join(results_dir, ANCESTORS_JSON), 'w', encoding='utf-8') as f:
            json.dump(ancestors_data, f)

        pick_ancestors(arch, "test-1.0-1.el9.src.rpm")

        ancestors_link = os.path.join(STAGING_DIR, ANCESTORS_JSON)
        self.assertTrue(os.path.islink(ancestors_link))
        self.assertEqual(
            os.readlink(ancestors_link),
            os.path.join('..', arch, 'results', ANCESTORS_JSON)
        )

    def test_pick_ancestors_warns_when_missing(self):
        """Test pick_ancestors warns when ancestors.json is missing."""
        arch = "x86_64"
        results_dir = os.path.join(self.temp_dir, arch, "results")
        os.makedirs(results_dir, exist_ok=True)

        with self.assertLogs('root', level='WARNING') as cm:
            pick_ancestors(arch, "test-1.0-1.el9.src.rpm")

        self.assertTrue(
            any(ANCESTORS_JSON in msg and "Missing" in msg for msg in cm.output),
            f"Expected warning about missing {ANCESTORS_JSON}, got: {cm.output}"
        )

        ancestors_link = os.path.join(STAGING_DIR, ANCESTORS_JSON)
        self.assertFalse(os.path.exists(ancestors_link))


class TestHandleArchdirIntegration(unittest.TestCase):
    """
    Integration tests for handle_archdir with new buildroot functionality.
    """

    def setUp(self):
        """Reset global state and create temp directories before each test."""
        gather_rpms.buildroots.clear()
        gather_rpms.broot_arch_rpms.clear()
        gather_rpms.srpm = None
        gather_rpms.rpms = {}
        gather_rpms.noarch_rpms = []
        gather_rpms.source_archs = {}
        gather_rpms.logs = []
        self.temp_dir = tempfile.mkdtemp()
        self.original_cwd = os.getcwd()
        # Create staging directory in temp dir
        self.staging_dir = os.path.join(self.temp_dir, STAGING_DIR)
        os.makedirs(self.staging_dir, exist_ok=True)
        # Change to temp directory
        os.chdir(self.temp_dir)

    def tearDown(self):
        """Clean up temp directory and restore cwd."""
        os.chdir(self.original_cwd)
        if os.path.exists(self.temp_dir):
            shutil.rmtree(self.temp_dir)

    @patch('gather_rpms.pick_ancestors')
    @patch('gather_rpms.symlink')
    @patch('gather_rpms.pick_sbom')
    @patch('gather_rpms.prepare_koji_broot')
    def test_handle_archdir_tracks_rpms(
            self, mock_prepare_koji_broot, _mock_pick_sbom,
            _mock_symlink, mock_pick_ancestors):
        """Test that handle_archdir tracks RPMs and calls prepare_koji_broot."""

        arch = "x86_64"
        pipeline_id = "test-pipeline-123"

        # Create arch directory with RPM files
        arch_dir = os.path.join(self.temp_dir, arch)
        os.makedirs(arch_dir, exist_ok=True)

        for f in ["foo-1.0-1.el9.x86_64.rpm", "bar-2.0-1.el9.x86_64.rpm",
                   "test-1.0-1.el9.src.rpm", "build.log"]:
            with open(os.path.join(arch_dir, f), 'w', encoding='utf-8'):
                pass

        handle_archdir(arch, pipeline_id)

        # Verify prepare_koji_broot was called
        mock_prepare_koji_broot.assert_called_once_with(
            "x86_64",
            "test-pipeline-123",
            lockfile_path=os.path.join("x86_64", "results", "buildroot_lock.json")
        )

        # Verify pick_ancestors was called for the SRPM
        mock_pick_ancestors.assert_called_once_with(
            "x86_64", "test-1.0-1.el9.src.rpm")

        # Verify broot_arch_rpms was populated
        self.assertIn("x86_64", gather_rpms.broot_arch_rpms)
        self.assertEqual(len(gather_rpms.broot_arch_rpms["x86_64"]["filelist"]), 3)
        self.assertIn("foo-1.0-1.el9.x86_64.rpm", gather_rpms.broot_arch_rpms["x86_64"]["filelist"])
        self.assertIn("bar-2.0-1.el9.x86_64.rpm", gather_rpms.broot_arch_rpms["x86_64"]["filelist"])
        self.assertIn("test-1.0-1.el9.src.rpm", gather_rpms.broot_arch_rpms["x86_64"]["filelist"])

        # Verify lockfile path is absolute and correct
        lockfile = gather_rpms.broot_arch_rpms["x86_64"]["lockfile"]
        self.assertTrue(os.path.isabs(lockfile), f"lockfile path should be absolute: {lockfile}")
        expected_lockfile = os.path.join(self.temp_dir, "x86_64", "results", "buildroot_lock.json")
        self.assertEqual(lockfile, expected_lockfile)

    @patch('gather_rpms.pick_ancestors')
    @patch('gather_rpms.symlink')
    @patch('gather_rpms.pick_sbom')
    @patch('gather_rpms.prepare_koji_broot')
    def test_handle_archdir_empty_directory(
            self, mock_prepare_koji_broot, _mock_pick_sbom,
            _mock_symlink, _mock_pick_ancestors):
        """Test handle_archdir with empty directory."""

        arch = "aarch64"
        pipeline_id = "test-pipeline-456"

        # Create empty arch directory
        os.makedirs(os.path.join(self.temp_dir, arch), exist_ok=True)

        handle_archdir(arch, pipeline_id)

        # Verify prepare_koji_broot was not called
        mock_prepare_koji_broot.assert_not_called()

        # Verify broot_arch_rpms was not populated
        self.assertNotIn("aarch64", gather_rpms.broot_arch_rpms)

    @patch('gather_rpms.pick_ancestors')
    @patch('gather_rpms.symlink')
    @patch('gather_rpms.pick_sbom')
    @patch('gather_rpms.prepare_koji_broot')
    def test_handle_archdir_logs_only_no_rpms(
            self, mock_prepare_koji_broot, _mock_pick_sbom,
            mock_symlink, _mock_pick_ancestors):
        """Test handle_archdir skips logs when arch has no RPMs.

        This happens with noarch packages built on multiple architectures:
        the first arch claims all noarch RPMs, leaving subsequent arch
        directories with only log files and no RPMs.
        """
        pipeline_id = "test-pipeline-789"

        # Simulate the first arch claiming the noarch RPMs
        first_arch = "aarch64"
        os.makedirs(os.path.join(self.temp_dir, first_arch), exist_ok=True)
        for f in ["foo-1.0-1.fc42.noarch.rpm", "foo-1.0-1.fc42.src.rpm", "build.log"]:
            with open(os.path.join(self.temp_dir, first_arch, f), 'w', encoding='utf-8'):
                pass
        handle_archdir(first_arch, pipeline_id)
        self.assertEqual(len(gather_rpms.logs), 1)
        mock_symlink.reset_mock()

        # Second arch has the same noarch RPMs (already claimed) plus logs
        second_arch = "x86_64"
        os.makedirs(os.path.join(self.temp_dir, second_arch), exist_ok=True)
        for f in ["foo-1.0-1.fc42.noarch.rpm", "foo-1.0-1.fc42.src.rpm", "build.log"]:
            with open(os.path.join(self.temp_dir, second_arch, f), 'w', encoding='utf-8'):
                pass
        handle_archdir(second_arch, pipeline_id)

        # x86_64 should not have a buildroot since all its RPMs were duplicates
        self.assertNotIn("x86_64", gather_rpms.broot_arch_rpms)
        mock_prepare_koji_broot.assert_called_once()

        # Logs from x86_64 should NOT be collected since no RPMs were new
        self.assertEqual(len(gather_rpms.logs), 1)
        self.assertEqual(gather_rpms.logs[0], ("aarch64", "build.log"))

        # No symlinks should have been created for x86_64
        mock_symlink.assert_not_called()


class TestParseCustomUserMetadata(unittest.TestCase):
    """Unit tests for parse_custom_user_metadata function."""

    def test_valid_object(self):
        """Test with valid JSON object."""
        result = gather_rpms.parse_custom_user_metadata('{"mr_iid": 496, "key": "value"}')
        self.assertEqual(result, {"mr_iid": 496, "key": "value"})

    def test_none_value(self):
        """Test with None value."""
        result = gather_rpms.parse_custom_user_metadata(None)
        self.assertIsNone(result)

    def test_empty_string(self):
        """Test with empty string."""
        result = gather_rpms.parse_custom_user_metadata("")
        self.assertIsNone(result)

    def test_whitespace_only(self):
        """Test with whitespace-only string."""
        result = gather_rpms.parse_custom_user_metadata("   ")
        self.assertIsNone(result)

    def test_empty_object(self):
        """Test with empty JSON object - returns falsy dict."""
        result = gather_rpms.parse_custom_user_metadata("{}")
        self.assertIsNone(result)

    def test_invalid_json_raises(self):
        """Test that invalid JSON raises ArgumentTypeError."""
        with self.assertRaises(ArgumentTypeError) as cm:
            gather_rpms.parse_custom_user_metadata("{bad")
        self.assertIn("not valid JSON", str(cm.exception))

    def test_json_array_raises(self):
        """Test that JSON array raises ArgumentTypeError."""
        with self.assertRaises(ArgumentTypeError) as cm:
            gather_rpms.parse_custom_user_metadata("[1, 2, 3]")
        self.assertIn("must be a JSON object", str(cm.exception))

    def test_json_string_raises(self):
        """Test that JSON string raises ArgumentTypeError."""
        with self.assertRaises(ArgumentTypeError) as cm:
            gather_rpms.parse_custom_user_metadata('"string"')
        self.assertIn("must be a JSON object", str(cm.exception))

    def test_json_number_raises(self):
        """Test that JSON number raises ArgumentTypeError."""
        with self.assertRaises(ArgumentTypeError) as cm:
            gather_rpms.parse_custom_user_metadata('42')
        self.assertIn("must be a JSON object", str(cm.exception))


class TestCreateMdFile(unittest.TestCase):
    """Unit tests for create_md_file function."""

    def setUp(self):
        """Set up test environment."""
        self.temp_dir = tempfile.mkdtemp()
        self.original_dir = os.getcwd()
        os.chdir(self.temp_dir)

        # Create staging directory
        os.makedirs(STAGING_DIR)
        os.makedirs(os.path.join(STAGING_DIR, "x86_64"))

        # Reset global variables
        gather_rpms.srpm = "test-1-1.fc42.src.rpm"
        gather_rpms.rpms = {"x86_64": ["test-1-1.fc42.x86_64.rpm"]}
        gather_rpms.noarch_rpms = ["test-noarch-1-1.fc42.noarch.rpm"]
        gather_rpms.source_archs = {
            "test-1-1.fc42.src.rpm": "x86_64",
            "test-noarch-1-1.fc42.noarch.rpm": "x86_64"
        }
        gather_rpms.logs = [("x86_64", "build.log")]
        gather_rpms.buildroots = {
            "x86_64": {
                "content_generator": {"name": "konflux", "version": "0.1"},
                "container": {"type": "docker", "arch": "x86_64"},
                "host": {"os": "RHEL", "arch": "x86_64"},
                "components": [],
                "tools": [],
                "extra": {"konflux": {"pipeline_id": "test/pipeline-123"}},
            }
        }

        # Create dummy RPM files in staging
        for rpm in [gather_rpms.srpm, "test-noarch-1-1.fc42.noarch.rpm"]:
            with open(os.path.join(STAGING_DIR, rpm), 'wb') as f:
                f.write(b'dummy')
        for rpm in gather_rpms.rpms["x86_64"]:
            with open(os.path.join(STAGING_DIR, rpm), 'wb') as f:
                f.write(b'dummy')
        # Create dummy log file
        with open(os.path.join(STAGING_DIR, "x86_64", "build.log"), 'w', encoding='utf-8') as f:
            f.write("test log")

    def tearDown(self):
        """Clean up test environment."""
        os.chdir(self.original_dir)
        shutil.rmtree(self.temp_dir)
        gather_rpms.srpm = None
        gather_rpms.rpms.clear()
        gather_rpms.noarch_rpms.clear()
        gather_rpms.source_archs.clear()
        gather_rpms.logs.clear()
        gather_rpms.buildroots.clear()

    @patch('gather_rpms.calc_checksum')
    @patch('gather_rpms.koji.get_header_fields')
    def test_custom_user_metadata_present(self, mock_get_header, mock_checksum):
        """Test that custom_user_metadata is added when provided."""
        mock_get_header.return_value = {
            'name': 'test', 'version': '1', 'release': '1.fc42',
            'epoch': None, 'arch': 'x86_64'
        }
        mock_checksum.return_value = 'deadbeef'

        options = Namespace(
            pipeline_id="test/pipeline-123",
            source_url="git+https://example.com/repo#abc123",
            start_time=1234567890,
            end_time=1234567900,
            owner=None,
            custom_user_metadata={"mr_iid": 496, "target_branch": "rhel-9.6.0"}
        )

        gather_rpms.create_md_file(options, extra_metadata=None)

        # Read the generated file
        cg_import_path = os.path.join(STAGING_DIR, gather_rpms.CG_IMPORT_JSON)
        with open(cg_import_path, 'r', encoding='utf-8') as f:
            md = json.load(f)

        # Verify custom_user_metadata is present at the right level
        self.assertIn("custom_user_metadata", md["build"]["extra"])
        self.assertEqual(md["build"]["extra"]["custom_user_metadata"], {
            "mr_iid": 496,
            "target_branch": "rhel-9.6.0"
        })

        # Verify it's NOT inside _export_source
        self.assertNotIn("custom_user_metadata", md["build"]["extra"]["_export_source"])

        # Verify _export_source still has its normal keys
        self.assertIn("_export_source", md["build"]["extra"])
        self.assertEqual(md["build"]["extra"]["_export_source"]["source"], "konflux")

    @patch('gather_rpms.calc_checksum')
    @patch('gather_rpms.koji.get_header_fields')
    def test_custom_user_metadata_absent(self, mock_get_header, mock_checksum):
        """Test that custom_user_metadata is omitted when not provided."""
        mock_get_header.return_value = {
            'name': 'test', 'version': '1', 'release': '1.fc42',
            'epoch': None, 'arch': 'x86_64'
        }
        mock_checksum.return_value = 'deadbeef'

        options = Namespace(
            pipeline_id="test/pipeline-123",
            source_url="git+https://example.com/repo#abc123",
            start_time=1234567890,
            end_time=1234567900,
            owner=None
            # no custom_user_metadata attribute
        )

        gather_rpms.create_md_file(options, extra_metadata=None)

        # Read the generated file
        cg_import_path = os.path.join(STAGING_DIR, gather_rpms.CG_IMPORT_JSON)
        with open(cg_import_path, 'r', encoding='utf-8') as f:
            md = json.load(f)

        # Verify custom_user_metadata is NOT present
        self.assertNotIn("custom_user_metadata", md["build"]["extra"])

        # Verify _export_source is still present and unchanged
        self.assertIn("_export_source", md["build"]["extra"])
        self.assertEqual(md["build"]["extra"]["_export_source"]["source"], "konflux")

    @patch('gather_rpms.calc_checksum')
    @patch('gather_rpms.koji.get_header_fields')
    def test_custom_user_metadata_none(self, mock_get_header, mock_checksum):
        """Test that custom_user_metadata is omitted when None."""
        mock_get_header.return_value = {
            'name': 'test', 'version': '1', 'release': '1.fc42',
            'epoch': None, 'arch': 'x86_64'
        }
        mock_checksum.return_value = 'deadbeef'

        options = Namespace(
            pipeline_id="test/pipeline-123",
            source_url="git+https://example.com/repo#abc123",
            start_time=1234567890,
            end_time=1234567900,
            owner=None,
            custom_user_metadata=None
        )

        gather_rpms.create_md_file(options, extra_metadata=None)

        # Read the generated file
        cg_import_path = os.path.join(STAGING_DIR, gather_rpms.CG_IMPORT_JSON)
        with open(cg_import_path, 'r', encoding='utf-8') as f:
            md = json.load(f)

        # Verify custom_user_metadata is NOT present
        self.assertNotIn("custom_user_metadata", md["build"]["extra"])

    @patch('gather_rpms.calc_checksum')
    @patch('gather_rpms.koji.get_header_fields')
    def test_custom_and_extra_metadata_coexist(
            self, mock_get_header, mock_checksum):
        """Test that custom_user_metadata and extra_metadata both work."""
        mock_get_header.return_value = {
            'name': 'test', 'version': '1', 'release': '1.fc42',
            'epoch': None, 'arch': 'x86_64'
        }
        mock_checksum.return_value = 'deadbeef'

        options = Namespace(
            pipeline_id="test/pipeline-123",
            source_url="git+https://example.com/repo#abc123",
            start_time=1234567890,
            end_time=1234567900,
            owner=None,
            custom_user_metadata={"mr_iid": 496}
        )

        # extra_metadata simulates the KOJI_BUILDROOT_METADATA_FILE content
        extra_metadata = {
            "repo_id": 123456,
            "buildroot_tag": "rhel-9.6.0-build",
            "event_id": 789
        }

        gather_rpms.create_md_file(options, extra_metadata=extra_metadata)

        # Read the generated file
        cg_import_path = os.path.join(STAGING_DIR, gather_rpms.CG_IMPORT_JSON)
        with open(cg_import_path, 'r', encoding='utf-8') as f:
            md = json.load(f)

        # Verify custom_user_metadata is at top level of extra
        self.assertIn("custom_user_metadata", md["build"]["extra"])
        self.assertEqual(md["build"]["extra"]["custom_user_metadata"], {"mr_iid": 496})

        # Verify extra_metadata keys are in _export_source
        self.assertEqual(md["build"]["extra"]["_export_source"]["repo_id"], 123456)
        self.assertEqual(md["build"]["extra"]["_export_source"]["buildroot_tag"],
                         "rhel-9.6.0-build")
        self.assertEqual(md["build"]["extra"]["_export_source"]["event_id"], 789)


if __name__ == "__main__":
    unittest.main()
