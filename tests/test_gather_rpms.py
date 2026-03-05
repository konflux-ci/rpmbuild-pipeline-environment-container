"""
Tests gather_rpms.py.
"""

# pylint: disable=W0201,C0116,R0801

import json
import os
import shutil
import tempfile
import unittest
from unittest.mock import patch, MagicMock

from gather_rpms import (
    prepare_koji_broot,
    create_broot_arch_rpms_file,
    handle_archdir,
    buildroots,
    broot_arch_rpms,
    STAGING_DIR,
    BROOT_ARCH_RPMS_JSON,
)


class TestPrepareKojiBroot(unittest.TestCase):
    """
    Unit tests for prepare_koji_broot function.
    """

    def setUp(self):
        """Reset global buildroots dict before each test."""
        buildroots.clear()

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
            self.assertIn("x86_64", buildroots)
            buildroot = buildroots["x86_64"]

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
        self.assertIn("aarch64", buildroots)
        buildroot = buildroots["aarch64"]

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
        self.assertIn("ppc64le", buildroots)
        buildroot = buildroots["ppc64le"]

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

            buildroot = buildroots["x86_64"]
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
        broot_arch_rpms.clear()
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
        broot_arch_rpms["x86_64"] = {
            "filelist": ["foo-1.0-1.el9.x86_64.rpm", "bar-2.0-1.el9.x86_64.rpm"],
            "lockfile": "x86_64/results/buildroot_lock.json"
        }
        broot_arch_rpms["aarch64"] = {
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


class TestHandleArchdirIntegration(unittest.TestCase):
    """
    Integration tests for handle_archdir with new buildroot functionality.
    """

    def setUp(self):
        """Reset global state and create temp directories before each test."""
        buildroots.clear()
        broot_arch_rpms.clear()
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

    @patch('gather_rpms.symlink')
    @patch('gather_rpms.pick_sbom')
    @patch('gather_rpms.prepare_koji_broot')
    @patch('gather_rpms.os.path.join')
    @patch('gather_rpms.os.listdir')
    def test_handle_archdir_tracks_rpms(
            self, mock_listdir, mock_join, mock_prepare_koji_broot, _mock_pick_sbom, _mock_symlink):
        """Test that handle_archdir tracks RPMs and calls prepare_koji_broot."""

        arch = "x86_64"
        pipeline_id = "test-pipeline-123"

        # Mock directory contents
        mock_listdir.return_value = [
            "foo-1.0-1.el9.x86_64.rpm",
            "bar-2.0-1.el9.x86_64.rpm",
            "test-1.0-1.el9.src.rpm",
            "build.log"
        ]

        # Mock path join to return expected lockfile path
        def join_side_effect(*args):
            if len(args) == 3 and args[1] == 'results' and args[2] == 'buildroot_lock.json':
                return "x86_64/results/buildroot_lock.json"
            return "/".join(args)

        mock_join.side_effect = join_side_effect

        # Call handle_archdir
        handle_archdir(arch, pipeline_id)

        # Verify prepare_koji_broot was called
        mock_prepare_koji_broot.assert_called_once_with(
            "x86_64",
            "test-pipeline-123",
            lockfile_path="x86_64/results/buildroot_lock.json"
        )

        # Verify broot_arch_rpms was populated
        self.assertIn("x86_64", broot_arch_rpms)
        self.assertEqual(len(broot_arch_rpms["x86_64"]["filelist"]), 3)
        self.assertIn("foo-1.0-1.el9.x86_64.rpm", broot_arch_rpms["x86_64"]["filelist"])
        self.assertIn("bar-2.0-1.el9.x86_64.rpm", broot_arch_rpms["x86_64"]["filelist"])
        self.assertIn("test-1.0-1.el9.src.rpm", broot_arch_rpms["x86_64"]["filelist"])
        self.assertEqual(broot_arch_rpms["x86_64"]["lockfile"], "x86_64/results/buildroot_lock.json")

    @patch('gather_rpms.symlink')
    @patch('gather_rpms.pick_sbom')
    @patch('gather_rpms.prepare_koji_broot')
    @patch('gather_rpms.os.listdir')
    def test_handle_archdir_empty_directory(
            self, mock_listdir, mock_prepare_koji_broot, _mock_pick_sbom, _mock_symlink):
        """Test handle_archdir with empty directory."""

        mock_options = MagicMock()
        mock_options.pipeline_id = "test-pipeline-456"

        # Empty directory
        mock_listdir.return_value = []

        handle_archdir(mock_options, "aarch64")

        # Verify prepare_koji_broot was not called
        mock_prepare_koji_broot.assert_not_called()

        # Verify broot_arch_rpms was not populated
        self.assertNotIn("aarch64", broot_arch_rpms)


if __name__ == "__main__":
    unittest.main()
