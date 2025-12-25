"""
Tests for rpm_utils.py.
"""

# pylint: disable=W0201,C0116

import os
import tempfile
import unittest

from python_scripts.rpm_utils import search_specfile


class TestSearchSpecfile(unittest.TestCase):
    """
    Unit tests for search_specfile function.
    """

    def test_single_specfile_found(self):
        """Test finding a single specfile in a directory."""
        with tempfile.TemporaryDirectory() as tmpdir:
            # Create a specfile
            specfile_path = os.path.join(tmpdir, "test.spec")
            with open(specfile_path, "w", encoding="utf-8") as f:
                f.write("Name: test\n")

            result = search_specfile(tmpdir)
            self.assertEqual(result, specfile_path)

    def test_specfile_in_subdirectory(self):
        """Test finding a specfile in a subdirectory."""
        with tempfile.TemporaryDirectory() as tmpdir:
            # Create a subdirectory with a specfile
            subdir = os.path.join(tmpdir, "subdir")
            os.makedirs(subdir)
            specfile_path = os.path.join(subdir, "package.spec")
            with open(specfile_path, "w", encoding="utf-8") as f:
                f.write("Name: package\n")

            result = search_specfile(tmpdir)
            self.assertEqual(result, specfile_path)

    def test_no_specfile_found(self):
        """Test error when no specfile is found."""
        with tempfile.TemporaryDirectory() as tmpdir:
            # Create a non-spec file
            with open(os.path.join(tmpdir, "README.md"), "w", encoding="utf-8") as f:
                f.write("# Test\n")

            with self.assertRaises(FileNotFoundError) as context:
                search_specfile(tmpdir)
            self.assertIn("No specfile found", str(context.exception))

    def test_multiple_specfiles_found(self):
        """Test error when multiple specfiles are found."""
        with tempfile.TemporaryDirectory() as tmpdir:
            # Create multiple specfiles
            with open(os.path.join(tmpdir, "test1.spec"), "w", encoding="utf-8") as f:
                f.write("Name: test1\n")
            with open(os.path.join(tmpdir, "test2.spec"), "w", encoding="utf-8") as f:
                f.write("Name: test2\n")

            with self.assertRaises(OSError) as context:
                search_specfile(tmpdir)
            self.assertIn("Multiple specfiles found", str(context.exception))

    def test_case_sensitive_extension(self):
        """Test that .spec extension matching is case-sensitive."""
        with tempfile.TemporaryDirectory() as tmpdir:
            # Create files with different case extensions
            spec_path = os.path.join(tmpdir, "test.spec")
            with open(spec_path, "w", encoding="utf-8") as f:
                f.write("Name: test\n")
            # Create a file with uppercase extension
            with open(os.path.join(tmpdir, "other.SPEC"), "w", encoding="utf-8") as f:
                f.write("Name: other\n")

            # Should only find .spec (lowercase)
            result = search_specfile(tmpdir)
            self.assertEqual(result, spec_path)

    def test_empty_directory(self):
        """Test error with empty directory."""
        with tempfile.TemporaryDirectory() as tmpdir:
            with self.assertRaises(FileNotFoundError) as context:
                search_specfile(tmpdir)
            self.assertIn("No specfile found", str(context.exception))

    def test_spec_extension_only(self):
        """Test that files ending with .spec are found."""
        with tempfile.TemporaryDirectory() as tmpdir:
            # Create various files
            specfile_path = os.path.join(tmpdir, "mypackage.spec")
            with open(specfile_path, "w", encoding="utf-8") as f:
                f.write("Name: mypackage\n")
            with open(os.path.join(tmpdir, "specfile.txt"), "w", encoding="utf-8") as f:
                f.write("not a spec\n")
            with open(os.path.join(tmpdir, ".spec.backup"), "w", encoding="utf-8") as f:
                f.write("backup\n")

            result = search_specfile(tmpdir)
            self.assertEqual(result, specfile_path)


if __name__ == "__main__":
    unittest.main()
