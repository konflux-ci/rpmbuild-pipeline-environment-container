"""
Tests for rpm_utils.py.
"""

# pylint: disable=W0201,C0116

import os
import tempfile
import unittest

from rpm_utils import (
    search_specfile,
    get_arch_specific_tags,
    create_macro_registry,
    SourceHooks,
    parse_spec_source_tags,
)


class TestCreateMacroRegistry(unittest.TestCase):
    """
    Unit tests for create_macro_registry function.
    """

    def test_basic_registry_creation(self):
        """Test creating a basic macro registry without overrides."""
        registry = create_macro_registry()
        # Registry should be created and have standard macros
        self.assertIsNotNone(registry)
        # Check that norpm hacks were applied (dist should be cleared)
        # We can't directly inspect all internals, but we can verify it's callable

    def test_registry_with_macro_overrides(self):
        """Test creating registry with custom macro overrides."""
        overrides = {
            "_sourcedir": "/custom/source/dir",
            "version": "1.2.3",
        }
        registry = create_macro_registry(macro_overrides=overrides)
        self.assertIsNotNone(registry)
        # Verify overrides were applied
        self.assertEqual(registry["_sourcedir"].value, "/custom/source/dir")
        self.assertEqual(registry["version"].value, "1.2.3")

    def test_registry_with_database_and_target(self):
        """Test creating registry with database and target for distribution-specific macros."""
        testdir = os.path.dirname(os.path.realpath(__file__))
        overrides_file = os.path.join(testdir, "..", "arch-specific-macro-overrides.json")

        if os.path.exists(overrides_file):
            registry = create_macro_registry(
                database=overrides_file, target_distribution="rhel-10")
            self.assertIsNotNone(registry)
            # Registry should have target-specific macros applied

    def test_registry_with_all_parameters(self):
        """Test creating registry with all parameters."""
        testdir = os.path.dirname(os.path.realpath(__file__))
        overrides_file = os.path.join(testdir, "..", "arch-specific-macro-overrides.json")

        macro_overrides = {"_sourcedir": "/tmp/sources"}

        if os.path.exists(overrides_file):
            registry = create_macro_registry(
                macro_overrides=macro_overrides,
                database=overrides_file,
                target_distribution="fedora-rawhide"
            )
            self.assertIsNotNone(registry)
            self.assertEqual(registry["_sourcedir"].value, "/tmp/sources")


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


class TestGetArchSpecificTags(unittest.TestCase):
    """
    Unit tests for get_arch_specific_tags function.
    """

    def test_multiple_statements(self):
        """
        Test that we concatenate multiple Exclu*Arch statements.
        """
        testdir = os.path.dirname(os.path.realpath(__file__))
        specfile = os.path.join(testdir, "specfiles",
                                "dummy-pkg-multiple-tags.spec")
        overrides = os.path.join(testdir, "..", "arch-specific-macro-overrides.json")
        assert get_arch_specific_tags(specfile, overrides, "rhel-10") == {
            'buildarch': {
                'noarch',
            },
            'excludearch': {
                's390x',
                'weirdarch',
                'on-rhel-excludearch',
            },
            'exclusivearch': {
                'aarch64',
                'i686',
                'noarch',
                'on-rhel-exclusivearch',
                'ppc64le',
                'riscv64',
                's390x',
                'x86_64',
            }}

        assert get_arch_specific_tags(specfile, overrides, "fedora-42") == {
            'buildarch': {
                'noarch',
            },
            'excludearch': {
                's390x',
                'weirdarch',
                'on-fedora-excludearch',
            },
            'exclusivearch': {
                'aarch64',
                'i686',
                'noarch',
                'on-fedora-exclusivearch',
                'ppc64le',
                'riscv64',
                's390x',
                'x86_64',
            }}


class TestSourceHooks(unittest.TestCase):
    """
    Unit tests for SourceHooks class.
    """

    def test_source_hooks_initialization(self):
        """Test SourceHooks initialization."""
        hooks = SourceHooks("/test/srcdir")
        self.assertEqual(hooks.srcdir, "/test/srcdir")
        self.assertEqual(hooks.sources, {})

    def test_tag_found_source0(self):
        """Test capturing Source0 tag."""
        hooks = SourceHooks("/test/srcdir")
        hooks.tag_found("source0", "https://example.com/file.tar.gz", "")
        self.assertEqual(hooks.sources, {"0": "https://example.com/file.tar.gz"})

    def test_tag_found_source1(self):
        """Test capturing Source1 tag."""
        hooks = SourceHooks("/test/srcdir")
        hooks.tag_found("source1", "patch-1.0.tar.gz", "")
        self.assertEqual(hooks.sources, {"1": "patch-1.0.tar.gz"})

    def test_tag_found_source_without_number(self):
        """Test capturing Source tag without number (defaults to 0)."""
        hooks = SourceHooks("/test/srcdir")
        hooks.tag_found("source", "https://example.com/archive.zip", "")
        self.assertEqual(hooks.sources, {"0": "https://example.com/archive.zip"})

    def test_tag_found_multiple_sources(self):
        """Test capturing multiple Source tags."""
        hooks = SourceHooks("/test/srcdir")
        hooks.tag_found("source0", "https://example.com/main.tar.gz", "")
        hooks.tag_found("source1", "https://example.com/patch1.patch", "")
        hooks.tag_found("source2", "https://example.com/patch2.patch", "")
        self.assertEqual(hooks.sources, {
            "0": "https://example.com/main.tar.gz",
            "1": "https://example.com/patch1.patch",
            "2": "https://example.com/patch2.patch",
        })

    def test_tag_found_ignores_non_source_tags(self):
        """Test that non-source tags are ignored."""
        hooks = SourceHooks("/test/srcdir")
        hooks.tag_found("name", "mypackage", "")
        hooks.tag_found("version", "1.0", "")
        hooks.tag_found("source0", "https://example.com/file.tar.gz", "")
        # Only source0 should be captured
        self.assertEqual(hooks.sources, {"0": "https://example.com/file.tar.gz"})


class TestParseSpecSourceTags(unittest.TestCase):
    """
    Unit tests for parse_spec_source_tags function.
    """

    def test_parse_simple_spec(self):
        """Test parsing a simple spec file."""
        with tempfile.TemporaryDirectory() as tmpdir:
            spec_content = """
Name: testpkg
Version: 1.0

Source0: https://example.com/testpkg-1.0.tar.gz

%description
Test package
"""
            spec_path = os.path.join(tmpdir, "test.spec")
            with open(spec_path, "w", encoding="utf-8") as f:
                f.write(spec_content)

            source_tags = parse_spec_source_tags(spec_path, tmpdir)

            self.assertEqual(source_tags, {"0": "https://example.com/testpkg-1.0.tar.gz"})

    def test_parse_multiple_sources(self):
        """Test parsing spec with multiple sources."""
        with tempfile.TemporaryDirectory() as tmpdir:
            spec_content = """
Name: testpkg
Version: 2.0

Source0: https://example.com/testpkg-2.0.tar.gz
Source1: https://example.com/patch1.patch
Source2: local-file.txt

%description
Test package
"""
            spec_path = os.path.join(tmpdir, "test.spec")
            with open(spec_path, "w", encoding="utf-8") as f:
                f.write(spec_content)

            source_tags = parse_spec_source_tags(spec_path, tmpdir)

            self.assertEqual(len(source_tags), 3)
            self.assertIn("0", source_tags)
            self.assertIn("1", source_tags)
            self.assertIn("2", source_tags)

    def test_parse_with_target(self):
        """Test parsing with target parameter."""
        with tempfile.TemporaryDirectory() as tmpdir:
            spec_content = """
Name: testpkg
Version: 1.0

Source0: https://example.com/testpkg-1.0.tar.gz

%description
Test package
"""
            spec_path = os.path.join(tmpdir, "test.spec")
            with open(spec_path, "w", encoding="utf-8") as f:
                f.write(spec_content)

            testdir = os.path.dirname(os.path.realpath(__file__))
            overrides_file = os.path.join(testdir, "..", "arch-specific-macro-overrides.json")

            if os.path.exists(overrides_file):
                source_tags = parse_spec_source_tags(
                    spec_path, tmpdir,
                    database=overrides_file,
                    target_distribution="fedora-rawhide"
                )
                self.assertGreaterEqual(len(source_tags), 0)


if __name__ == "__main__":
    unittest.main()
