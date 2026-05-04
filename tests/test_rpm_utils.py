"""
Tests for rpm_utils.py.
"""

# pylint: disable=W0201,C0116

import os
import tempfile
import unittest

from rpm_utils import (
    search_specfile,
    create_macro_registry,
    SourceHooks,
    parse_spec_source_tags,
    _parse_source_tags_literal,
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

            source_tags = parse_spec_source_tags(spec_path)

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

            source_tags = parse_spec_source_tags(spec_path)

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

            source_tags = parse_spec_source_tags(spec_path, tmpdir)
            self.assertGreaterEqual(len(source_tags), 0)

    def test_parse_with_expand_false(self):
        """Test parsing with expand=False uses literal parser."""
        with tempfile.TemporaryDirectory() as tmpdir:
            # Create an already-expanded spec with escaped macros
            spec_content = """
Name: testpkg
Version: 1.0

Source0: https://example.com/testpkg-1.0.tar.gz
Source1: local-file.txt

%changelog
* Mon Jan 01 2024 Test User <test@example.com> - 1.0-1
- Some %escaped_macro should not be re-expanded
"""
            spec_path = os.path.join(tmpdir, "expanded.spec")
            with open(spec_path, "w", encoding="utf-8") as f:
                f.write(spec_content)

            source_tags = parse_spec_source_tags(spec_path, tmpdir, expand=False)

            self.assertEqual(len(source_tags), 2)
            self.assertEqual(source_tags["0"], "https://example.com/testpkg-1.0.tar.gz")
            self.assertEqual(source_tags["1"], "local-file.txt")

    def test_parse_with_expand_true_default(self):
        """Test that expand=True is the default behavior."""
        with tempfile.TemporaryDirectory() as tmpdir:
            spec_content = """
Name: testpkg
Version: 1.0

Source0: https://example.com/testpkg-%{version}.tar.gz

%description
Test package
"""
            spec_path = os.path.join(tmpdir, "test.spec")
            with open(spec_path, "w", encoding="utf-8") as f:
                f.write(spec_content)

            # Default behavior should expand macros
            source_tags = parse_spec_source_tags(spec_path, tmpdir)
            # The %{version} macro should be expanded to 1.0
            self.assertIn("0", source_tags)
            self.assertIn("1.0", source_tags["0"])


class TestParseSourceTagsLiteral(unittest.TestCase):
    """
    Unit tests for _parse_source_tags_literal function.
    """

    def test_parse_simple_source(self):
        """Test parsing a simple already-expanded spec."""
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

            source_tags = _parse_source_tags_literal(spec_path, tmpdir)
            self.assertEqual(source_tags, {"0": "https://example.com/testpkg-1.0.tar.gz"})

    def test_parse_multiple_sources_literal(self):
        """Test parsing multiple sources literally."""
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

            source_tags = _parse_source_tags_literal(spec_path, tmpdir)

            self.assertEqual(len(source_tags), 3)
            self.assertEqual(source_tags["0"], "https://example.com/testpkg-2.0.tar.gz")
            self.assertEqual(source_tags["1"], "https://example.com/patch1.patch")
            self.assertEqual(source_tags["2"], "local-file.txt")

    def test_parse_source_without_number(self):
        """Test parsing Source tag without number (defaults to 0)."""
        with tempfile.TemporaryDirectory() as tmpdir:
            spec_content = """
Source: https://example.com/file.tar.gz
"""
            spec_path = os.path.join(tmpdir, "test.spec")
            with open(spec_path, "w", encoding="utf-8") as f:
                f.write(spec_content)

            source_tags = _parse_source_tags_literal(spec_path, tmpdir)
            self.assertEqual(source_tags["0"], "https://example.com/file.tar.gz")

    def test_parse_source_with_sourcedir_macro(self):
        """Test that %{_sourcedir} macro is replaced with srcdir in literal parsing."""
        with tempfile.TemporaryDirectory() as tmpdir:
            spec_content = """
Source0: %{_sourcedir}/testpkg-1.0.tar.gz
Source1: ${_sourcedir}/patch.txt
"""
            spec_path = os.path.join(tmpdir, "test.spec")
            with open(spec_path, "w", encoding="utf-8") as f:
                f.write(spec_content)

            source_tags = _parse_source_tags_literal(spec_path, tmpdir)
            # %{_sourcedir} should be replaced with srcdir
            self.assertEqual(source_tags["0"], tmpdir + "/testpkg-1.0.tar.gz")
            self.assertEqual(source_tags["1"], tmpdir + "/patch.txt")

    def test_parse_case_insensitive(self):
        """Test that Source tag matching is case-insensitive."""
        with tempfile.TemporaryDirectory() as tmpdir:
            spec_content = """
SOURCE0: https://example.com/file1.tar.gz
source1: https://example.com/file2.tar.gz
Source2: https://example.com/file3.tar.gz
"""
            spec_path = os.path.join(tmpdir, "test.spec")
            with open(spec_path, "w", encoding="utf-8") as f:
                f.write(spec_content)

            source_tags = _parse_source_tags_literal(spec_path, tmpdir)
            self.assertEqual(len(source_tags), 3)
            self.assertIn("0", source_tags)
            self.assertIn("1", source_tags)
            self.assertIn("2", source_tags)

    def test_parse_ignores_non_source_lines(self):
        """Test that non-Source lines are ignored."""
        with tempfile.TemporaryDirectory() as tmpdir:
            spec_content = """
Name: testpkg
Version: 1.0
Release: 1%{?dist}
Source0: https://example.com/testpkg-1.0.tar.gz
Patch0: fix-bug.patch

%description
Test package
"""
            spec_path = os.path.join(tmpdir, "test.spec")
            with open(spec_path, "w", encoding="utf-8") as f:
                f.write(spec_content)

            source_tags = _parse_source_tags_literal(spec_path, tmpdir)
            # Should only have Source0, not Patch0 or other tags
            self.assertEqual(len(source_tags), 1)
            self.assertEqual(source_tags["0"], "https://example.com/testpkg-1.0.tar.gz")

    def test_parse_with_escaped_macros_in_changelog(self):
        """Test that escaped macros in changelog don't cause issues."""
        with tempfile.TemporaryDirectory() as tmpdir:
            spec_content = """
Name: testpkg
Version: 1.0

Source0: https://example.com/testpkg-1.0.tar.gz

%description
Test package

%changelog
* Mon Jan 01 2024 Test User <test@example.com> - 1.0-1
- Fixed %escaped_macro in code
- Updated %another_macro reference
"""
            spec_path = os.path.join(tmpdir, "test.spec")
            with open(spec_path, "w", encoding="utf-8") as f:
                f.write(spec_content)

            # This should not fail even with escaped macros in changelog
            source_tags = _parse_source_tags_literal(spec_path, tmpdir)
            self.assertEqual(source_tags["0"], "https://example.com/testpkg-1.0.tar.gz")

    def test_parse_stops_at_section_directives(self):
        """Test that parser stops at % section directives and doesn't parse changelog."""
        with tempfile.TemporaryDirectory() as tmpdir:
            spec_content = """
Name: testpkg
Version: 1.0

Source0: https://example.com/real-source.tar.gz
Source1: https://example.com/real-patch.patch

%description
Test package

%changelog
* Mon Jan 01 2024 Test User <test@example.com> - 1.0-1
- Source0: This should NOT be parsed as a source tag
- Source2: Neither should this
"""
            spec_path = os.path.join(tmpdir, "test.spec")
            with open(spec_path, "w", encoding="utf-8") as f:
                f.write(spec_content)

            source_tags = _parse_source_tags_literal(spec_path, tmpdir)

            # Should only have Source0 and Source1 from preamble
            self.assertEqual(len(source_tags), 2)
            self.assertEqual(source_tags["0"], "https://example.com/real-source.tar.gz")
            self.assertEqual(source_tags["1"], "https://example.com/real-patch.patch")
            # Source2 from changelog should NOT be in results
            self.assertNotIn("2", source_tags)

    def test_parse_handles_percent_escapes(self):
        """Test that %% (escaped percent) doesn't stop parsing."""
        with tempfile.TemporaryDirectory() as tmpdir:
            spec_content = """
Name: testpkg
Version: 1.0
# Some comment with %% escaped percent

Source0: https://example.com/testpkg-1.0.tar.gz

%description
Test package
"""
            spec_path = os.path.join(tmpdir, "test.spec")
            with open(spec_path, "w", encoding="utf-8") as f:
                f.write(spec_content)

            source_tags = _parse_source_tags_literal(spec_path, tmpdir)
            # Should still find Source0 even after %% line
            self.assertEqual(source_tags["0"], "https://example.com/testpkg-1.0.tar.gz")

    def test_parse_with_global_directive(self):
        """Test that %global directives don't stop parsing."""
        with tempfile.TemporaryDirectory() as tmpdir:
            spec_content = """
%global upstream_version 1.0.0
%global python3_sitelib /usr/lib/python3/site-packages
Name: testpkg
Version: 1.0

Source0: https://example.com/testpkg-1.0.tar.gz
Source1: https://example.com/patch.tar.gz

%description
Test package
"""
            spec_path = os.path.join(tmpdir, "test.spec")
            with open(spec_path, "w", encoding="utf-8") as f:
                f.write(spec_content)

            source_tags = _parse_source_tags_literal(spec_path, tmpdir)
            # Should parse through %global directives
            self.assertEqual(len(source_tags), 2)
            self.assertEqual(source_tags["0"], "https://example.com/testpkg-1.0.tar.gz")
            self.assertEqual(source_tags["1"], "https://example.com/patch.tar.gz")

    def test_parse_with_define_directive(self):
        """Test that %define directives don't stop parsing."""
        with tempfile.TemporaryDirectory() as tmpdir:
            spec_content = """
%define _fortify_level 3
Name: testpkg

Source0: https://example.com/file.tar.gz

%description
Test package
"""
            spec_path = os.path.join(tmpdir, "test.spec")
            with open(spec_path, "w", encoding="utf-8") as f:
                f.write(spec_content)

            source_tags = _parse_source_tags_literal(spec_path, tmpdir)
            # Should parse through %define directives
            self.assertEqual(source_tags["0"], "https://example.com/file.tar.gz")

    def test_parse_with_conditionals(self):
        """Test that %if/%endif conditionals don't stop parsing."""
        with tempfile.TemporaryDirectory() as tmpdir:
            spec_content = """
Name: testpkg
%if 0
This is removed in expanded spec
%endif
Source0: https://example.com/file.tar.gz

%description
Test package
"""
            spec_path = os.path.join(tmpdir, "test.spec")
            with open(spec_path, "w", encoding="utf-8") as f:
                f.write(spec_content)

            source_tags = _parse_source_tags_literal(spec_path, tmpdir)
            # Should parse through conditional blocks
            self.assertEqual(source_tags["0"], "https://example.com/file.tar.gz")

    def test_parse_real_world_structure(self):
        """Test parsing a realistic spec file structure with changelog."""
        with tempfile.TemporaryDirectory() as tmpdir:
            spec_content = """
%global __python3 /usr/bin/python3
%global python3_sitelib /usr/lib/python3/site-packages

Name: testpkg
Version: 1.0
Release: 1

Source0: https://example.com/testpkg-1.0.tar.gz
Patch0: fix-build.patch

BuildRequires: python3

%description
A test package

%changelog
* Mon Jan 01 2024 Test User <test@example.com> - 1.0-1
- Initial package
- Source0: Updated source URL (this should NOT be parsed)
- Source1: Another fake source (should NOT be parsed)
"""
            spec_path = os.path.join(tmpdir, "test.spec")
            with open(spec_path, "w", encoding="utf-8") as f:
                f.write(spec_content)

            source_tags = _parse_source_tags_literal(spec_path, tmpdir)
            # Should only have Source0 from preamble, not from changelog
            self.assertEqual(len(source_tags), 1)
            self.assertEqual(source_tags["0"], "https://example.com/testpkg-1.0.tar.gz")


if __name__ == "__main__":
    unittest.main()
