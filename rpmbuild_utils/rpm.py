#!/usr/bin/python3
"""Utility functions for RPM package operations.

This module provides common utilities for RPM-related operations including:
- RPM spec file discovery and parsing
- Architecture-specific tag extraction from spec files
- Source file extraction from spec files
"""

import logging
import os

from norpm.macrofile import system_macro_registry
from norpm.specfile import specfile_expand, ParserHooks
from norpm.overrides import override_macro_registry
from norpm.exceptions import NorpmError


def create_macro_registry(macro_overrides=None, database=None, target=None):
    """Create and configure a norpm macro registry for spec file parsing.

    :param macro_overrides: Optional dictionary of macros to set in registry
    :type macro_overrides: dict or None
    :param database: Optional path to JSON file with RPM macro overrides
    :type database: str or None
    :param target: Optional distribution target (e.g., 'fedora-rawhide', 'rhel-10')
    :type target: str or None
    :returns: Configured macro registry
    :rtype: MacroRegistry
    """
    registry = system_macro_registry()

    # Apply macro overrides from database if provided
    if database and target:
        registry = override_macro_registry(registry, database, target)

    # Apply custom macro overrides
    if macro_overrides:
        for key, value in macro_overrides.items():
            registry[key] = value

    # Apply norpm hacks for easier spec file parsing
    registry.known_norpm_hacks()

    return registry


def search_specfile(src_dir):
    """Search for a specfile in the given source directory.

    :param src_dir: Source directory to search in
    :type src_dir: str
    :returns: Path to the specfile if found
    :rtype: str
    :raises FileNotFoundError: If no specfile found
    :raises OSError: If multiple specfiles found
    """
    specfiles = []
    for root, _, files in os.walk(src_dir):
        for file in files:
            if file.endswith(".spec"):
                specfiles.append(os.path.join(root, file))
    if len(specfiles) == 0:
        raise FileNotFoundError(f"No specfile found in {src_dir}")
    if len(specfiles) > 1:
        raise OSError(f"Multiple specfiles found: {specfiles}")
    return specfiles[0]


def get_arches(name, tags):
    """Evaluate architecture tags as a set.

    Evaluates %{exclusivearch|excludearch|buildarch} as a list of architectures.

    :param name: Tag name (lowercase: 'exclusivearch', 'excludearch', or 'buildarch')
    :type name: str
    :param tags: Dictionary of tags captured from spec file parsing
    :type tags: dict
    :returns: Set of architecture names
    :rtype: set
    """
    name_map = {
        'exclusivearch': 'ExclusiveArch',
        'excludearch': 'ExcludeArch',
        'buildarch': 'BuildArch',
    }
    values = tags.get(name, set())
    unknown = " ".join([x for x in values if x.startswith("%")])
    if unknown:
        print(f"Unknown macros in {name_map[name]}: {unknown}")
        return set()
    return set(values)


class TagHooks(ParserHooks):
    """Gather access to spec tags during parsing."""

    def __init__(self):
        """Initialize TagHooks with empty tags dictionary."""
        self.tags = {}

    def tag_found(self, name, value, _tag_raw):
        """Gather ExclusiveArch, ExcludeArch and BuildArch tags.

        :param name: Tag name (lowercase)
        :type name: str
        :param value: Expanded tag value
        :type value: str
        :param _tag_raw: Raw tag value (unused)
        :type _tag_raw: str
        """
        if name not in ["exclusivearch", "excludearch", "buildarch"]:
            return
        if name not in self.tags:
            self.tags[name] = set()
        # even multiple exclu*arch statements are accepted
        self.tags[name].update(value.split())


def get_arch_specific_tags(specfile, database, target):
    """Parse specfile and read architecture-specific tags.

    Parse given specfile (against macros from TARGET) and read ExclusiveArch,
    ExcludeArch and BuildArch statements.

    :param specfile: Path to the specfile
    :type specfile: str
    :param database: Path to JSON file with RPM macro overrides
    :type database: str
    :param target: Distribution target (e.g., 'fedora-rawhide', 'rhel-10')
    :type target: str
    :returns: Dictionary with 'exclusivearch', 'excludearch', 'buildarch' as keys,
              each containing a set of architecture names
    :rtype: dict
    """
    registry = create_macro_registry(
        # Clear %dist to avoid lua issues
        macro_overrides={
            "dist": ""
        },
        database=database, target=target)
    tags = TagHooks()
    try:
        with open(specfile, "r", encoding="utf8") as fd:
            specfile_expand(fd.read(), registry, tags)
    except NorpmError as err:
        print("WARNING: Building for all architectures since "
              f"the spec file parser failed: failed: {err}")

    arches = {}
    for name in ['exclusivearch', 'excludearch', 'buildarch']:
        arches[name] = get_arches(name, tags.tags)
    return arches


class SourceHooks(ParserHooks):
    """Capture Source tags from spec file parsing."""

    def __init__(self, srcdir):
        """Initialize SourceHooks.

        :param srcdir: Source directory for resolving filenames
        :type srcdir: str
        """
        self.sources = {}
        self.srcdir = srcdir

    def tag_found(self, name, value, _tag_raw):
        """Capture Source tags during spec file parsing.

        :param name: Tag name (lowercase)
        :type name: str
        :param value: Expanded tag value
        :type value: str
        :param _tag_raw: Raw tag value (unused)
        :type _tag_raw: str
        """
        # Match source0, source1, etc. (name is lowercased by norpm)
        if name.startswith("source"):
            source_num = name[6:] if len(name) > 6 else "0"
            self.sources[source_num] = value


def parse_spec_source_tags(specfile, srcdir=".", database=None, target=None):
    """Parse Source tags from specfile using SourceHooks.

    :param specfile: Path to the specfile
    :type specfile: str
    :param srcdir: Source directory for resolving filenames
    :type srcdir: str
    :param database: Optional path to JSON file with RPM macro overrides
    :type database: str or None
    :param target: Optional distribution target (e.g., 'fedora-rawhide', 'rhel-10')
    :type target: str or None
    :returns: Dictionary mapping source number to location (e.g., {"0": "https://...", "1": "patch.tar.gz"})
    :rtype: dict
    """
    # Set up macro registry with _sourcedir macro
    registry = create_macro_registry(
        macro_overrides={"_sourcedir": srcdir},
        database=database,
        target=target
    )

    # Parse spec file with SourceHooks
    hooks = SourceHooks(srcdir)
    try:
        with open(specfile, "r", encoding="utf-8") as fd:
            specfile_expand(fd.read(), registry, hooks)
    except NorpmError as err:
        logging.error("Failed to parse spec file %s: %s", specfile, err)
        raise
    return hooks.sources
