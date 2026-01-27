#!/usr/bin/python3
"""Utility functions for RPM package operations.

This module provides common utilities for RPM-related operations including:
- RPM spec file discovery and parsing
- Source file extraction from spec files
"""

import logging
import os

from specfile import Specfile

from common_utils import run_command


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


def parse_spec_source_tags(specfile):
    """Parse Source tags from specfile using python-specfile.

    :param specfile: Path to the specfile
    :type specfile: str
    :returns: Dictionary mapping source number to location (e.g., {"0": "https://...", "1": "patch.tar.gz"})
    :rtype: dict
    """
    try:
        spec = Specfile(specfile)
        sources_dict = {}

        with spec.sources() as sources:
            for source in sources:
                # Convert number to string for consistency with previous implementation
                source_num = str(source.number)
                # Expand macros in the location
                expanded_location = spec.expand(source.location)
                sources_dict[source_num] = expanded_location

        return sources_dict
    except Exception as err:
        logging.error("Failed to parse spec file %s: %s", specfile, err)
        raise


def get_rpm_license(rpm_path):
    """Extract license from RPM header.

    :param rpm_path: Path to RPM file
    :type rpm_path: str
    :returns: License string from RPM header
    :rtype: str
    """
    result = run_command(["rpm", "-qp", "--qf", "%{LICENSE}", rpm_path])
    return result.stdout.strip()
