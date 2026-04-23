#!/usr/bin/python3
"""Utility functions for SBOM generation and processing.

This module provides common utilities for SBOM-related operations including:
- Package URL (purl) generation for generic and RPM packages
- License conversion from RPM to SPDX format
"""

import logging
import subprocess

from functools import lru_cache

from common_utils import run_command


def get_generic_purl(name, version=None, url=None, checksum=None, alg=None):
    """Generate Package URL (purl) for a source package."""
    purl = f"pkg:generic/{name}"
    if version:
        purl += f"@{version}"
    if url:
        purl += f"?download_url={url}"
    if checksum:
        purl += f"&checksum={alg.lower() if alg else 'sha256'}:{checksum}"
    return purl


def get_rpm_purl(name, version, release, arch, *, epoch=None, namespace="fedora"):
    """Generate Package URL (purl) for an RPM package.

    :param name: Package name
    :type name: str
    :param version: Package version
    :type version: str
    :param release: Package release
    :type release: str
    :param arch: Package architecture
    :type arch: str
    :param epoch: Package epoch (optional)
    :type epoch: str or None
    :param namespace: RPM purl namespace (e.g. "fedora", "redhat")
    :type namespace: str
    :returns: RPM purl string
    :rtype: str
    """
    # Format: pkg:rpm/namespace/name@version-release?arch=...
    version_str = f"{version}-{release}"
    if epoch:
        version_str = f"{epoch}:{version_str}"

    purl = f"pkg:rpm/{namespace}/{name}@{version_str}?arch={arch}"
    return purl


@lru_cache(maxsize=1024)
def _license_validate(rpm_license):
    result = run_command(["license-validate", rpm_license], timeout=5)
    if result.returncode == 0:
        return result.stdout
    return None


@lru_cache(maxsize=1024)
def _license_fedora2spdx(rpm_license):
    return run_command(["license-fedora2spdx", rpm_license], timeout=5).stdout


def to_spdx_license(rpm_license):
    """Convert RPM license to SPDX license expression using license-fedora2spdx.

    :param rpm_license: RPM license string
    :type rpm_license: str
    :returns: SPDX license expression, or "NOASSERTION" if conversion fails
    :rtype: str
    """
    if not rpm_license:
        return "NOASSERTION"

    try:
        result = _license_validate(rpm_license)
        if result is not None:
            logging.debug("Valid SPDX license '%s'", rpm_license)
            return rpm_license

        result = _license_fedora2spdx(rpm_license)
        if result == '':
            logging.warning("[CRITICAL] license-fedora2spdx returned empty output for license '%s'", rpm_license)
            return "NOASSERTION"

        lines = result.splitlines()
        spdx_license = lines[0].strip()
        if not spdx_license:
            logging.warning("[CRITICAL] license-fedora2spdx returned blank first line for license '%s'", rpm_license)
            return "NOASSERTION"

        if len(lines) > 1:
            logging.warning(
                "[IMPORTANT] license-fedora2spdx returned some important notes for license '%s':\n%s",
                rpm_license, result.stdout)

        if spdx_license != rpm_license:
            logging.debug("Converted RPM license '%s' to SPDX license '%s'", rpm_license, spdx_license)
        return spdx_license
    except (subprocess.CalledProcessError, subprocess.TimeoutExpired, FileNotFoundError) as e:
        logging.warning("[CRITICAL] Failed to convert license '%s' to SPDX: %s", rpm_license, e)
        return "NOASSERTION"
