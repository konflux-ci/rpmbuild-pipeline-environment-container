#!/usr/bin/python3
"""Utility functions for SBOM generation and processing.

This module provides common utilities for SBOM-related operations including:
- Package URL (purl) generation for generic and RPM packages
- License conversion from RPM to SPDX format
"""

import enum
import logging
import subprocess  # nosec B404 - subprocess needed for RPM query operations
from functools import lru_cache

from common_utils import run_command

# Timeout for license validation/conversion tools (seconds)
_LICENSE_TOOL_TIMEOUT = 15


class _Validity(enum.Enum):
    """Outcome of validating a license expression."""
    VALID = "valid"        # parses as a Fedora/SPDX license expression
    INVALID = "invalid"    # does not parse - may be a legacy Fedora short name
    UNKNOWN = "unknown"    # validator unavailable or broken - cannot tell


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

    purl = f"pkg:rpm/{namespace}/{name}@{version_str}?arch={arch}"
    if epoch and str(epoch) != "0":
        purl += f"&epoch={epoch}"
    return purl


@lru_cache(maxsize=1024)
def _license_validate(rpm_license):
    """Validate a license expression; negative results are cached too.

    :param rpm_license: RPM license string
    :type rpm_license: str
    :returns: _Validity indicating if the license is valid, invalid, or unknown
    :rtype: _Validity
    """
    try:
        run_command(["license-validate", rpm_license], timeout=_LICENSE_TOOL_TIMEOUT)
        return _Validity.VALID
    except subprocess.CalledProcessError as exc:
        if exc.returncode == 1:
            return _Validity.INVALID
        logging.warning("license-validate failed for '%s': %s", rpm_license, exc)
        return _Validity.UNKNOWN
    except (subprocess.TimeoutExpired, OSError) as exc:
        logging.warning("license-validate failed for '%s': %s", rpm_license, exc)
        return _Validity.UNKNOWN


@lru_cache(maxsize=1024)
def _license_fedora2spdx(rpm_license):
    """Convert a legacy license string; returns None on failure (cached).

    :param rpm_license: RPM license string
    :type rpm_license: str
    :returns: SPDX license expression or None on failure
    :rtype: str or None
    """
    try:
        return run_command(["license-fedora2spdx", rpm_license],
                           timeout=_LICENSE_TOOL_TIMEOUT).stdout
    except (subprocess.CalledProcessError, subprocess.TimeoutExpired, OSError) as exc:
        logging.warning("license-fedora2spdx failed for '%s': %s", rpm_license, exc)
        return None


@lru_cache(maxsize=1024)
def to_spdx_license(rpm_license):
    """Convert RPM license to SPDX license expression using license-fedora2spdx.

    This function is cached, so warnings and tool invocations happen only once
    per distinct license string. Use reset_license_caches() to clear the cache
    if needed (e.g., in long-running processes or tests).

    :param rpm_license: RPM license string
    :type rpm_license: str
    :returns: SPDX license expression, or "NOASSERTION" if conversion fails
    :rtype: str
    """
    if not rpm_license:
        return "NOASSERTION"

    validity = _license_validate(rpm_license)
    if validity is _Validity.VALID:
        logging.debug("Valid SPDX license '%s'", rpm_license)
        return rpm_license
    if validity is _Validity.UNKNOWN:
        logging.warning("Cannot validate license '%s'", rpm_license)
        return "NOASSERTION"

    # validity is INVALID - try legacy conversion
    output = _license_fedora2spdx(rpm_license)
    if output is None:
        return "NOASSERTION"  # already logged by the helper

    lines = output.splitlines()
    spdx_license = lines[0].strip() if lines else ""
    if not spdx_license:
        logging.warning("license-fedora2spdx returned no usable output "
                        "for license '%s'", rpm_license)
        return "NOASSERTION"

    if len(lines) > 1:
        logging.warning("license-fedora2spdx returned some important notes "
                        "for license '%s':\n%s", rpm_license, output)

    if spdx_license != rpm_license:
        logging.debug("Converted RPM license '%s' to SPDX license '%s'",
                      rpm_license, spdx_license)
    return spdx_license


def reset_license_caches():
    """Drop all memoized license data (for tests or long-running callers)."""
    _license_validate.cache_clear()
    _license_fedora2spdx.cache_clear()
    to_spdx_license.cache_clear()


def log_license_cache_stats():
    """Log how often the external license tools were spawned."""
    logging.info("license-validate cache: %s", _license_validate.cache_info())
    logging.info("license-fedora2spdx cache: %s", _license_fedora2spdx.cache_info())
    logging.info("to_spdx_license cache: %s", to_spdx_license.cache_info())
