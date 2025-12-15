#!/usr/bin/python3
"""Utility functions for SBOM generation and processing.

This module provides common utilities for SBOM-related operations including:
- Package URL (purl) generation for generic and RPM packages
- License conversion from RPM to SPDX format
- Checksum calculation
- Command execution and URL validation
"""

import hashlib
import logging
import subprocess
import urllib.request


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


def get_rpm_purl(name, version, release, arch, epoch=None):
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
    :returns: RPM purl string
    :rtype: str
    """
    # Format: pkg:rpm/redhat/name@version-release?arch=...
    version_str = f"{version}-{release}"
    if epoch:
        version_str = f"{epoch}:{version_str}"

    purl = f"pkg:rpm/redhat/{name}@{version_str}?arch={arch}"
    return purl


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
        result = run_command(["license-fedora2spdx", rpm_license], timeout=5)
        spdx_license = result.stdout.strip()
        return spdx_license if spdx_license else "NOASSERTION"
    except (subprocess.CalledProcessError, subprocess.TimeoutExpired, FileNotFoundError) as e:
        logging.warning("[CRITICAL] Failed to convert license '%s' to SPDX: %s", rpm_license, e)
        return "NOASSERTION"


def calc_checksum(filepath, algorithm="sha256", chunk_size=1024**2):
    """Calculate checksum of a file using specified algorithm.

    :param filepath: Path to the file
    :type filepath: str
    :param algorithm: Hash algorithm (e.g., 'sha256', 'sha512', 'md5')
    :type algorithm: str
    :param chunk_size: Size of chunks to read
    :type chunk_size: int
    :returns: Hexadecimal checksum string
    :rtype: str
    """
    h = hashlib.new(algorithm.lower())
    with open(filepath, "rb") as fp:
        while True:
            data = fp.read(chunk_size)
            if not data:
                break
            h.update(data)
    return h.hexdigest()


def run_command(cmd, capture_output=True, check=True, cwd=None, timeout=None):
    """Execute a command and return the result.

    :param cmd: Command to execute (string or list)
    :type cmd: str or list
    :param capture_output: Whether to capture stdout/stderr
    :type capture_output: bool
    :param check: Whether to raise exception on non-zero exit code
    :type check: bool
    :param cwd: chdir while running the command
    :type cwd: str
    :param timeout: Timeout in seconds
    :type timeout: int or None
    :returns: Completed process object
    :rtype: subprocess.CompletedProcess
    """
    logging.debug("Running command: %s", cmd)
    result = subprocess.run(
        cmd,
        shell=isinstance(cmd, str),
        capture_output=capture_output,
        text=True,
        check=check,
        cwd=cwd,
        encoding="utf-8",
        timeout=timeout,
    )
    if result.stdout:
        logging.debug("Command stdout: %s", result.stdout)
    if result.stderr:
        logging.debug("Command stderr: %s", result.stderr)
    result.check_returncode()
    return result


def is_url_accessible(url):
    """Verify whether a URL is accessible.

    Performs an HTTP HEAD request to check if the URL can be reached.
    Automatically follows redirects.

    :param url: URL to verify
    :type url: str
    :returns: True if URL is accessible, False otherwise
    :rtype: bool
    """
    if not url:
        return False

    try:
        # Create opener that follows redirects (default behavior)
        opener = urllib.request.build_opener(urllib.request.HTTPRedirectHandler)
        req = urllib.request.Request(url, method='HEAD')

        with opener.open(req, timeout=5) as response:
            return response.status == 200
    except Exception as e:  # pylint: disable=broad-exception-caught
        logging.debug("URL accessibility check failed for %s: %s", url, e)
        return False
