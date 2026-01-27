"""Common utility functions.

This module provides shared utility functions for logging, file operations,
and error message sanitization.
"""

import hashlib
import logging
import subprocess
import urllib.request


def setup_logging(debug=False):
    """Set up logging configuration.

    :param debug: Enable debug logging if True
    :type debug: bool
    """

    level = logging.DEBUG if debug else logging.INFO
    logging.basicConfig(
        level=level,
        format="[%(asctime)s] %(levelname)s: %(message)s",
        datefmt="%Y-%m-%d %H:%M:%S",
    )


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
