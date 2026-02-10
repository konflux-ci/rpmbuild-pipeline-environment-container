"""Common utility functions.

This module provides shared utility functions for logging, file operations,
and error message sanitization.
"""

import hashlib


# ============================================================================
# File Utilities
# ============================================================================

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
