#!/usr/bin/env python3
"""
Shared utilities for Pulp operations.

This module provides common utilities, constants, and helper functions
used across multiple Pulp-related modules to reduce code duplication.
"""

import argparse
import base64
import binascii
import glob
import hashlib
import logging
import os
import re
import time
import traceback
from concurrent.futures import ThreadPoolExecutor, as_completed
from pathlib import Path
from typing import Any, Dict, Generator, List, Optional, Tuple, TYPE_CHECKING

# Third-party imports
import requests
from requests.adapters import HTTPAdapter, Retry

if TYPE_CHECKING:
    from pulp_client import PulpClient

# Optional imports with fallback
try:
    import tomllib
except ImportError:
    # Fallback for Python < 3.11
    import tomli as tomllib

# ============================================================================
# Constants
# ============================================================================

# HTTP status codes to retry on
RETRY_STATUS_CODES = [429, 500, 502, 503, 504]

# Default timeouts
DEFAULT_TIMEOUT = 60
DEFAULT_TASK_TIMEOUT = 86400
DEFAULT_MAX_WORKERS = 4

# Repository types
REPOSITORY_TYPES = ["rpms", "logs", "sbom", "artifacts"]

# File patterns and batch processing
RPM_FILE_PATTERN = "*.rpm"
LOG_FILE_PATTERN = "*.log"

# ============================================================================
# Shared Utility Functions
# ============================================================================

def create_session_with_retry() -> requests.Session:
    """
    Create a requests session with retry strategy and connection pooling.

    Returns:
        Configured requests.Session object
    """
    retry_strategy = Retry(
        total=4,
        backoff_factor=2,
        status_forcelist=RETRY_STATUS_CODES,
    )
    adapter = HTTPAdapter(
        max_retries=retry_strategy,
        pool_connections=20,  # Number of connection pools to cache
        pool_maxsize=50,      # Maximum number of connections to save in the pool
        pool_block=False      # Whether the connection pool should block for connections
    )

    session = requests.Session()
    session.mount("http://", adapter)
    session.mount("https://", adapter)

    return session
BATCH_SIZE = 50
RESULTS_JSON_FILENAME = "pulp_results.json"

# Architecture constants
SUPPORTED_ARCHITECTURES = ["x86_64", "aarch64", "s390x", "ppc64le"]

# Thread pool configuration
REPOSITORY_SETUP_MAX_WORKERS = 4
ARCHITECTURE_PROCESSING_MAX_WORKERS = 4
ARCHITECTURE_THREAD_PREFIX = "process_architectures"

# URL constants

# Logging configuration
DEFAULT_LOG_WIDTH = 120
MAX_LOG_LINE_LENGTH = 114

# File validation
MIN_FILE_SIZE = 0

# ============================================================================
# URL Utilities
# ============================================================================

def get_pulp_content_base_url(cert_config_path: Optional[str] = None) -> str:
    """
    Get the Pulp content base URL from cert config or use default.

    Args:
        cert_config_path: Optional path to certificate config file

    Returns:
        Constructed base URL for Pulp content
    """
    if cert_config_path:
        try:
            config_path = Path(cert_config_path).expanduser()
            with open(config_path, "rb") as fp:
                config = tomllib.load(fp)

            base_url = config["cli"]["base_url"]
            api_root = config["cli"]["api_root"]

            # Construct the content base URL
            content_base_url = f"{base_url}{api_root}/pulp-content"
            logging.info("Using cert config base URL: %s", content_base_url)
            return content_base_url

        except Exception as e:
            logging.error("Failed to read cert config %s: %s", cert_config_path, sanitize_error_message(str(e)))
            raise ValueError(f"Cannot determine Pulp content base URL: {e}") from e

    # No cert config provided
    raise ValueError("cert_config_path is required to determine Pulp content base URL")

# ============================================================================
# File Utilities
# ============================================================================

def decode_base64_if_encoded(content: bytes) -> bytes:
    """
    Decode base64 content if it's encoded, otherwise return original content.

    This function attempts to decode base64-encoded content. If the content
    is not base64 encoded, it returns the original content unchanged.

    Args:
        content: Bytes content that may be base64 encoded

    Returns:
        Decoded bytes if base64 encoded, otherwise original bytes
    """
    try:
        # Try to decode as base64
        decoded = base64.b64decode(content, validate=True)
        # If successful and the decoded content is different, return decoded
        if decoded != content:
            return decoded
        # If decoding didn't change anything, it wasn't base64
        return content
    except (binascii.Error, ValueError):
        # If decoding fails, it's not base64 encoded
        return content


def read_file_with_base64_decode(file_path: str) -> Tuple[bytes, bytes]:
    """
    Read a file and decode base64 content if encoded.

    Args:
        file_path: Path to the file to read

    Returns:
        Tuple of (original_content, decoded_content)
    """
    with open(file_path, "rb") as f:
        original_content = f.read()
    decoded_content = decode_base64_if_encoded(original_content)
    return original_content, decoded_content

# ============================================================================
# Logging Utilities
# ============================================================================

def sanitize_error_message(error_msg: str) -> str:
    """
    Sanitize error messages to remove sensitive information like passwords or secrets.

    This function should be used whenever logging error messages that might contain
    sensitive data such as passwords, API keys, tokens, or other credentials.

    Args:
        error_msg: Original error message that may contain sensitive data

    Returns:
        Sanitized error message with sensitive information redacted
    """
    # List of sensitive field names that should be redacted
    sensitive_fields = [
        'password', 'secret', 'token', 'key', 'credential', 'auth',
        'client_secret', 'client_id', 'api_key', 'access_token',
        'private_key', 'privatekey', 'cert', 'certificate'
    ]

    sanitized = error_msg
    # Try to redact common patterns like key=value or "key": "value"
    for field in sensitive_fields:
        # Pattern: field = "value" or field="value" (with optional quotes)
        # Match values that might be on the same line or next line
        pattern = rf'\b{field}\s*=\s*["\']?[^"\'\n\r]+["\']?'
        sanitized = re.sub(pattern, f'{field} = <REDACTED>', sanitized, flags=re.IGNORECASE)
        # Pattern: "field": "value" or 'field': 'value'
        pattern = rf'["\']?{field}["\']?\s*:\s*["\']?[^"\'\n\r]+["\']?'
        sanitized = re.sub(pattern, f'"{field}": "<REDACTED>"', sanitized, flags=re.IGNORECASE)
        # Pattern: [field] section with values below (for TOML)
        pattern = rf'\[{field}\][^\]]*'
        sanitized = re.sub(pattern, f'[{field}] <REDACTED>', sanitized, flags=re.IGNORECASE | re.DOTALL)

    return sanitized


class WrappingFormatter(logging.Formatter):
    """
    Custom formatter that wraps long log messages for better readability.

    This formatter extends the standard logging formatter to handle
    long messages by wrapping them at a specified width.
    """

    def __init__(self, fmt=None, datefmt=None, width=DEFAULT_LOG_WIDTH):
        """
        Initialize the wrapping formatter.

        Args:
            fmt: Format string for log messages
            datefmt: Date format string
            width: Maximum width for log message wrapping
        """
        super().__init__(fmt, datefmt)
        self.width = width

    def format(self, record):
        """
        Format the log record with line wrapping.

        Args:
            record: Log record to format

        Returns:
            Formatted log message with wrapping
        """
        formatted = super().format(record)

        # Only wrap if the message is longer than the specified width
        if len(formatted) > self.width:
            lines = []
            current_line = ""

            for word in formatted.split():
                if len(current_line + " " + word) <= self.width:
                    current_line += (" " + word) if current_line else word
                else:
                    if current_line:
                        lines.append(current_line)
                    current_line = word

            if current_line:
                lines.append(current_line)

            formatted = "\n".join(lines)

        return formatted


def _setup_wrapping_logging(level: int) -> None:
    """Setup logging with wrapping formatter."""
    formatter = WrappingFormatter(
        fmt='%(asctime)s - %(levelname)s - %(message)s',
        width=120
    )
    handler = logging.StreamHandler()
    handler.setFormatter(formatter)

    # Clear any existing handlers
    root_logger = logging.getLogger()
    root_logger.handlers.clear()
    root_logger.addHandler(handler)
    root_logger.setLevel(level)

def _setup_basic_logging(level: int) -> None:
    """Setup basic logging configuration."""
    logging.basicConfig(
        level=level,
        format='%(asctime)s - %(levelname)s - %(message)s'
    )

def setup_logging(debug: bool, use_wrapping: bool = False) -> None:
    """
    Setup logging configuration.

    This function configures the logging system with appropriate level and
    formatter. Optionally uses a custom wrapping formatter for better readability.

    Args:
        debug: If True, enable debug level logging; otherwise use info level
        use_wrapping: If True, use wrapping formatter for long messages
    """
    level = logging.DEBUG if debug else logging.INFO

    if use_wrapping:
        _setup_wrapping_logging(level)
    else:
        _setup_basic_logging(level)


# ============================================================================
# Argument Parsing Utilities
# ============================================================================

def create_base_parser(description: str, epilog: Optional[str] = None) -> argparse.ArgumentParser:
    """
    Create a base argument parser with common options.

    Args:
        description: Description for the argument parser
        epilog: Optional epilog text

    Returns:
        Configured ArgumentParser instance
    """
    parser = argparse.ArgumentParser(
        description=description,
        epilog=epilog,
        formatter_class=argparse.RawDescriptionHelpFormatter
    )

    # Common options
    parser.add_argument(
        '--debug',
        action='store_true',
        help='Enable debug logging'
    )

    return parser


def add_pulp_config_args(parser: argparse.ArgumentParser) -> None:
    """
    Add common Pulp configuration arguments to a parser.

    Args:
        parser: ArgumentParser instance to add arguments to
    """
    parser.add_argument(
        '--config',
        required=True,
        help='Path to Pulp configuration file'
    )
    parser.add_argument(
        '--domain',
        required=True,
        help='Pulp domain name'
    )
    parser.add_argument(
        '--namespace',
        required=True,
        help='Pulp namespace'
    )
    parser.add_argument(
        '--repository-name',
        default='rok-storage',
        help='Base name for repositories (default: rok-storage)'
    )


def add_cert_args(parser: argparse.ArgumentParser) -> None:
    """
    Add certificate-related arguments to a parser.

    Args:
        parser: ArgumentParser instance to add arguments to
    """
    parser.add_argument(
        '--cert-path',
        required=True,
        help='Path to client certificate file'
    )
    parser.add_argument(
        '--key-path',
        required=True,
        help='Path to client private key file'
    )


# ============================================================================
# Validation Utilities
# ============================================================================

def sanitize_build_id_for_repository(build_id: str) -> str:
    """
    Sanitize a build ID for use in repository naming by replacing invalid characters.

    Args:
        build_id: Build ID to sanitize

    Returns:
        Sanitized build ID safe for repository naming
    """
    if not build_id or not isinstance(build_id, str):
        return "default-build"

    # Replace invalid characters with hyphens
    invalid_chars = ['/', '\\', ':', '*', '?', '"', '<', '>', '|']
    sanitized = build_id

    for char in invalid_chars:
        sanitized = sanitized.replace(char, '-')

    # Remove multiple consecutive hyphens
    while '--' in sanitized:
        sanitized = sanitized.replace('--', '-')

    # Remove leading/trailing hyphens
    sanitized = sanitized.strip('-')

    # Ensure it's not empty after sanitization
    if not sanitized:
        return "default-build"

    return sanitized

def validate_build_id(build_id: str) -> bool:
    """
    Validate that a build ID is not empty or None.

    Args:
        build_id: Build ID to validate

    Returns:
        True if valid, False otherwise
    """
    return bool(build_id and isinstance(build_id, str))


def extract_build_id_from_artifact_json(artifact_json: Dict[str, Any]) -> str:
    """
    Extract build_id from artifact_json metadata.

    Args:
        artifact_json: Artifact metadata from distribution client

    Returns:
        Build ID extracted from artifact metadata, or 'rok-storage' as fallback
    """
    artifacts = artifact_json.get("artifacts", {})

    # Try to find build_id in any of the artifacts
    for artifact_info in artifacts.values():
        labels = artifact_info.get("labels", {})
        build_id = labels.get("build_id")
        if build_id:
            logging.info("Extracted build_id '%s' from artifact metadata", build_id)
            return build_id

    # Fallback if no build_id found
    logging.warning("No build_id found in artifact metadata, using default: rok-storage")
    return "rok-storage"


def extract_build_id_from_artifacts(pulled_artifacts: Dict[str, Dict]) -> str:
    """
    Extract build_id from the first available artifact's labels.

    Args:
        pulled_artifacts: Dictionary containing downloaded artifacts organized by type

    Returns:
        Build ID extracted from artifact labels, or 'rok-storage' as fallback
    """
    # Try to find build_id in any of the artifact types
    for artifact_type, artifacts in pulled_artifacts.items():
        if artifacts:
            # Get the first artifact's labels
            first_artifact = next(iter(artifacts.values()))
            build_id = first_artifact["labels"].get("build_id")
            if build_id:
                logging.info("Extracted build_id '%s' from %s artifacts", build_id, artifact_type)
                return build_id

    # Fallback if no build_id found
    logging.warning("No build_id found in artifact labels, using default: rok-storage")
    return "rok-storage"


def determine_build_id(args, artifact_json: Optional[Dict] = None,
                      pulled_artifacts: Optional[Dict[str, Dict]] = None) -> str:
    """
    Determine build ID from command line arguments, artifact metadata, or pulled artifacts.

    Priority: command line argument > artifact_json > pulled_artifacts > default

    Args:
        args: Command line arguments
        artifact_json: Optional artifact metadata
        pulled_artifacts: Optional pulled artifacts dictionary

    Returns:
        Build ID string
    """
    # Priority 1: Command line argument
    if hasattr(args, 'build_id') and args.build_id:
        build_id = args.build_id
        logging.info("Using build_id from command line argument: %s", build_id)
        return build_id

    # Priority 2: Extract from artifact_json
    if artifact_json:
        build_id = extract_build_id_from_artifact_json(artifact_json)
        logging.info("Using build_id from artifact metadata: %s", build_id)
        return build_id

    # Priority 3: Extract from pulled_artifacts
    if pulled_artifacts:
        build_id = extract_build_id_from_artifacts(pulled_artifacts)
        logging.info("Using build_id from pulled artifacts: %s", build_id)
        return build_id

    # Priority 4: Default fallback
    build_id = "rok-storage"
    logging.info("Using default build_id: %s", build_id)
    return build_id


def validate_file_path(file_path: str, file_type: str) -> None:
    """
    Validate file exists, is readable, and not empty.

    Args:
        file_path: Path to the file to validate
        file_type: Type of file for error messages (e.g., 'RPM', 'SBOM')

    Raises:
        FileNotFoundError: If the file does not exist
        PermissionError: If the file cannot be read
        ValueError: If the file is empty
    """
    if not os.path.exists(file_path):
        raise FileNotFoundError(f"{file_type} file not found: {file_path}")

    if not os.access(file_path, os.R_OK):
        raise PermissionError(f"Cannot read {file_type} file: {file_path}")

    file_size = os.path.getsize(file_path)
    if file_size == MIN_FILE_SIZE:
        raise ValueError(f"{file_type} file is empty: {file_path}")

    logging.debug("%s file size: %d bytes", file_type, file_size)


# ============================================================================
# Repository Utilities
# ============================================================================

def validate_repository_setup(repositories: Dict[str, str]) -> tuple[bool, List[str]]:
    """
    Validate that repository setup is complete.

    Args:
        repositories: Dictionary of repository information

    Returns:
        Tuple of (is_valid, error_messages)
    """
    errors = []

    # Check that all required repository types are present
    for repo_type in REPOSITORY_TYPES:
        prn_key = f"{repo_type}_prn"
        if prn_key not in repositories:
            errors.append(f"Missing {repo_type} repository PRN")

        # RPM repositories should also have href
        if repo_type == 'rpms':
            href_key = f"{repo_type}_href"
            if href_key not in repositories:
                errors.append(f"Missing {repo_type} repository href")

    return len(errors) == 0, errors

# ============================================================================
# Upload Functions
# ============================================================================

def create_labels(build_id: str, arch: str, namespace: str, parent_package: str,
                 date: str) -> Dict[str, str]:
    """
    Create standard labels for Pulp content.

    Args:
        build_id: Unique build identifier
        arch: Architecture (e.g., 'x86_64', 'aarch64')
        namespace: Namespace for the content
        parent_package: Parent package name
        date: Build date string

    Returns:
        Dictionary containing standard labels for Pulp content
    """
    labels = {
        "date": date,
        "build_id": build_id,
        "arch": arch,
        "namespace": namespace,
        "parent_package": parent_package,
    }
    return labels


def upload_log(client, file_repository_prn: str, log_path: str,
               *, build_id: str, labels: Dict[str, str], arch: str) -> None:
    """
    Upload a log file to the specified file repository.

    Args:
        client: PulpClient instance for API interactions
        file_repository_prn: File repository PRN for log uploads
        log_path: Path to the log file to upload
        build_id: Build identifier for the log
        labels: Labels to attach to the log content
        arch: Architecture for the log content
    """
    validate_file_path(log_path, "Log")

    content_upload_response = client.create_file_content(
        file_repository_prn, log_path,
        build_id=build_id, pulp_label=labels, arch=arch
    )

    client.check_response(content_upload_response, f"upload log {log_path}")
    client.wait_for_finished_task(content_upload_response.json()['task'])


def _create_batches(items: List[str], batch_size: int = BATCH_SIZE) -> Generator[List[str], None, None]:
    """
    Split a list into batches of specified size using a generator.

    Args:
        items: List of items to split into batches
        batch_size: Maximum number of items per batch

    Yields:
        List of items for each batch
    """
    for i in range(0, len(items), batch_size):
        yield items[i:i + batch_size]


def _calculate_sha256_checksum(file_path: str) -> str:
    """
    Calculate SHA256 checksum of a file.

    Args:
        file_path: Path to the file to calculate checksum for

    Returns:
        SHA256 checksum as hexadecimal string

    Raises:
        FileNotFoundError: If the file does not exist
        IOError: If there's an error reading the file
    """
    if not os.path.exists(file_path):
        raise FileNotFoundError(f"File not found: {file_path}")

    sha256_hash = hashlib.sha256()

    try:
        with open(file_path, "rb") as f:
            for chunk in iter(lambda: f.read(4096), b""):
                sha256_hash.update(chunk)
    except IOError as e:
        raise IOError(f"Error reading file {file_path}: {e}") from e

    return sha256_hash.hexdigest()


def _get_nvra(result: Dict[str, Any]) -> str:
    """
    Get Name-Version-Release-Architecture (NVRA) from Pulp response.

    Args:
        result: Dictionary containing RPM package information from Pulp

    Returns:
        NVRA string in format "name-version-release.arch"
    """
    return (f"{result.get('name')}-{result.get('version')}-"
            f"{result.get('release')}.{result.get('arch')}")


def _process_single_batch(
    client,
    batch: List[str],
    batch_num: int,
    total_batches: int,
) -> Dict[str, Any]:
    """
    Process a single batch to find RPM files on Pulp.

    This function calculates checksums for RPM files in the batch and queries
    Pulp to determine which RPMs already exist and which need to be uploaded.

    Args:
        client: PulpClient instance for API interactions
        batch: List of RPM file paths to process
        batch_num: Current batch number (1-indexed)
        total_batches: Total number of batches being processed

    Returns:
        Dictionary containing:
            - batch_number: The batch number processed
            - missing_rpms: List of RPM files not found on Pulp
            - missing_checksums: Set of checksums not found on Pulp
            - found_rpms: List of RPM files found on Pulp
            - found_checksums: List of checksums found on Pulp
            - found_artifacts: List of artifact information for found RPMs
            - error: Error message if processing failed (optional)
    """
    logging.debug("Processing batch %d/%d with %d files", batch_num, total_batches, len(batch))

    # Calculate checksums for the current batch
    checksums = []
    for rpm_file in batch:
        try:
            checksum = _calculate_sha256_checksum(rpm_file)
            checksums.append(checksum)
            logging.debug("Calculated checksum for %s: %s", os.path.basename(rpm_file), checksum)
        except Exception as e: # pylint: disable=W0718 broad-exception-caught
            logging.error("Failed to calculate checksum for %s: %s", rpm_file, sanitize_error_message(str(e)))
            logging.error("Traceback: %s", sanitize_error_message(traceback.format_exc()))
            continue

    # Lookup RPMs on Pulp
    try:
        response = client.get_rpm_by_pkgIDs(checksums)
        client.check_response(response)
        response_data = response.json()

        # Extract found checksums from the API response
        found_checksums = set()
        found_artifacts = []
        found_rpms = []

        for result in response_data.get("results", []):
            checksum = result.get("sha256")
            if checksum:
                found_checksums.add(checksum)
                found_artifacts.append({
                    "href": result.get("pulp_href"),
                    "nvra": _get_nvra(result),
                    "checksum": checksum
                })

        # Determine which RPMs are missing
        missing_rpms = []
        missing_checksums = set()
        for i, rpm_file in enumerate(batch):
            if i < len(checksums) and checksums[i] not in found_checksums:
                missing_rpms.append(rpm_file)
                missing_checksums.add(checksums[i])

        logging.debug("Batch %d/%d: %d missing, %d found", batch_num, total_batches,
                     len(missing_rpms), len(found_artifacts))

        return {
            "batch_number": batch_num,
            "missing_rpms": missing_rpms,
            "missing_checksums": missing_checksums,
            "found_rpms": found_rpms,
            "found_checksums": list(found_checksums),
            "found_artifacts": found_artifacts,
        }

    except Exception as e: # pylint: disable=W0718 broad-exception-caught
        logging.error("Batch %d/%d failed: %s", batch_num, total_batches, sanitize_error_message(str(e)))
        logging.debug("Traceback: %s", sanitize_error_message(traceback.format_exc()))
        return {
            "batch_number": batch_num,
            "missing_rpms": batch,
            "missing_checksums": set(),
            "found_rpms": [],
            "found_checksums": [],
            "found_artifacts": [],
            "error": str(e),
        }


def _process_batch_results(future_to_batch: Dict, batches: List[List[str]]) -> \
        Tuple[List[str], List[Dict[str, str]]]:
    """
    Process batch results and collect missing RPMs and found artifacts.

    This function processes completed batch futures and aggregates the results
    to determine which RPMs need to be uploaded and which artifacts were found.

    Args:
        future_to_batch: Dictionary mapping futures to batch numbers
        batches: List of all batches for error handling

    Returns:
        Tuple of (missing_rpms, found_artifacts) where:
            - missing_rpms: List of RPM files that need to be uploaded
            - found_artifacts: List of artifact information for existing RPMs
    """
    missing_rpms = []
    found_artifacts = []

    for i, future in enumerate(as_completed(future_to_batch)):
        batch_num = future_to_batch[future]
        try:
            result = future.result()
            if result is not None:
                missing_rpms.extend(result["missing_rpms"])
                found_artifacts.extend(result["found_artifacts"])

            # Add small delay every few batches to reduce connection pressure
            if i > 0 and i % 3 == 0:
                time.sleep(0.1)

        except Exception as e: # pylint: disable=W0718 broad-exception-caught
            logging.error("Batch %d processing failed with exception: %s", batch_num, sanitize_error_message(str(e)))
            logging.error("Traceback: %s", sanitize_error_message(traceback.format_exc()))
            missing_rpms.extend(batches[batch_num - 1])
            found_artifacts.extend([])

    return missing_rpms, found_artifacts


def check_rpms_on_pulp(client, rpms: List[str]) -> Tuple[List[str], List[Dict[str, str]]]:
    """
    Check if RPMs are already on Pulp.

    This function processes RPMs in batches to determine which ones already exist
    on Pulp and which ones need to be uploaded. It uses parallel processing for
    better performance.

    Args:
        client: PulpClient instance for API interactions
        rpms: List of RPM file paths to check

    Returns:
        Tuple of (missing_rpms, found_artifacts) where:
            - missing_rpms: List of RPM files not found on Pulp
            - found_artifacts: List of artifact information for existing RPMs
    """
    batches = list(_create_batches(rpms, BATCH_SIZE))
    logging.info("Checking %d RPMs against Pulp in %d batches", len(rpms), len(batches))
    logging.debug("Created %d batches with %d rpms for lookup in Pulp", len(batches), len(rpms))

    with ThreadPoolExecutor(thread_name_prefix="check_rpms_on_pulp",
                          max_workers=DEFAULT_MAX_WORKERS) as executor:
        future_to_batch = {
            executor.submit(_process_single_batch, client, batch, batch_num,
                          len(batches)): batch_num
            for batch_num, batch in enumerate(batches, 1)
        }

        logging.debug("Submitted %d batches with %d workers",
                     len(future_to_batch), DEFAULT_MAX_WORKERS)
        missing_rpms, found_artifacts = _process_batch_results(future_to_batch, batches)

    logging.info("RPM lookup completed: %d missing, %d found",
                len(missing_rpms), len(found_artifacts))
    return missing_rpms, found_artifacts


def _upload_rpms_parallel(client, rpms_to_upload: List[str],
                         labels: Dict[str, str], arch: str) -> List[str]:
    """
    Upload RPMs in parallel and return artifact hrefs.

    This function uploads multiple RPM files concurrently using a thread pool
    for improved performance.

    Args:
        client: PulpClient instance for API interactions
        rpms_to_upload: List of RPM file paths to upload
        labels: Labels to attach to the uploaded content
        arch: Architecture for the uploaded RPMs

    Returns:
        List of artifact hrefs for successfully uploaded RPMs
    """
    if not rpms_to_upload:
        return []

    with ThreadPoolExecutor(thread_name_prefix="upload_rpms",
                          max_workers=DEFAULT_MAX_WORKERS) as executor:
        futures = [executor.submit(client.upload_content, rpm, labels,
                                  file_type="RPM", upload_method="rpm", arch=arch)
                  for rpm in rpms_to_upload]
        return [future.result() for future in as_completed(futures)]


def _upload_logs_sequential(client, logs: List[str],
                           *, file_repository_prn: str, build_id: str,
                           labels: Dict[str, str], arch: str) -> None:
    """
    Upload logs sequentially.

    This function uploads log files one by one to avoid overwhelming the server
    with concurrent file uploads.

    Args:
        client: PulpClient instance for API interactions
        logs: List of log file paths to upload
        file_repository_prn: File repository PRN for log uploads
        build_id: Build identifier for the logs
        labels: Labels to attach to the uploaded content
        arch: Architecture for the uploaded logs
    """
    for log in logs:
        upload_log(client, file_repository_prn, log,
                  build_id=build_id, labels=labels, arch=arch)


def initialize_upload_tracking(build_id: str, repositories: Dict[str, str]) -> Dict:
    """
    Initialize upload tracking structure.

    Args:
        build_id: Build ID for the upload
        repositories: Repository information

    Returns:
        Upload tracking dictionary
    """
    return {
        "build_id": build_id,
        "repositories": repositories,
        "uploaded_counts": {
            "sboms": 0,
            "logs": 0,
            "rpms": 0
        },
        "upload_errors": []
    }


def upload_artifacts_to_repository(client, artifacts: Dict[str, Dict],
                                 repository_prn: str, file_type: str) -> Tuple[int, List[str]]:
    """
    Upload artifacts to a specific repository.

    Args:
        client: PulpClient instance for API interactions
        artifacts: Dictionary of artifacts to upload
        repository_prn: Repository PRN to upload to
        file_type: Type of file being uploaded (for logging)

    Returns:
        Tuple of (upload_count, error_list)
    """
    upload_count = 0
    errors = []

    for artifact_name, artifact_info in artifacts.items():
        try:
            logging.debug("Uploading %s: %s", file_type, artifact_name)

            # Upload the file content
            content_response = client.create_file_content(
                repository_prn,
                artifact_info["file"],
                build_id=artifact_info["labels"].get("build_id", "unknown"),
                pulp_label=artifact_info["labels"],
                filename=os.path.basename(artifact_info["file"]),
                arch=artifact_info["labels"].get("arch", "unknown")
            )

            # Check if response contains a task or if it's already complete
            response_data = content_response.json()
            if 'task' in response_data:
                # Wait for upload to complete
                client.wait_for_finished_task(response_data['task'])
            else:
                # Response might be immediate success, log it
                logging.debug("File upload completed immediately: %s", artifact_name)
            upload_count += 1
            logging.debug("Successfully uploaded %s: %s", file_type, artifact_name)

        except (requests.RequestException, ValueError, FileNotFoundError, KeyError) as e:
            logging.error("Failed to upload %s %s: %s", file_type, artifact_name, sanitize_error_message(str(e)))
            logging.error("Traceback: %s", sanitize_error_message(traceback.format_exc()))
            errors.append(f"{file_type} {artifact_name}: {e}")

    return upload_count, errors


def upload_rpms_from_artifacts(client: "PulpClient", pulled_artifacts: Dict[str, Dict],
                               repositories: Dict[str, str], upload_info: Dict) -> None:
    """
    Upload RPM files from pulled artifacts to the RPM repository.

    Args:
        client: PulpClient instance for API interactions
        pulled_artifacts: Downloaded artifacts organized by type
        repositories: Repository information
        upload_info: Upload tracking dictionary to update
    """
    if not pulled_artifacts.get("rpms"):
        return

    logging.info("Uploading %d RPM files to Pulp", len(pulled_artifacts["rpms"]))

    # Upload RPMs and get artifact hrefs
    rpm_artifacts = []
    rpm_upload_count = 0
    for artifact_name, artifact_info in pulled_artifacts["rpms"].items():
        try:
            logging.debug("Uploading RPM: %s", artifact_name)
            # Upload the RPM file and get artifact href
            artifact_href = client.upload_content(
                artifact_info["file"],
                artifact_info["labels"],
                file_type="RPM",
                upload_method="rpm",
                arch=artifact_info["labels"].get("arch", "unknown")
            )
            rpm_artifacts.append(artifact_href)
            rpm_upload_count += 1
            logging.debug("Successfully uploaded RPM: %s", artifact_name)
        except (requests.RequestException, ValueError, FileNotFoundError) as e:
            logging.error("Failed to upload RPM %s: %s", artifact_name, sanitize_error_message(str(e)))
            logging.error("Traceback: %s", sanitize_error_message(traceback.format_exc()))
            upload_info["upload_errors"].append(f"RPM {artifact_name}: {e}")

    # Add all RPM artifacts to the repository
    if rpm_artifacts:
        logging.info("Adding %d RPM artifacts to repository", len(rpm_artifacts))
        try:
            add_response = client.add_content(repositories["rpms_href"], rpm_artifacts)
            client.wait_for_finished_task(add_response.json()['task'])
            upload_info["uploaded_counts"]["rpms"] = rpm_upload_count
        except (requests.RequestException, ValueError, KeyError) as e:
            logging.error("Failed to add RPMs to repository: %s", sanitize_error_message(str(e)))
            logging.error("Traceback: %s", sanitize_error_message(traceback.format_exc()))
            upload_info["upload_errors"].append(f"RPM repository addition: {e}")


def upload_sboms_and_logs_from_artifacts(client: "PulpClient", pulled_artifacts: Dict[str, Dict],
                                        repositories: Dict[str, str], upload_info: Dict) -> None:
    """
    Upload SBOM and log files from pulled artifacts to their respective repositories.

    Args:
        client: PulpClient instance for API interactions
        pulled_artifacts: Downloaded artifacts organized by type
        repositories: Repository information
        upload_info: Upload tracking dictionary to update
    """
    # Upload SBOMs
    if pulled_artifacts.get("sboms"):
        logging.info("Uploading %d SBOM files to Pulp", len(pulled_artifacts["sboms"]))
        upload_count, errors = upload_artifacts_to_repository(
            client, pulled_artifacts["sboms"], repositories["sbom_prn"], "SBOM"
        )
        upload_info["uploaded_counts"]["sboms"] = upload_count
        upload_info["upload_errors"].extend(errors)

    # Upload logs
    if pulled_artifacts.get("logs"):
        logging.info("Uploading %d log files to Pulp", len(pulled_artifacts["logs"]))
        upload_count, errors = upload_artifacts_to_repository(
            client, pulled_artifacts["logs"], repositories["logs_prn"], "log"
        )
        upload_info["uploaded_counts"]["logs"] = upload_count
        upload_info["upload_errors"].extend(errors)


def upload_rpms_logs(rpm_path: str, args: argparse.Namespace, client, arch: str,
                     *, rpm_repository_href: str, file_repository_prn: str, date: str) -> \
                     Tuple[List[str], List[Dict[str, str]]]:
    """
    Upload RPMs and logs for a specific architecture.

    This function handles the complete upload process for a single architecture,
    including checking existing RPMs on Pulp, uploading new RPMs, and uploading logs.

    Args:
        rpm_path: Path to directory containing RPM and log files
        args: Command line arguments containing build metadata
        client: PulpClient instance for API interactions
        arch: Architecture being processed
        rpm_repository_href: RPM repository href for adding content
        file_repository_prn: File repository PRN for log uploads
        date: Build date string

    Returns:
        Tuple of (uploaded_rpms, existing_artifacts) where:
            - uploaded_rpms: List of RPM files that were uploaded
            - existing_artifacts: List of artifact information for existing RPMs
    """
    # Find RPM and log files
    rpms = glob.glob(os.path.join(rpm_path, RPM_FILE_PATTERN))
    logs = glob.glob(os.path.join(rpm_path, LOG_FILE_PATTERN))

    if not rpms and not logs:
        logging.debug("No RPMs or logs found in %s", rpm_path)
        return [], []

    logging.info("Processing %s: %d RPMs, %d logs", arch, len(rpms), len(logs))
    labels = create_labels(args.build_id, arch, args.namespace, args.parent_package, date)
    rpms_to_upload, existing_artifacts = check_rpms_on_pulp(client, rpms)

    # Upload RPMs in parallel
    if rpms_to_upload:
        logging.info("Uploading %d RPMs for %s", len(rpms_to_upload), arch)
        rpm_results_artifacts = _upload_rpms_parallel(client, rpms_to_upload, labels, arch)

        # Add uploaded RPMs to the repository
        if rpm_results_artifacts:
            logging.debug("Adding %s RPM artifacts to repository", len(rpm_results_artifacts))
            rpm_repo_results = client.add_content(rpm_repository_href, rpm_results_artifacts)
            client.wait_for_finished_task(rpm_repo_results.json()['task'])
    else:
        logging.debug("No new RPMs to upload for %s", arch)

    # Upload logs sequentially
    if logs:
        logging.info("Uploading %d logs for %s", len(logs), arch)
        _upload_logs_sequential(client, logs,
                               file_repository_prn=file_repository_prn,
                               build_id=args.build_id, labels=labels, arch=arch)
    else:
        logging.debug("No logs to upload for %s", arch)

    return rpms_to_upload, existing_artifacts

# ============================================================================
# PulpHelper Class
# ============================================================================

class PulpHelper:
    """
    Helper class for Pulp operations including repositories, distributions, and other functionality.

    This class provides high-level methods for managing Pulp operations,
    delegating API calls to the PulpClient instance.
    """

    def __init__(self, pulp_client, cert_config_path: Optional[str] = None):
        """
        Initialize the helper with a PulpClient instance.

        Args:
            pulp_client: PulpClient instance for API interactions
            cert_config_path: Optional path to certificate config file for base URL construction
        """
        self.client = pulp_client
        self.cert_config_path = cert_config_path

    def setup_repositories(self, build_id: str) -> Dict[str, str]:
        """
        Setup all required repositories and return their identifiers.

        This method orchestrates the creation of all necessary repositories
        by delegating to the PulpClient API methods.

        Args:
            build_id: Build ID for naming repositories and distributions

        Returns:
            Dictionary mapping repository types to their PRNs and hrefs:
                - {repo_type}_prn: Repository PRN for each type
                - {repo_type}_href: Repository href for RPM repositories (None for file repos)
        """
        # Validate build ID
        if not validate_build_id(build_id):
            raise ValueError(f"Invalid build ID: {build_id}")

        # Sanitize build ID for repository naming
        sanitized_build_id = sanitize_build_id_for_repository(build_id)
        if sanitized_build_id != build_id:
            logging.info("Sanitized build ID '%s' to '%s' for repository naming", build_id, sanitized_build_id)

        logging.info("Setting up repositories for build: %s", sanitized_build_id)

        # Create repositories directly using the helper's own methods
        repositories = self._setup_repositories_impl(sanitized_build_id)

        # Validate the setup
        is_valid, errors = validate_repository_setup(repositories)
        if not is_valid:
            raise RuntimeError(f"Repository setup validation failed: {', '.join(errors)}")

        logging.info("Repository setup completed successfully")
        return repositories

    def get_distribution_urls(self, build_id: str) -> Dict[str, str]:
        """
        Get distribution URLs for all repository types.

        This method orchestrates the retrieval of distribution URLs
        by delegating to the PulpClient API methods.

        Args:
            build_id: Build ID for naming repositories and distributions

        Returns:
            Dictionary mapping repo_type to distribution URL
        """
        # Validate build ID
        if not validate_build_id(build_id):
            raise ValueError(f"Invalid build ID: {build_id}")

        # Sanitize build ID for repository naming
        sanitized_build_id = sanitize_build_id_for_repository(build_id)
        if sanitized_build_id != build_id:
            logging.info("Sanitized build ID '%s' to '%s' for repository naming", build_id, sanitized_build_id)

        logging.info("Getting distribution URLs for build: %s", sanitized_build_id)

        # Get distribution URLs directly using the helper's own methods
        distribution_urls = self._get_distribution_urls_impl(sanitized_build_id)

        logging.info("Retrieved %d distribution URLs", len(distribution_urls))
        return distribution_urls

    def create_or_get_repository(self, build_id: str, repo_type: str) -> Tuple[str, Optional[str]]:
        """
        Create or get a repository and distribution of the specified type.

        This method orchestrates the creation/retrieval of repositories
        by delegating to the PulpClient API methods.

        Args:
            build_id: Build ID for naming repositories and distributions
            repo_type: Type of repository ('rpms', 'logs', 'sbom', 'artifacts')

        Returns:
            Tuple of (repository_prn, repository_href) where href is None for file repos
        """
        # Validate inputs
        if not validate_build_id(build_id):
            raise ValueError(f"Invalid build ID: {build_id}")

        if repo_type not in REPOSITORY_TYPES:
            raise ValueError(f"Invalid repository type: {repo_type}")

        # Sanitize build ID for repository naming
        sanitized_build_id = sanitize_build_id_for_repository(build_id)
        if sanitized_build_id != build_id:
            logging.info("Sanitized build ID '%s' to '%s' for repository naming", build_id, sanitized_build_id)

        logging.info("Creating or getting repository: %s/%s", sanitized_build_id, repo_type)

        # Create or get repository directly using the helper's own methods
        repository_prn, repository_href = self._create_or_get_repository_impl(sanitized_build_id, repo_type)

        logging.info("Repository operation completed: %s/%s", sanitized_build_id, repo_type)
        return repository_prn, repository_href

    def get_repository_methods(self, repo_type: str) -> Dict[str, Any]:
        """
        Get the appropriate client methods for the repository type.

        Args:
            repo_type: Type of repository ('rpm' or 'file')

        Returns:
            Dictionary mapping method names to their implementations
        """
        return {
            'get': lambda name: self.client.repository_operation("get_repo", repo_type, name),
            'create': lambda name: self.client.repository_operation("create_repo", repo_type, name),
            'distro': lambda name, repository, basepath=None, publication=None:
                     self.client.repository_operation("create_distro", repo_type, name,
                                                    repository=repository, basepath=basepath,
                                                    publication=publication),
            'get_distro': lambda name: self.client.repository_operation("get_distro", repo_type, name),
            'update_distro': lambda distribution_href, publication:
                           self.client.repository_operation("update_distro", repo_type, "",
                                                           distribution_href=distribution_href,
                                                           publication=publication),
            'wait_for_finished_task': self.client.wait_for_finished_task
        }

    def _get_single_distribution_url(self, build_id: str, repo_type: str, base_url: str) -> Optional[str]:
        """Get distribution URL for a single repository type."""
        try:
            methods = self.get_repository_methods("rpm" if repo_type == "rpms" else "file")
            distribution_name = f"{build_id}/{repo_type}"

            # Get distribution information
            distro_response = methods['get_distro'](distribution_name)

            if distro_response.ok:
                distro_data = distro_response.json()
                if distro_data.get("results"):
                    distribution_info = distro_data["results"][0]
                    base_path = distribution_info.get("base_path", distribution_name)
                    distribution_url = f"{base_url}{base_path}/"
                    logging.debug("Found distribution URL for %s: %s", repo_type, distribution_url)
                    return distribution_url

                logging.warning("No distribution found for %s: %s", repo_type, distribution_name)
            else:
                logging.warning("Failed to get distribution for %s: %s - %s",
                              repo_type, distro_response.status_code, distro_response.text)

        except (requests.RequestException, ValueError, KeyError, AttributeError) as e:
            logging.warning("Error getting distribution URL for %s: %s", repo_type, sanitize_error_message(str(e)))
            logging.error("Traceback: %s", sanitize_error_message(traceback.format_exc()))

        return None

    def _get_distribution_urls_impl(self, build_id: str) -> Dict[str, str]:
        """
        Get distribution URLs for all repository types.

        Args:
            build_id: Base name for the repositories

        Returns:
            Dictionary mapping repo_type to distribution URL
        """
        distribution_urls = {}
        pulp_content_base_url = get_pulp_content_base_url(self.cert_config_path)
        base_url = f"{pulp_content_base_url}/{self.client.get_domain()}/"

        for repo_type in REPOSITORY_TYPES:
            url = self._get_single_distribution_url(build_id, repo_type, base_url)
            if url:
                distribution_urls[repo_type] = url

        return distribution_urls

    def _parse_repository_response(self, response, repo_type: str, operation: str) -> Dict[str, Any]:
        """Parse repository response JSON with error handling."""
        try:
            return response.json()
        except ValueError as e:
            logging.error("Failed to parse JSON response for %s repository %s: %s",
                         repo_type, operation, e)
            logging.error("Response content: %s", response.text[:500])
            logging.error("Traceback: %s", sanitize_error_message(traceback.format_exc()))
            raise ValueError(f"Invalid JSON response from Pulp API: {e}") from e

    def _get_existing_repository(self, methods: Dict[str, Any], full_name: str,
                                repo_type: str) -> Optional[Tuple[str, Optional[str]]]:
        """Check if repository exists and return its details."""
        repository_response = methods['get'](full_name)
        self.client.check_response(repository_response, f"check {repo_type} repository")

        response_data = self._parse_repository_response(repository_response, repo_type, "check")

        if response_data.get("results"):
            logging.debug("%s repository already exists: %s", repo_type.capitalize(), full_name)
            result = response_data["results"][0]
            return result["prn"], result.get("pulp_href")

        return None

    def _create_new_repository(self, methods: Dict[str, Any], full_name: str,
                              repo_type: str) -> Tuple[str, Optional[str]]:
        """Create a new repository and return its details."""
        logging.info("Creating %s repository: %s", repo_type, full_name)
        repository_response = methods['create'](full_name)
        self.client.check_response(repository_response, f"create {repo_type} repository")

        # Get the repository details
        repository_response = methods['get'](full_name)
        self.client.check_response(repository_response, f"get {repo_type} repository details")

        response_data = self._parse_repository_response(repository_response, repo_type, "details")
        result = response_data["results"][0]
        return result["prn"], result.get("pulp_href")

    def _wait_for_distribution_task(self, methods: Dict[str, Any], task_id: str, repo_type: str, build_id: str) -> None:
        """Wait for distribution creation task to complete."""
        task_response = methods['wait_for_finished_task'](task_id)
        try:
            task_data = task_response.json()
        except ValueError as e:
            logging.error("Failed to parse JSON response for distribution task: %s", sanitize_error_message(str(e)))
            logging.error("Response content: %s", task_response.text[:500])
            logging.error("Traceback: %s", sanitize_error_message(traceback.format_exc()))
            raise ValueError(f"Invalid JSON response from Pulp API: {e}") from e

        if task_data.get("created_resources"):
            logging.debug("Distribution creation completed. Created resources:")
            for resource in task_data["created_resources"]:
                logging.debug("  - %s", resource)
        else:
            logging.debug("Distribution creation completed for %s %s", repo_type, build_id)

    def _create_or_get_repository_impl(self, build_id: str, repo_type: str) -> Tuple[str, Optional[str]]:
        """
        Create or get a repository and distribution of the specified type.

        Args:
            build_id: Base name for the repository
            repo_type: Type of repository ('rpms', 'logs', 'sbom', 'artifacts')

        Returns:
            Tuple of (repository_prn, repository_href) where href is None for file repos
        """
        full_name = f"{build_id}/{repo_type}"
        api_type = "rpm" if repo_type == "rpms" else "file"
        methods = self.get_repository_methods(api_type)

        # Check if repository already exists
        existing_repo = self._get_existing_repository(methods, full_name, repo_type)
        if existing_repo:
            repository_prn, repository_href = existing_repo
        else:
            repository_prn, repository_href = self._create_new_repository(methods, full_name, repo_type)

        # Create distribution (always create, check for existing first)
        task_id = self._create_distribution_task(build_id, repo_type, repository_prn, methods)

        # If distribution was created, wait for it to complete
        if task_id:
            self._wait_for_distribution_task(methods, task_id, repo_type, build_id)

        return repository_prn, repository_href

    def _check_existing_distribution(self, methods: Dict[str, Any], full_name: str, repo_type: str) -> bool:
        """Check if distribution already exists."""
        try:
            logging.debug("Checking for existing %s distribution: %s", repo_type, full_name)
            distro_response = methods['get_distro'](full_name)
            logging.debug("Distribution check response status: %s", distro_response.status_code)

            response_data = self._parse_repository_response(distro_response, repo_type, "distribution check")
            logging.debug("Distribution check response data: %s", response_data)

            if response_data.get("results"):
                logging.debug("%s distribution already exists: %s", repo_type.capitalize(), full_name)
                return True

            logging.debug("No existing %s distribution found for: %s", repo_type, full_name)
            return False
        except AttributeError:
            logging.debug("Distribution check method not available for %s, will create", repo_type)
            return False  # Create distribution if check method doesn't exist
        except (requests.RequestException, ValueError, KeyError) as e:
            logging.warning("Error checking for existing distribution: %s", sanitize_error_message(str(e)))
            logging.error("Traceback: %s", sanitize_error_message(traceback.format_exc()))
            return False  # Continue with creation if check fails

    def _create_distribution_task(self, build_id: str, repo_type: str,
                                 repository_prn: str, methods: Dict[str, Any]) -> str:
        """Create a distribution for a repository and return the task ID."""
        full_name = f"{build_id}/{repo_type}"

        # Check if distribution already exists
        if self._check_existing_distribution(methods, full_name, repo_type):
            return None

        # Create distribution with the same name as the repository
        logging.debug("Creating %s distribution: %s", repo_type, full_name)
        distro_response = methods['distro'](full_name, repository_prn, basepath=full_name)
        self.client.check_response(distro_response, f"create {repo_type} distribution")

        response_data = self._parse_repository_response(distro_response, repo_type, "distribution creation")
        return response_data['task']

    def _setup_repositories_impl(self, build_id: str) -> Dict[str, str]:
        """
        Setup all required repositories and return their identifiers.

        This method creates or retrieves all necessary repositories (rpms, logs, sbom, artifacts)
        and their distributions in parallel for better performance.

        Args:
            build_id: Base name for the repositories

        Returns:
            Dictionary mapping repository types to their PRNs and hrefs:
                - {repo_type}_prn: Repository PRN for each type
                - {repo_type}_href: Repository href for RPM repositories (None for file repos)
        """
        logging.info("Setting up repositories for: %s", build_id)

        repositories = {}
        repo_types = REPOSITORY_TYPES

        # Create repositories in parallel for better performance
        with ThreadPoolExecutor(thread_name_prefix="setup_repositories",
                              max_workers=REPOSITORY_SETUP_MAX_WORKERS) as executor:
            # Submit all repository creation tasks
            future_to_repo = {
                executor.submit(self._create_or_get_repository_impl, build_id, repo_type):
                repo_type
                for repo_type in repo_types
            }

            # Collect results as they complete
            for future in as_completed(future_to_repo):
                repo_type = future_to_repo[future]
                try:
                    prn, href = future.result()
                    repositories[f"{repo_type}_prn"] = prn
                    if href:  # RPM repositories have href, file repositories don't
                        repositories[f"{repo_type}_href"] = href
                    logging.debug("Completed setup for %s repository", repo_type)
                except Exception as e:
                    logging.error("Failed to setup %s repository: %s", repo_type, sanitize_error_message(str(e)))
                    logging.error("Traceback: %s", sanitize_error_message(traceback.format_exc()))
                    raise

        return repositories

    def process_architecture_uploads(self, client, args, repositories: Dict[str, str],
                                   *, date_str: str, rpm_href: str) -> Dict[str, Any]:
        """
        Process uploads for all supported architectures.

        This function processes uploads for all supported architectures in parallel,
        handling RPM and log uploads for each architecture directory found.

        Args:
            client: PulpClient instance for API interactions
            args: Command line arguments
            repositories: Dictionary of repository identifiers
            date_str: Build date string
            rpm_href: RPM repository href for adding content

        Returns:
            Dictionary mapping architecture names to their upload results:
                - {arch}: Dictionary containing uploaded_rpms and existing_rpm_artifacts
        """
        # Find architectures that exist
        existing_archs = []
        for arch in SUPPORTED_ARCHITECTURES:
            arch_path = os.path.join(args.rpm_path, arch)
            if os.path.exists(arch_path):
                existing_archs.append(arch)
            else:
                logging.debug("Skipping %s - path does not exist: %s", arch, arch_path)

        if not existing_archs:
            logging.warning("No architecture directories found in %s", args.rpm_path)
            return {}

        processed_archs = {}

        # Process architectures in parallel for better performance
        with ThreadPoolExecutor(thread_name_prefix=ARCHITECTURE_THREAD_PREFIX,
                              max_workers=len(existing_archs)) as executor:
            # Submit all architecture processing tasks
            future_to_arch = {
                executor.submit(self._upload_rpms_logs_for_arch, os.path.join(args.rpm_path, arch),
                               args, client, arch,
                               rpm_repository_href=rpm_href,
                               file_repository_prn=repositories["logs_prn"],
                               date=date_str): arch
                for arch in existing_archs
            }

            # Collect results as they complete
            for future in as_completed(future_to_arch):
                arch = future_to_arch[future]
                try:
                    logging.debug("Processing architecture: %s", arch)
                    uploaded_rpms, existing_rpm_artifacts = future.result()
                    processed_archs[arch] = {
                        "uploaded_rpms": uploaded_rpms,
                        "existing_rpm_artifacts": existing_rpm_artifacts
                    }
                    logging.debug("Completed processing architecture: %s", arch)
                except Exception as e:
                    logging.error("Failed to process architecture %s: %s", arch, sanitize_error_message(str(e)))
                    logging.error("Traceback: %s", sanitize_error_message(traceback.format_exc()))
                    raise

            logging.info("Processed architectures: %s", ", ".join(processed_archs.keys()))
        return processed_archs

    def process_uploads(self, client, args, repositories: Dict[str, str],
                       *, date_str: str, upload_sbom_func, collect_results_func) -> Optional[str]:
        """
        Process all upload operations.

        This function orchestrates the complete upload process including processing
        all architectures, uploading SBOM, and collecting results.

        Args:
            client: PulpClient instance for API interactions
            args: Command line arguments
            repositories: Dictionary of repository identifiers
            date_str: Build date string
            upload_sbom_func: Function to upload SBOM
            collect_results_func: Function to collect results

        Returns:
            URL of the uploaded results JSON, or None if upload failed
        """
        # Ensure RPM repository href exists
        rpm_href = repositories.get("rpms_href")
        if not rpm_href:
            raise ValueError("RPM repository href is required but not found")

        # Process each architecture
        processed_uploads = self.process_architecture_uploads(
            client, args, repositories, date_str=date_str, rpm_href=rpm_href
        )
        existing_rpm_artifacts = [artifact for upload in processed_uploads.values()
                                 for artifact in upload["existing_rpm_artifacts"]]

        # Upload SBOM
        upload_sbom_func(client, args, repositories["sbom_prn"], date_str)

        # Collect and save results
        results_json_url = collect_results_func(
            client, args, date_str, repositories["artifacts_prn"], existing_rpm_artifacts
        )

        # Summary logging
        total_architectures = len(processed_uploads)
        total_existing = len(existing_rpm_artifacts)
        logging.info("Upload process completed: %d architectures processed, %d existing artifacts found",
                    total_architectures, total_existing)

        return results_json_url

    def _upload_rpms_logs_for_arch(self, rpm_path: str, args, client, arch: str,
                                  *, rpm_repository_href: str, file_repository_prn: str,
                                  date: str) -> Tuple[List[str], List[Dict[str, str]]]:
        """
        Upload RPMs and logs for a specific architecture.

        This method delegates to the upload_rpms_logs function in this module.
        """
        return upload_rpms_logs(rpm_path, args, client, arch,
                               rpm_repository_href=rpm_repository_href,
                               file_repository_prn=file_repository_prn,
                               date=date)
