#!/usr/bin/env python3
"""
Pulp pull script for downloading RPM packages, logs, and SBOM files.

This script provides functionality for downloading content from Pulp repositories
and organizing them by type and architecture.
"""

# Standard library imports
import argparse
import json
import logging
import os
import sys
import tempfile
import traceback
from concurrent.futures import ThreadPoolExecutor, as_completed
from typing import Dict, List, Tuple, Any, Optional

# Third-party imports
from requests import Session, exceptions, Response
import requests

# Local imports
from python_scripts.lib import sanitize_error_message, setup_logging
from python_scripts.lib.pulp.client import PulpClient
from python_scripts.lib.pulp.utils import (
    PulpHelper,
    determine_build_id,
    initialize_upload_tracking,
    upload_sboms_and_logs_from_artifacts,
    upload_rpms_from_artifacts,
    create_session_with_retry,
    read_file_with_base64_decode
)

# ============================================================================
# Distribution Client Class
# ============================================================================

class DistributionClient:
    """Client for downloading artifacts from distribution repositories."""

    def __init__(self, cert: str, key: str) -> None:
        """Initialize the distribution client with SSL certificates.

        Args:
            cert: Path to the SSL certificate file (may be base64 encoded)
            key: Path to the SSL private key file (may be base64 encoded)
        """
        # Read and decode base64 if encoded
        original_cert, cert_content = read_file_with_base64_decode(cert)
        original_key, key_content = read_file_with_base64_decode(key)

        # If content was base64 decoded, write to temporary files
        # Otherwise use original file paths
        self._temp_files = []
        if cert_content != original_cert:
            # Content was decoded, create temp file
            with tempfile.NamedTemporaryFile(mode='wb', delete=False, suffix='.crt') as temp_cert:
                temp_cert.write(cert_content)
                self.cert = temp_cert.name
            self._temp_files.append(self.cert)
            logging.debug("Decoded base64 certificate, using temporary file: %s", self.cert)
        else:
            self.cert = cert

        if key_content != original_key:
            # Content was decoded, create temp file
            with tempfile.NamedTemporaryFile(mode='wb', delete=False, suffix='.key') as temp_key:
                temp_key.write(key_content)
                self.key = temp_key.name
            self._temp_files.append(self.key)
            logging.debug("Decoded base64 key, using temporary file: %s", self.key)
        else:
            self.key = key

        self.session = self._create_session()

    def __del__(self):
        """Clean up temporary files if they were created."""
        for temp_file in getattr(self, '_temp_files', []):
            try:
                if os.path.exists(temp_file):
                    os.unlink(temp_file)
            except OSError:
                pass  # Ignore errors during cleanup

    def _create_session(self) -> Session:
        """Create a requests session with retry strategy and connection pooling."""
        return create_session_with_retry()

    def pull_artifact(self, file_url: str) -> Response:
        """Pull artifact metadata from the given URL.

        Args:
            file_url: URL to fetch artifact metadata from

        Returns:
            Response object containing artifact metadata as JSON
        """
        logging.info("Pulling files %s", file_url)
        return self.session.get(file_url, cert=(self.cert, self.key))

    def pull_data(self, filename: str, file_url: str, arch: str) -> str:
        """Download and save artifact data to local filesystem.

        Args:
            filename: Name of the file to save
            file_url: URL to download the file from
            arch: Architecture for organizing the file path

        Returns:
            Full path to the saved file
        """
        logging.info("Pulling file %s", file_url)
        file_full_filename = f"rpms/{arch}/{filename.split('/')[-1]}"
        os.makedirs(os.path.dirname(file_full_filename), exist_ok=True)

        response = self.session.get(file_url, stream=True, cert=(self.cert, self.key))
        response.raise_for_status()

        # Optimize chunk size based on content length
        content_length = response.headers.get('content-length')
        if content_length:
            file_size = int(content_length)
            # Use larger chunks for bigger files, but cap at 64KB
            chunk_size = min(max(8192, file_size // 100), 65536)
        else:
            chunk_size = 8192

        with open(file_full_filename, 'wb') as f:
            for chunk in response.iter_content(chunk_size=chunk_size):
                f.write(chunk)
        return file_full_filename

    def pull_data_async(self, download_info: Tuple[str, str, str, str]) -> Tuple[str, str]:
        """Download artifact data asynchronously.

        Args:
            download_info: Tuple of (artifact_name, file_url, arch, artifact_type)

        Returns:
            Tuple of (artifact_name, file_path)
        """
        artifact_name, file_url, arch, _ = download_info
        try:
            file_path = self.pull_data(artifact_name, file_url, arch)
            return artifact_name, file_path
        except exceptions.RequestException as e:
            logging.error("Failed to download %s: %s", artifact_name, e)
            logging.error("Traceback: %s", sanitize_error_message(traceback.format_exc()))
            raise

# ============================================================================
# Utility Functions
# ============================================================================

def _categorize_artifacts(artifacts: Dict[str, Any], distros: Dict[str, str]) -> List[Tuple[str, str, str, str]]:
    """Categorize artifacts and prepare download information.

    Args:
        artifacts: Dictionary of artifacts from the API response
        distros: Dictionary of distribution URLs

    Returns:
        List of download info tuples (artifact_name, file_url, arch, artifact_type)
    """
    download_tasks = []

    for artifact, keys in artifacts.items():
        arch = keys["labels"]["arch"]

        if "sbom" in artifact:
            file_url = f"{distros['sbom']}{artifact}"
            download_tasks.append((artifact, file_url, arch, "sbom"))
        elif "log" in artifact:
            file_url = f"{distros['logs']}{artifact}"
            download_tasks.append((artifact, file_url, arch, "log"))
        elif "rpm" in artifact:
            file_url = f"{distros['rpms']}Packages/l/{artifact}"
            download_tasks.append((artifact, file_url, arch, "rpm"))

    return download_tasks


def load_artifact_metadata(artifact_location: str, distribution_client: DistributionClient) -> Dict[str, Any]:
    """
    Load artifact metadata from either a local file or HTTP URL.

    Args:
        artifact_location: Path to local file or HTTP URL
        distribution_client: DistributionClient instance for HTTP requests

    Returns:
        Dictionary containing artifact metadata
    """
    if artifact_location.startswith(('http://', 'https://')):
        # HTTP URL - use distribution client
        logging.info("Loading artifact metadata from URL: %s", artifact_location)
        response = distribution_client.pull_artifact(artifact_location)

        # Check response status
        try:
            response.raise_for_status()
        except exceptions.HTTPError as e:
            logging.error("HTTP error when fetching artifact metadata from %s: %s", artifact_location, e)
            logging.error("Response status code: %d", response.status_code)
            logging.error("Response content (first 500 chars): %s", response.text[:500])
            raise

        # Try to parse JSON with better error handling
        try:
            return response.json()
        except json.JSONDecodeError as e:
            logging.error("Failed to parse JSON response from %s: %s", artifact_location, e)
            logging.error("Response status code: %d", response.status_code)
            logging.error("Response content type: %s", response.headers.get('content-type', 'unknown'))
            logging.error("Response content (first 1000 chars): %s", response.text[:1000])
            raise

    # Local file path
    logging.info("Loading artifact metadata from local file: %s", artifact_location)
    try:
        with open(artifact_location, 'r', encoding='utf-8') as f:
            return json.load(f)
    except FileNotFoundError:
        logging.error("Artifact file not found: %s", artifact_location)
        raise
    except json.JSONDecodeError as e:
        logging.error("Invalid JSON in artifact file %s: %s", artifact_location, e)
        raise
    except Exception as e:
        logging.error("Failed to read artifact file %s: %s", artifact_location, e)
        raise

# ============================================================================
# Upload Functions
# ============================================================================

def upload_downloaded_files_to_pulp(pulp_client: PulpClient, pulled_artifacts: Dict[str, Dict], args) -> Dict:
    """
    Upload downloaded files to the appropriate Pulp repositories.

    Args:
        pulp_client: PulpClient instance for API interactions
        pulled_artifacts: Dictionary containing downloaded artifacts organized by type
        args: Command line arguments

    Returns:
        Dictionary containing upload information including repository details
    """
    # Initialize PulpHelper to get repository information
    helper = PulpHelper(pulp_client, None)  # TODO: Add cert_config support to pulp-transfer

    # Determine build ID and setup repositories
    build_id = determine_build_id(args, pulled_artifacts=pulled_artifacts)
    repositories = helper.setup_repositories(build_id)

    # Initialize upload tracking
    upload_info = initialize_upload_tracking(build_id, repositories)

    # Upload different artifact types
    upload_sboms_and_logs_from_artifacts(pulp_client, pulled_artifacts, repositories, upload_info)
    upload_rpms_from_artifacts(pulp_client, pulled_artifacts, repositories, upload_info)

    return upload_info


# ============================================================================
# Reporting Functions
# ============================================================================

def _log_transfer_summary(completed: int, failed: int) -> None:
    """Log transfer summary statistics."""
    logging.info("TRANSFER SUMMARY:")
    logging.info("  Total artifacts processed: %d", completed + failed)
    logging.info("  Successfully downloaded: %d", completed)
    logging.info("  Failed downloads: %d", failed)
    success_rate = (completed / (completed + failed) * 100) if (completed + failed) > 0 else 0
    logging.info("  Success rate: %.1f%%", success_rate)

def _log_source_info(args: argparse.Namespace) -> None:
    """Log source information."""
    logging.info("SOURCE:")
    logging.info("  Artifact location: %s", args.artifact_location)
    logging.info("  Max workers used: %d", args.max_workers)

def _log_single_artifact(artifact_name: str, artifact_data: Dict) -> Tuple[int, int]:
    """Log information for a single artifact and return file count and size."""
    file_path = artifact_data["file"]
    labels = artifact_data.get("labels", {})

    # Get file size
    try:
        file_size = os.path.getsize(file_path)
        size_str = _format_file_size(file_size)
    except OSError:
        file_size = 0
        size_str = "Unknown size"

    # Extract key information from labels
    build_id = labels.get("build_id", "Unknown")
    arch = labels.get("arch", "Unknown")
    namespace = labels.get("namespace", "Unknown")

    logging.info("    - %s", artifact_name)
    logging.info("      Location: %s", file_path)
    logging.info("      Size: %s", size_str)
    logging.info("      Build ID: %s", build_id)
    logging.info("      Architecture: %s", arch)
    logging.info("      Namespace: %s", namespace)

    return 1, file_size


def _log_artifacts_downloaded(pulled_artifacts: Dict) -> Tuple[int, int]:
    """Log detailed breakdown of downloaded artifacts and return totals."""
    logging.info("ARTIFACTS DOWNLOADED:")

    total_files = 0
    total_size = 0

    for artifact_type, artifacts in pulled_artifacts.items():
        if artifacts:
            logging.info("  %s (%d files):", artifact_type.upper(), len(artifacts))

            for artifact_name, artifact_data in artifacts.items():
                file_count, file_size = _log_single_artifact(artifact_name, artifact_data)
                total_files += file_count
                total_size += file_size
        else:
            logging.info("  %s: No files downloaded", artifact_type.upper())

    return total_files, total_size

def _log_storage_summary(total_files: int, total_size: int, pulled_artifacts: Dict) -> None:
    """Log storage summary and locations."""
    logging.info("STORAGE SUMMARY:")
    logging.info("  Total files stored: %d", total_files)
    logging.info("  Total size: %s", _format_file_size(total_size))

    # Storage locations
    if total_files > 0:
        logging.info("STORAGE LOCATIONS:")
        storage_locations = set()
        for artifacts in pulled_artifacts.values():
            for artifact_data in artifacts.values():
                file_path = artifact_data["file"]
                storage_dir = os.path.dirname(file_path)
                storage_locations.add(storage_dir)

        for location in sorted(storage_locations):
            logging.info("  - %s", location)

def _log_pulp_upload_info(upload_info: Optional[Dict]) -> None:
    """Log Pulp upload information."""
    if upload_info:
        logging.info("PULP UPLOAD SUMMARY:")
        logging.info("  Build ID: %s", upload_info.get("build_id", "Unknown"))

        # Repository information
        repositories = upload_info.get("repositories", {})
        if repositories:
            logging.info("  REPOSITORIES CREATED:")
            for repo_type, repo_info in repositories.items():
                if isinstance(repo_info, dict) and "name" in repo_info:
                    logging.info("    - %s: %s", repo_type.replace("_prn", "").upper(), repo_info["name"])
                elif isinstance(repo_info, str):
                    logging.info("    - %s: %s", repo_type.replace("_prn", "").upper(), repo_info)

        # Upload counts
        uploaded_counts = upload_info.get("uploaded_counts", {})
        total_uploaded = sum(uploaded_counts.values())
        if total_uploaded > 0:
            logging.info("  UPLOADED TO PULP:")
            for artifact_type, count in uploaded_counts.items():
                if count > 0:
                    logging.info("    - %s: %d files", artifact_type.upper(), count)
            logging.info("    - Total uploaded: %d files", total_uploaded)
        else:
            logging.info("  No files uploaded to Pulp")

        # Upload errors
        upload_errors = upload_info.get("upload_errors", [])
        if upload_errors:
            logging.info("  UPLOAD ERRORS:")
            for error in upload_errors:
                logging.info("    - %s", error)
    else:
        logging.info("PULP UPLOAD SUMMARY:")
        logging.info("  No Pulp client available - files not uploaded to repositories")

def _log_build_information(pulled_artifacts: Dict) -> None:
    """Log build information summary."""
    logging.info("BUILD INFORMATION:")
    build_ids = set()
    architectures = set()
    namespaces = set()

    for artifacts in pulled_artifacts.values():
        for artifact_data in artifacts.values():
            labels = artifact_data.get("labels", {})
            if labels.get("build_id"):
                build_ids.add(labels["build_id"])
            if labels.get("arch"):
                architectures.add(labels["arch"])
            if labels.get("namespace"):
                namespaces.add(labels["namespace"])

    if build_ids:
        logging.info("  Build IDs: %s", ', '.join(sorted(build_ids)))
    if architectures:
        logging.info("  Architectures: %s", ', '.join(sorted(architectures)))
    if namespaces:
        logging.info("  Namespaces: %s", ', '.join(sorted(namespaces)))

def _generate_transfer_report(pulled_artifacts: Dict, completed: int, failed: int,
                             args: argparse.Namespace,
                             upload_info: Optional[Dict] = None) -> None:
    """
    Generate and display a comprehensive report of what was transferred and where it was stored.

    Args:
        pulled_artifacts: Dictionary containing all pulled artifacts organized by type
        completed: Number of successfully downloaded artifacts
        failed: Number of failed downloads
        args: Command line arguments for context
        upload_info: Optional dictionary containing upload information from Pulp
    """
    logging.info("=" * 60)
    logging.info("PULP TRANSFER REPORT")
    logging.info("=" * 60)

    _log_transfer_summary(completed, failed)
    _log_source_info(args)
    total_files, total_size = _log_artifacts_downloaded(pulled_artifacts)
    _log_storage_summary(total_files, total_size, pulled_artifacts)
    _log_pulp_upload_info(upload_info)
    _log_build_information(pulled_artifacts)

    logging.info("=" * 60)
    logging.info("Transfer completed successfully!")
    logging.info("=" * 60)

def _format_file_size(size_bytes: int) -> str:
    """
    Format file size in human-readable format.

    Args:
        size_bytes: Size in bytes

    Returns:
        Formatted size string
    """
    if size_bytes == 0:
        return "0 B"

    size_names = ["B", "KB", "MB", "GB", "TB"]
    i = 0
    while size_bytes >= 1024 and i < len(size_names) - 1:
        size_bytes /= 1024.0
        i += 1

    return f"{size_bytes:.1f} {size_names[i]}"

# ============================================================================
# Main Functions
# ============================================================================

def _initialize_clients(args: argparse.Namespace) -> DistributionClient:
    """Initialize the distribution client for downloading files.

    Args:
        args: Command line arguments

    Returns:
        Initialized DistributionClient instance
    """
    logging.info("Initializing distribution client...")
    return DistributionClient(args.cert_path, args.key_path)

def _load_and_validate_artifacts(args: argparse.Namespace,
                                distribution_client: DistributionClient) -> Tuple[Dict[str, Any], Dict[str, Any]]:
    """Load artifact metadata and validate it contains artifacts.

    Args:
        args: Command line arguments
        distribution_client: DistributionClient for loading metadata

    Returns:
        Tuple of (artifact_json, artifacts)

    Raises:
        SystemExit: If no artifacts are found
    """
    logging.info("Loading artifact metadata...")
    artifact_json = load_artifact_metadata(args.artifact_location, distribution_client)

    artifacts = artifact_json.get("artifacts", {})
    if not artifacts:
        logging.warning("No artifacts found in the response")
        sys.exit(0)

    return artifact_json, artifacts

def _download_artifacts_concurrently(artifacts: Dict[str, Any], distros: Dict[str, str],
                                   distribution_client: DistributionClient,
                                   max_workers: int) -> Tuple[Dict[str, Dict], int, int]:
    """Download all artifacts concurrently using thread pool.

    Args:
        artifacts: Dictionary of artifacts to download
        distros: Dictionary of distribution URLs
        distribution_client: DistributionClient for downloading
        max_workers: Maximum number of concurrent workers

    Returns:
        Tuple of (pulled_artifacts, completed_count, failed_count)
    """
    # Prepare download tasks
    download_tasks = _categorize_artifacts(artifacts, distros)
    total_artifacts = len(download_tasks)

    logging.info("Starting download of %d artifacts with %d workers",
                total_artifacts, max_workers)

    # Initialize artifact storage structure
    pulled_artifacts = {
        "sboms": {},
        "logs": {},
        "rpms": {}
    }

    # Download artifacts concurrently
    completed = 0
    failed = 0

    with ThreadPoolExecutor(max_workers=max_workers) as executor:
        # Submit all download tasks
        future_to_artifact = {
            executor.submit(distribution_client.pull_data_async, task): task[0]
            for task in download_tasks
        }

        # Process completed downloads
        for future in as_completed(future_to_artifact):
            artifact_name = future_to_artifact[future]
            try:
                artifact_name, file_path = future.result()

                # Find the original artifact info to get labels
                artifact_info = artifacts[artifact_name]

                # Determine artifact type and store
                if "sbom" in artifact_name:
                    pulled_artifacts["sboms"][artifact_name] = {
                        "file": file_path,
                        "labels": artifact_info["labels"]
                    }
                elif "log" in artifact_name:
                    pulled_artifacts["logs"][artifact_name] = {
                        "file": file_path,
                        "labels": artifact_info["labels"]
                    }
                elif "rpm" in artifact_name:
                    pulled_artifacts["rpms"][artifact_name] = {
                        "file": file_path,
                        "labels": artifact_info["labels"]
                    }

                completed += 1
                if completed % 10 == 0 or completed == total_artifacts:
                    logging.info("Downloaded %d/%d artifacts", completed, total_artifacts)

            except exceptions.RequestException as e:
                failed += 1
                logging.error("Failed to download %s: %s", artifact_name, e)
                logging.error("Traceback: %s", sanitize_error_message(traceback.format_exc()))

    logging.info("Download completed: %d successful, %d failed", completed, failed)
    return pulled_artifacts, completed, failed

def _handle_pulp_upload(pulp_client: Optional[PulpClient], pulled_artifacts: Dict[str, Dict],
                       args: argparse.Namespace) -> Optional[Dict]:
    """Handle uploading downloaded files to Pulp repositories.

    Args:
        pulp_client: PulpClient instance if available
        pulled_artifacts: Downloaded artifacts to upload
        args: Command line arguments

    Returns:
        Upload information dictionary or None if no client available
    """
    if pulp_client:
        logging.info("Uploading downloaded files to Pulp repositories...")
        return upload_downloaded_files_to_pulp(pulp_client, pulled_artifacts, args)

    logging.info("No Pulp client available, skipping upload to repositories")
    return None

def main() -> None:
    """Main function for Pulp pull operations."""
    args = _parse_arguments()
    setup_logging(args.debug)

    try:
        # Initialize distribution client (always needed for downloading files)
        distribution_client = _initialize_clients(args)

        # Initialize Pulp client if configuration is provided
        client = None
        if args.config:
            client = PulpClient.create_from_config_file(
                path=args.config
            )

        if not args.artifact_location and (args.namespace and args.build_id):
            if not client:
                logging.error("Pulp client required to construct artifact_location from namespace and build_id")
                sys.exit(1)
            # construct the artifact_location
            args.artifact_location = (f"{client.config['base_url']}/api/pulp-content/{args.namespace}"
                                      f"/{args.namespace}-{args.build_id}/artifacts/pulp_results.json")

        # Load artifact metadata and validate
        artifact_json, artifacts = _load_and_validate_artifacts(args, distribution_client)

        # Process artifacts by type
        distros = artifact_json.get("distributions", {})

        # Download artifacts concurrently
        pulled_artifacts, completed, failed = _download_artifacts_concurrently(
            artifacts, distros, distribution_client, args.max_workers
        )

        # Set up repositories if configuration is provided
        if client:
            try:
                build_id = determine_build_id(args, artifact_json=artifact_json)
                logging.info("Setting up repositories for pull operations: %s", build_id)
                repository_helper = PulpHelper(client, None)  # TODO: Add cert_config support to pulp-transfer
                repository_helper.setup_repositories(build_id)
                logging.info("Repository setup completed for pull operations")
            except (ValueError, RuntimeError, requests.RequestException) as e:
                logging.warning("Failed to setup repositories: %s", sanitize_error_message(str(e)))
                logging.warning("Continuing with distribution-only mode")
        else:
            logging.debug("No Pulp configuration provided, skipping repository setup")

        # Upload downloaded files to Pulp repositories if client is available
        upload_info = _handle_pulp_upload(client, pulled_artifacts, args)

        # Generate and display transfer report
        _generate_transfer_report(pulled_artifacts, completed, failed, args, upload_info)

        logging.info("All operations completed successfully")

    except exceptions.RequestException as e:
        logging.error("Fatal error during execution: %s", e)
        logging.error("Traceback: %s", traceback.format_exc())
        sys.exit(1)
    finally:
        # Ensure pulp client session is properly closed if it was created
        if 'client' in locals() and client:
            client.close()
            logging.debug("PulpClient session closed")

def _parse_arguments() -> argparse.Namespace:
    """Parse and validate command line arguments.

    Returns:
        Parsed command line arguments as argparse.Namespace
    """
    parser = argparse.ArgumentParser(
        description="Download RPM packages, logs, and SBOM files from Pulp repositories",
        formatter_class=argparse.RawDescriptionHelpFormatter
    )

    # Required arguments
    parser.add_argument("--cert_path", required=True,
                       help="Path to SSL certificate file for authentication")
    parser.add_argument("--key_path", required=True,
                       help="Path to SSL private key file for authentication")

    # Optional arguments
    parser.add_argument("--config",
                       help="Path to Pulp CLI config file (default: ~/.config/pulp/cli.toml)")
    parser.add_argument("--build_id",
                       help="Build ID for naming repositories and distributions")
    parser.add_argument("--namespace",
                       help="Namespace for naming repositories and distributions")
    parser.add_argument("--artifact_location",
                       help="Path to local artifact metadata JSON file or HTTP URL to artifact metadata")
    parser.add_argument("-d", "--debug", action="store_true",
                       help="Enable debug logging")
    parser.add_argument("--max-workers", type=int, default=10,
                       help="Maximum number of concurrent download threads (default: 10)")

    return parser.parse_args()

if __name__ == "__main__":
    main()
