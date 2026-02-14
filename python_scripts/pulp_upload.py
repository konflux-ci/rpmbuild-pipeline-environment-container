#!/usr/bin/env python3
"""
Pulp upload script for uploading RPM packages, logs, and SBOM files.

This script provides functionality for uploading content to Pulp repositories
using the PulpClient from pulp_client.py.
"""

# Standard library imports
import argparse
import json
import logging
import os
import sys
import traceback
from datetime import datetime, timezone
from typing import Any, Dict, List, Optional, Tuple

# Third-party imports
import requests

# Local imports
from common_utils import sanitize_error_message, setup_logging
from pulp_client import PulpClient
from pulp_utils import (
    PulpHelper,
    validate_file_path,
    RESULTS_JSON_FILENAME,
    create_labels,
)

# ============================================================================
# Constants
# ============================================================================

# Configuration constants
# All constants are now imported from pulp_utils
MAX_LOG_LINE_LENGTH = 114

# ============================================================================
# SBOM and Results Functions
# ============================================================================

def upload_sbom(client: PulpClient, args: argparse.Namespace,
                sbom_repository_prn: str, date: str) -> None:
    """
    Upload SBOM file to repository.

    Args:
        client: PulpClient instance for API interactions
        args: Command line arguments containing SBOM path
        sbom_repository_prn: SBOM repository PRN
        date: Build date string
    """
    if not os.path.exists(args.sbom_path):
        logging.error("SBOM file not found: %s", args.sbom_path)
        return

    logging.info("Uploading SBOM: %s", args.sbom_path)
    labels = create_labels(args.build_id, "", args.namespace, args.parent_package, date)
    validate_file_path(args.sbom_path, "SBOM")

    content_upload_response = client.create_file_content(
        sbom_repository_prn, args.sbom_path,
        build_id=args.build_id, pulp_label=labels
    )

    client.check_response(content_upload_response, f"upload SBOM {args.sbom_path}")
    client.wait_for_finished_task(content_upload_response.json()['task'])
    logging.debug("SBOM uploaded successfully: %s", args.sbom_path)


def _gather_content_and_artifacts(client: PulpClient, args: argparse.Namespace,
                                 extra_artifacts: List[Dict[str, str]] = None) -> Tuple[Any, Any]:
    """Gather content data and artifacts for results collection."""
    content_results, artifacts = client.gather_content_data(args.build_id, extra_artifacts)

    if not content_results:
        logging.warning("No content found for build ID: %s", args.build_id)
        return None, None

    return content_results, artifacts


def _build_results_structure(client: PulpClient, args: argparse.Namespace,
                           content_results: Any, artifacts: Any) -> Dict[str, Any]:
    """Build the complete results structure with distributions."""
    # Get file locations and build mapping
    file_locations_json = client.get_file_locations(artifacts).json()["results"]
    file_info_map = {file_info["pulp_href"]: file_info for file_info in file_locations_json}

    # Build the results structure
    results = client.build_results_structure(content_results, file_info_map)
    results["distributions"] = {}

    # Add distribution URLs
    _add_distribution_urls(client, args, results)

    return results


def _add_distribution_urls(client: PulpClient, args: argparse.Namespace, results: Dict[str, Any]) -> None:
    """Add distribution URLs to results structure."""
    repository_helper = PulpHelper(client, getattr(args, 'cert_config', 'cli.toml'))
    distribution_urls = repository_helper.get_distribution_urls(args.build_id)

    if distribution_urls:
        results["distributions"] = distribution_urls
        logging.info("Added distribution URLs for %d repository types", len(distribution_urls))
        for repo_type, url in distribution_urls.items():
            logging.debug("Distribution URL for %s: %s", repo_type, url)
    else:
        logging.warning("No distribution URLs found")


def _serialize_results_to_json(results: Dict[str, Any]) -> str:
    """Serialize results to JSON with error handling."""
    try:
        logging.debug("Results data before JSON serialization: %s", results)
        json_content = json.dumps(results, indent=2)
        logging.debug("Successfully created JSON content, length: %d", len(json_content))
        preview = json_content[:500] + "..." if len(json_content) > 500 else json_content
        logging.debug("JSON content preview: %s", preview)
        return json_content
    except (TypeError, ValueError) as e:
        logging.error("Failed to serialize results to JSON: %s", sanitize_error_message(str(e)))
        logging.error("Results data: %s", results)
        logging.error("Traceback: %s", sanitize_error_message(traceback.format_exc()))
        _diagnose_serialization_error(results)
        raise


def _diagnose_serialization_error(results: Dict[str, Any]) -> None:
    """Diagnose which part of results is causing serialization error."""
    for key, value in results.items():
        try:
            json.dumps(value)
            logging.debug("Key '%s' serializes successfully", key)
        except (TypeError, ValueError) as key_error:
            logging.error("Key '%s' failed to serialize: %s", key, sanitize_error_message(str(key_error)))
            logging.error("Key error traceback: %s", sanitize_error_message(traceback.format_exc()))


def _upload_and_get_results_url(client: PulpClient, args: argparse.Namespace,
                               artifact_repository_prn: str, json_content: str,
                               date: str) -> Optional[str]:
    """Upload results JSON and return the distribution URL."""
    # Upload results JSON
    labels = create_labels(args.build_id, "", args.namespace, args.parent_package, date)
    content_upload_response = client.create_file_content(
        artifact_repository_prn, json_content,
        build_id=args.build_id, pulp_label=labels, filename=RESULTS_JSON_FILENAME
    )

    try:
        client.check_response(content_upload_response, "upload results JSON")
        task_response = client.wait_for_finished_task(content_upload_response.json()['task'])
        logging.info("Results JSON uploaded successfully")

        # Get results URL and handle artifacts
        results_json_url = _extract_results_url(client, args, task_response)
        _handle_artifact_results_if_requested(client, args, task_response, results_json_url)

        return results_json_url

    except Exception as e:
        logging.error("Failed to upload results JSON: %s", sanitize_error_message(str(e)))
        logging.error("Traceback: %s", sanitize_error_message(traceback.format_exc()))
        raise


def _extract_results_url(client: PulpClient, args: argparse.Namespace, task_response: Any) -> str:
    """Extract results JSON URL from task response."""
    task_resp = task_response.json()
    logging.debug("Task response for results JSON: %s", task_resp)

    distro_name = f"{args.build_id}/artifacts"
    return f"{client.get_domain()}/{distro_name}/{task_resp["result"]["relative_path"]}"


def _handle_artifact_results_if_requested(client: PulpClient, args: argparse.Namespace,
                                         task_response: Any, results_json_url: str) -> None:
    """Handle artifact results for Konflux if requested."""
    if args.artifact_results:
        _handle_artifact_results(client, args, task_response)
    else:
        logging.info("Results JSON available at: %s", results_json_url)


def collect_results(client: PulpClient, args: argparse.Namespace, date: str,
                   artifact_repository_prn: str,
                    extra_artifacts: List[Dict[str, str]] = None) -> Optional[str]:
    """
    Collect results and upload JSON directly from memory.

    This function gathers all uploaded content, creates a structured results JSON,
    and uploads it to the artifacts repository.

    Args:
        client: PulpClient instance for API interactions
        args: Command line arguments
        date: Build date string
        artifact_repository_prn: Artifacts repository PRN
        extra_artifacts: Optional list of extra artifacts to include

    Returns:
        URL of the uploaded results JSON, or None if upload failed
    """
    logging.info("Collecting results for build ID: %s", args.build_id)

    # Gather content data and artifacts
    content_results, artifacts = _gather_content_and_artifacts(client, args, extra_artifacts)
    if content_results is None:
        return None

    # Build the results structure
    results = _build_results_structure(client, args, content_results, artifacts)

    # Handle SBOM results if requested
    if args.sbom_results:
        _handle_sbom_results_from_json(results, args)

    # Serialize results to JSON
    json_content = _serialize_results_to_json(results)

    # Upload and get results URL
    return _upload_and_get_results_url(client, args, artifact_repository_prn, json_content, date)



def _handle_artifact_results(client: PulpClient, args: argparse.Namespace,
                                        task_response: Any) -> None:
    """
    Handle artifact results for Konflux integration using in-memory data.

    This function processes the task response to extract artifact information
    and writes the results to files specified in the artifact_results argument.

    Args:
        client: PulpClient instance for API interactions
        args: Command line arguments containing artifact_results path
        task_response: Response from the upload task
    """
    resp = task_response.json()
    logging.debug("Task response: %s", resp)

    # Find the created content
    artifact_href = next(
        (a for a in resp["created_resources"] if "content" in a),
        None
    )

    if not artifact_href:
        logging.error("No content artifact found in task response")
        return

    content_resp = client.find_content("href", artifact_href).json()["results"]
    if not content_resp:
        logging.error("No content found for href: %s", artifact_href)
        return

    content_list_location = client.get_file_locations(
        [content_resp[0]["artifacts"]]
    ).json()["results"][0]

    # Parse and write artifact results
    try:
        image_url_path, image_digest_path = args.artifact_results.split(",")

        with open(image_url_path, "w", encoding="utf-8") as f:
            f.write(content_list_location["file"])

        with open(image_digest_path, "w", encoding="utf-8") as f:
            f.write(f"sha256:{content_list_location['sha256']}")

        logging.info("Artifact results written to %s and %s", image_url_path, image_digest_path)

    except ValueError as e:
        logging.error("Invalid artifact_results format: %s", sanitize_error_message(str(e)))
        logging.error("Traceback: %s", sanitize_error_message(traceback.format_exc()))


def _handle_sbom_results_from_json(results: Dict[str, Any], args: argparse.Namespace) -> None:
    """
    Handle SBOM results for Konflux integration using results JSON data.

    This function extracts SBOM information from the results JSON structure
    and writes the results to the file specified in the sbom_results argument.

    Args:
        results: Results JSON structure containing artifacts
        args: Command line arguments containing sbom_results path
    """
    # Look for SBOM in the artifacts
    artifacts = results.get("artifacts", {})
    sbom_info = None

    # Find SBOM artifact by looking for SBOM-related keys
    for artifact_key, artifact_data in artifacts.items():
        if "sbom" in artifact_key.lower() or "spdx" in artifact_key.lower():
            sbom_info = artifact_data
            break

    if not sbom_info:
        logging.warning("No SBOM artifact found in results")
        return

    # Extract URL and SHA256 from SBOM info
    sbom_url = sbom_info.get("url", "")
    sbom_sha256 = sbom_info.get("sha256", "")

    if not sbom_url or not sbom_sha256:
        logging.error("SBOM URL or SHA256 missing from results")
        return

    # Write SBOM results to file
    try:
        with open(args.sbom_results, "w", encoding="utf-8") as f:
            f.write(f"{sbom_url}@sha256:{sbom_sha256}")

        logging.info("SBOM results written to %s", args.sbom_results)

    except (FileNotFoundError, PermissionError, OSError) as e:
        logging.error("Failed to write SBOM results: %s", sanitize_error_message(str(e)))
        logging.error("Traceback: %s", sanitize_error_message(traceback.format_exc()))


# ============================================================================
# Main Functions
# ============================================================================

def main() -> None:
    """
    Main function for Pulp upload operations.

    This function orchestrates the entire upload process including:
    - Repository setup
    - Content upload (RPMs, logs, SBOM)
    - Results collection and JSON generation
    - Distribution URL reporting
    """
    args = _parse_arguments()
    setup_logging(args.debug, use_wrapping=True)

    client = None
    try:
        # Initialize client and timestamp
        client = PulpClient.create_from_config_file(
            path=args.config, namespace=args.namespace
        )
        date_str = datetime.now(timezone.utc).strftime('%Y-%m-%d %H:%M:%S')

        # Setup repositories using helper
        repository_helper = PulpHelper(client, getattr(args, 'cert_config', 'cli.toml'))
        repositories = repository_helper.setup_repositories(args.build_id)
        logging.info("Repository setup completed")

        # Process uploads
        logging.info("Starting upload process")
        results_json_url = repository_helper.process_uploads(
            client, args, repositories,
            date_str=date_str, upload_sbom_func=upload_sbom, collect_results_func=collect_results
        )

        logging.info("All operations completed successfully")

        # Report the results JSON URL
        if results_json_url:
            print(f"\n{'='*80}")
            print(f"RESULTS JSON URL: {results_json_url}")
            if not args.artifact_results:
                print("NOTE: Results JSON created but not written to Konflux artifact files")
                print("      Use --artifact_results to specify file paths for Konflux integration")
            print("="*80)
        else:
            logging.warning("Results JSON URL not available")

    except requests.exceptions.RequestException as e:
        logging.error("Fatal error during execution: %s", sanitize_error_message(str(e)))
        logging.error("Traceback: %s", sanitize_error_message(traceback.format_exc()))
        sys.exit(1)
    finally:
        # Ensure client session is properly closed
        if client:
            client.close()
            logging.debug("Client session closed")


def _parse_arguments() -> argparse.Namespace:
    """
    Parse and validate command line arguments.

    This function sets up the argument parser with all required and optional
    arguments for the Pulp upload script.

    Returns:
        Parsed command line arguments as argparse.Namespace
    """
    parser = argparse.ArgumentParser(
        description="Upload RPM packages, logs, and SBOM files to Pulp repositories",
        formatter_class=argparse.RawDescriptionHelpFormatter
    )

    # Required arguments
    parser.add_argument("--rpm_path", required=True,
                       help="Root path to the RPM packages (should contain arch subdirs)")
    parser.add_argument("--sbom_path", required=True,
                       help="Path to the SBOM file")
    parser.add_argument("--build_id", required=True,
                       help="Unique build identifier")
    parser.add_argument("--namespace", required=True,
                       help="Namespace for this upload operation")
    parser.add_argument("--parent_package", required=True,
                       help="Parent package name")

    # Optional arguments
    parser.add_argument("--config",
                       help="Path to Pulp CLI config file (default: ~/.config/pulp/cli.toml)")
    parser.add_argument("--cert_config",
                       help="Path to certificate config file for base URL construction")
    parser.add_argument("--artifact_results",
                       help="Comma-separated paths for Konflux artifact location "
                            "(url_path,digest_path)")
    parser.add_argument("--sbom_results",
                       help="Comma-separated paths for Konflux sbom locaiton "
                            "(url_path,digest_path)")
    parser.add_argument("-d", "--debug", action="store_true",
                       help="Enable debug logging")

    return parser.parse_args()

if __name__ == "__main__":
    main()
