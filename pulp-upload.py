#!/usr/bin/env python3
"""
Pulp API client for uploading RPM packages, logs, and SBOM files.

This module provides a client for interacting with Pulp API to manage
RPM repositories, file repositories, and content uploads with OAuth2 authentication.
"""

import argparse
import concurrent.futures
import glob
import json
import logging
import os
import sys
import time
import tomllib
from datetime import datetime, timedelta, timezone
from pathlib import Path
from typing import Any, Dict, List, Optional, Tuple, Union
from urllib.parse import urlencode

import requests
from requests.adapters import HTTPAdapter
from requests.models import Response
from urllib3.util import Retry

# Constants
DEFAULT_TIMEOUT = 60
DEFAULT_CONFIG_PATH = "~/.config/pulp/cli.toml"
DEFAULT_OUTPUT_JSON = "pulp_results.json"
DEFAULT_MAX_WORKERS = 3
DEFAULT_TASK_TIMEOUT = 86400
TASK_SLEEP_INTERVAL = 5
SUPPORTED_ARCHITECTURES = ["x86_64", "aarch64", "s390x", "ppc64le"]

# HTTP status codes to retry on
RETRY_STATUS_CODES = [429, 500, 502, 503, 504]


class OAuth2ClientCredentialsAuth(requests.auth.AuthBase):
    """
    OAuth2 Client Credentials Grant authentication flow implementation.
    Based on pulp-cli's authentication mechanism.

    This handles automatic token retrieval, refresh, and 401 retry logic.
    """

    def __init__(
        self,
        client_id: str,
        client_secret: str,
        token_url: str,
    ):
        """
        Initialize OAuth2 authentication.

        Args:
            client_id: OAuth2 client ID
            client_secret: OAuth2 client secret
            token_url: URL for token endpoint (e.g., "https://console.redhat.com/token")
        """
        self._token_server_auth = requests.auth.HTTPBasicAuth(client_id, client_secret)
        self._token_url = token_url

        self._access_token: Optional[str] = None
        self._expire_at: Optional[datetime] = None

    def __call__(self, request: requests.PreparedRequest) -> requests.PreparedRequest:
        """Apply OAuth2 authentication to the request."""
        # Check if we need to fetch/refresh token
        if self._expire_at is None or self._expire_at < datetime.now():
            self._retrieve_token()

        if self._access_token is None:
            raise RuntimeError("Failed to obtain access token")

        request.headers["Authorization"] = f"Bearer {self._access_token}"

        # Register 401 handler for automatic token refresh
        request.hooks["response"].append(self._handle401)
        return request

    def _handle401(
        self,
        response: requests.Response,
        **kwargs: Any,
    ) -> requests.Response:
        """Handle 401 responses by refreshing token and retrying once."""
        if response.status_code != 401:
            return response

        # Token probably expired, get a new one
        self._retrieve_token()
        if self._access_token is None:
            logging.error("Failed to refresh access token")
            return response

        # Consume content and release the original connection
        _ = response.content
        response.close()

        # Prepare new request with fresh token
        prepared_new_request = response.request.copy()
        prepared_new_request.headers["Authorization"] = f"Bearer {self._access_token}"

        # Avoid infinite loop by removing the 401 handler
        prepared_new_request.deregister_hook("response", self._handle401)

        # Send the new request
        new_response: requests.Response = response.connection.send(prepared_new_request, **kwargs)
        new_response.history.append(response)
        new_response.request = prepared_new_request

        return new_response

    def _retrieve_token(self) -> None:
        """Fetch a new OAuth2 access token."""
        data = {"grant_type": "client_credentials"}

        try:
            response = requests.post(
                self._token_url,
                data=data,
                auth=self._token_server_auth,
                timeout=30,
            )
            response.raise_for_status()

            token = response.json()
            if "access_token" not in token or "expires_in" not in token:
                raise ValueError("Invalid token response format")

            self._expire_at = datetime.now() + timedelta(seconds=token["expires_in"])
            self._access_token = token["access_token"]

        except requests.RequestException as e:
            logging.error("Failed to retrieve OAuth2 token: %s", e)
            raise

    @property
    def access_token(self) -> Optional[str]:
        """Get the current access token (for debugging/inspection)."""
        return self._access_token

    @property
    def expires_at(self) -> Optional[datetime]:
        """Get the token expiration time (for debugging/inspection)."""
        return self._expire_at


class PulpClient:
    """
    A client for interacting with Pulp API.

    API documentation:
    - https://docs.pulpproject.org/pulp_rpm/restapi.html
    - https://docs.pulpproject.org/pulpcore/restapi.html

    A note regarding PUT vs PATCH:
    - PUT changes all data and therefore all required fields need to be sent
    - PATCH changes only the data that we are sending

    Many methods require repository, distribution, publication, etc,
    to be the full API endpoint (called "pulp_href"), not simply their name.
    If method argument doesn't have "name" in its name, assume it expects
    pulp_href. It looks like this:
    /pulp/api/v3/publications/rpm/rpm/5e6827db-260f-4a0f-8e22-7f17d6a2b5cc/
    """

    def __init__(self, config: Dict[str, Union[str, int]], domain: Optional[str] = None,
                 namespace: Optional[str] = None):
        """Initialize the Pulp client."""
        self.domain = domain
        self.config = config
        self.namespace = namespace
        self.timeout = DEFAULT_TIMEOUT
        self._auth = None
        self.session = self._create_session()

    def _create_session(self) -> requests.Session:
        """Create a requests session with retry strategy."""
        retry_strategy = Retry(
            total=4,
            backoff_factor=2,
            status_forcelist=RETRY_STATUS_CODES,
        )
        adapter = HTTPAdapter(max_retries=retry_strategy)

        session = requests.Session()
        session.mount("http://", adapter)
        session.mount("https://", adapter)
        return session

    @classmethod
    def create_from_config_file(cls, path: Optional[str] = None, domain: Optional[str] = None,
                                 namespace: Optional[str] = None) -> "PulpClient":
        """
        Create a Pulp client from a standard configuration file that is
        used by the `pulp` CLI tool.
        """
        config_path = Path(path or DEFAULT_CONFIG_PATH).expanduser()
        with open(config_path, "rb") as fp:
            config = tomllib.load(fp)
        return cls(config["cli"], domain, namespace)

    @property
    def headers(self) -> Optional[Dict[str, str]]:
        """Get headers for requests."""
        return None

    @property
    def auth(self) -> OAuth2ClientCredentialsAuth:
        """Get authentication credentials."""
        if not self._auth:
            # Set up OAuth2 authentication with correct Red Hat SSO token URL
            token_url = "https://sso.redhat.com/auth/realms/redhat-external/protocol/openid-connect/token"

            self._auth = OAuth2ClientCredentialsAuth(
                client_id=str(self.config["client_id"]),
                client_secret=str(self.config["client_secret"]),
                token_url=token_url,
            )
        return self._auth

    @property
    def cert(self) -> Tuple[str, str]:
        """Get client certificate information."""
        return (str(self.config.get("cert")), str(self.config.get("key")))

    @property
    def request_params(self) -> Dict[str, Any]:
        """Get default parameters for requests."""
        params = {}
        if self.headers:
            params["headers"] = self.headers
        if self.config.get("cert"):
            params["cert"] = self.cert
        else:
            params["auth"] = self.auth
        return params

    def _url(self, endpoint: str) -> str:
        """Build a fully qualified URL for a given API endpoint."""
        domain = self._get_domain()

        relative = os.path.normpath("/".join([
            str(self.config["api_root"]),
            domain,
            endpoint,
        ]))

        # Normpath removes the trailing slash. If it was there, put it back
        if endpoint.endswith("/"):
            relative += "/"
        return str(self.config["base_url"]) + relative

    def _get_domain(self) -> str:
        """Get the domain name, removing -tenant suffix."""
        if self.domain:
            return self.domain.replace("-tenant", "")
        if self.config.get("domain"):
            return str(self.config["domain"])
        return self.namespace.replace("-tenant", "")

    def _get_single_resource(self, endpoint: str, name: str) -> Response:
        """Helper method to get a single resource by name."""
        url = self._url(f"{endpoint}?")
        url += urlencode({"name": name, "offset": 0, "limit": 1})
        return self.session.get(url, timeout=self.timeout, **self.request_params)

    def _create_repository(self, endpoint: str, name: str) -> Response:
        """Helper method to create a repository."""
        url = self._url(endpoint)
        data = {"name": name, "autopublish": True}
        return self.session.post(url, json=data, timeout=self.timeout, **self.request_params)

    def _create_distribution(self,
                             endpoint: str,
                             name: str,
                             repository: str,
                             basepath: Optional[str] = None) -> Response:
        """Helper method to create a distribution."""
        url = self._url(endpoint)
        data = {
            "name": name,
            "repository": repository,
            "base_path": basepath or name,
        }
        return self.session.post(url, json=data, timeout=self.timeout, **self.request_params)

    # RPM Repository Methods
    def create_rpm_repository(self, name: str) -> Response:
        """Create an RPM repository."""
        return self._create_repository("api/v3/repositories/rpm/rpm/", name)

    def get_rpm_repository(self, name: str) -> Response:
        """Get a single RPM repository."""
        return self._get_single_resource("api/v3/repositories/rpm/rpm/", name)

    def create_rpm_distribution(self, name: str, repository: str, basepath: Optional[str] = None) -> Response:
        """Create an RPM distribution."""
        return self._create_distribution("api/v3/distributions/rpm/rpm/", name, repository, basepath)

    def get_distribution(self, name: str) -> Response:
        """Get a single RPM distribution."""
        return self._get_single_resource("api/v3/distributions/rpm/rpm/", name)

    def create_rpm_content(self, path: str, pulp_label: Dict[str, str]) -> Response:
        """Create content for a given RPM artifact."""
        url = self._url("api/v3/content/rpm/packages/upload/")
        with open(path, "rb") as fp:
            data = {"pulp_labels": json.dumps(pulp_label)}
            files = {"file": fp}
            return self.session.post(
                url, data=data, files=files, timeout=self.timeout, **self.request_params
            )

    def add_content(self, repository: str, artifacts: List[str]) -> Response:
        """Add a list of artifacts to a repository."""
        modify_path = os.path.join(repository, "modify/")
        url = str(self.config["base_url"]) + modify_path
        data = {"add_content_units": artifacts}
        return self.session.post(url, json=data, timeout=self.timeout, **self.request_params)

    # File Repository Methods
    def create_file_repository(self, name: str) -> Response:
        """Create a File repository."""
        return self._create_repository("api/v3/repositories/file/file/", name)

    def get_file_repository(self, name: str) -> Response:
        """Get a single File repository."""
        return self._get_single_resource("api/v3/repositories/file/file/", name)

    def create_file_distribution(self, name: str, repository: str, basepath: Optional[str] = None) -> Response:
        """Create a File distribution."""
        return self._create_distribution("api/v3/distributions/file/file/", name, repository, basepath)

    def create_file_content(self, repository: str, path: str, build_id: str, pulp_label: Dict[str, str]) -> Response:
        """Create content for a given file artifact."""
        url = self._url("api/v3/content/file/files/")
        with open(path, "rb") as fp:
            file_name = Path(path).name
            data = {
                "repository": repository,
                "relative_path": f"{build_id}/{file_name}",
                "pulp_labels": json.dumps(pulp_label)
            }
            files = {"file": fp}
            return self.session.post(
                url, data=data, files=files, timeout=self.timeout, **self.request_params
            )

    # Task and Content Methods
    def get_task(self, task: str) -> Response:
        """Get detailed information about a task."""
        url = str(self.config["base_url"]) + task
        return self.session.get(url, timeout=self.timeout, **self.request_params)

    def wait_for_finished_task(self, task: str, timeout: int = DEFAULT_TASK_TIMEOUT) -> Response:
        """
        Wait for a Pulp task to finish.

        Pulp tasks (e.g. creating a publication) can run for an
        unpredictably long time. We need to wait until it is finished to know
        what it actually did.
        """
        start = time.time()

        while time.time() - start < timeout:
            logging.info("Waiting for %s to finish.", task)
            response = self.get_task(task)

            if not response.ok:
                logging.error(f"Error processing task {task}: {response.text}")
                return response

            task_state = response.json().get("state")
            if task_state not in ["waiting", "running"]:
                logging.info("Task finished: %s (state: %s)", task, task_state)
                return response

            time.sleep(TASK_SLEEP_INTERVAL)

        logging.error("Timed out waiting for task %s after %d seconds", task, timeout)
        return response

    def find_content_by_build_id(self, build_id: str) -> Response:
        """Find content by build ID."""
        url = self._url(f"api/v3/content/?pulp_label_select=build_id~{build_id}")
        return self.session.get(url, timeout=self.timeout, **self.request_params)

    def find_content_by_href(self, href: str) -> Response:
        """Find content by build ID."""
        url = self._url(f"api/v3/content/?pulp_href__in={href}")
        return self.session.get(url, timeout=self.timeout, **self.request_params)

    def get_file_locations(self, artifacts: List[Dict[str, str]]) -> Response:
        """Get file locations for artifacts."""
        hrefs = [list(artifact.values())[0] for artifact in artifacts]
        hrefs_string = ','.join(hrefs)
        url = self._url(f"api/v3/artifacts/?pulp_href__in={hrefs_string}")
        return self.session.get(url, timeout=self.timeout, **self.request_params)


def check_response(response: Response, operation: str = "request") -> None:
    """Check if a response is successful, exit if not."""
    if not response.ok:
        logging.error(f"Failed to {operation}: {response.status_code} - {response.text}")
        sys.exit(1)


def create_labels(build_id: str, arch: str, namespace: str, parent_package: str, date: str) -> Dict[str, str]:
    """Create standard labels for pulp content."""
    return {
        "date": date,
        "build_id": build_id,
        "arch": arch,
        "namespace": namespace,
        "parent_package": parent_package,
    }


def create_rpm_content(client: PulpClient, rpm_path: str, labels: Dict[str, str]) -> str:
    """Upload RPM content and return pulp_href."""
    logging.info("Uploading rpm file: %s", rpm_path)
    content_upload_response = client.create_rpm_content(rpm_path, labels)
    check_response(content_upload_response)
    return content_upload_response.json()["pulp_href"]


def upload_log(client: PulpClient, file_repository_prn: str, log_path: str,
               build_id: str, labels: Dict[str, str]) -> None:
    """Upload log file."""
    logging.info(f"Uploading log file: {log_path}")
    content_upload_response = client.create_file_content(file_repository_prn, log_path, build_id, labels)
    check_response(content_upload_response, f"upload log {log_path}")
    client.wait_for_finished_task(content_upload_response.json()['task'])


def upload_rpms_logs(rpm_path: str, args: argparse.Namespace, client: PulpClient, arch: str,
                     rpm_repository_href: str, file_repository_prn: str, date: str) -> None:
    """Upload RPMs and logs for a specific architecture."""
    rpms = glob.glob(os.path.join(rpm_path, "*.rpm"))
    logs = glob.glob(os.path.join(rpm_path, "*.log"))

    if not rpms and not logs:
        logging.info("No RPMs or logs found in %s", rpm_path)
        return

    labels = create_labels(args.build_id, arch, args.namespace, args.parent_package, date)

    # Upload RPMs in parallel
    rpm_results_artifacts = []
    if rpms:
        logging.info("Uploading %s RPM files for %s", len(rpms), arch)
        with concurrent.futures.ThreadPoolExecutor(max_workers=DEFAULT_MAX_WORKERS) as executor:
            futures = [executor.submit(create_rpm_content, client, rpm, labels) for rpm in rpms]
            rpm_results_artifacts = [future.result() for future in concurrent.futures.as_completed(futures)]

    # Upload logs sequentially
    if logs:
        logging.info("Uploading %s log files for %s", len(logs), arch)
        for log in logs:
            upload_log(client, file_repository_prn, log, args.build_id, labels)

    # Add RPM content to repository
    if rpm_results_artifacts:
        logging.info("Adding %s RPM artifacts to repository", len(rpm_results_artifacts))
        rpm_repo_results = client.add_content(rpm_repository_href, rpm_results_artifacts)
        client.wait_for_finished_task(rpm_repo_results.json()['task'])


def create_or_get_repository(client: PulpClient, repository_name: str, repo_type: str) -> Tuple[str, Optional[str]]:
    """
    Create or get a repository of the specified type.

    Args:
        client: PulpClient instance
        repository_name: Base name for the repository
        repo_type: Type of repository ('rpms', 'logs', 'sbom', 'artifacts')

    Returns:
        Tuple of (repository_prn, repository_href) where href is None for file repos
    """
    full_name = f"{repository_name}/{repo_type}"

    # Get the appropriate methods based on repository type
    methods = _get_repository_methods(client, repo_type)

    # Try getting the repo first if it already exists
    repository_response = methods['get'](full_name)
    if repository_response.json().get("results"):
        logging.info("%s repository already exists: %s", repo_type.capitalize(), full_name)
        result = repository_response.json()["results"][0]
        return result["prn"], result.get("pulp_href")

    # Create new repository and distribution
    return _create_new_repository(repository_name, repo_type, full_name, methods)


def _get_repository_methods(client: PulpClient, repo_type: str) -> Dict[str, Any]:
    """Get the appropriate client methods for the repository type."""
    if repo_type == "rpms":
        return {
            'get': client.get_rpm_repository,
            'create': client.create_rpm_repository,
            'distro': client.create_rpm_distribution
        }
    return {
        'get': client.get_file_repository,
        'create': client.create_file_repository,
        'distro': client.create_file_distribution
    }


def _create_new_repository(repository_name: str, repo_type: str,
                          full_name: str, methods: Dict[str, Any]) -> Tuple[str, Optional[str]]:
    """Create a new repository and distribution."""
    # Create repository
    logging.info("Creating %s repository: %s", repo_type, full_name)
    repository_response = methods['create'](full_name)
    check_response(repository_response, f"create {repo_type} repository")

    # Get the repository details
    repository_response = methods['get'](full_name)
    check_response(repository_response, f"get {repo_type} repository details")

    result = repository_response.json()["results"][0]
    repository_prn = result["prn"]
    repository_href = result.get("pulp_href")

    # Create distribution
    logging.info("Creating %s distribution: %s", repo_type, repository_name)
    distro_response = methods['distro'](repository_name, repository_prn, basepath=repository_name)
    check_response(distro_response, f"create {repo_type} distribution")

    return repository_prn, repository_href


def upload_sbom(client: PulpClient, args: argparse.Namespace, sbom_repository_prn: str, date: str) -> None:
    """Upload SBOM file to repository."""
    if not os.path.exists(args.sbom_path):
        logging.error("SBOM file not found: %s", args.sbom_path)
        return

    labels = create_labels(args.build_id, "", args.namespace, args.parent_package, date)
    logging.info("Uploading SBOM file: %s", args.sbom_path)

    content_upload_response = client.create_file_content(
        sbom_repository_prn, args.sbom_path, args.build_id, labels
    )
    check_response(content_upload_response, f"upload SBOM {args.sbom_path}")
    client.wait_for_finished_task(content_upload_response.json()['task'])


def collect_results(client: PulpClient, args: argparse.Namespace, date: str, artifact_repository_prn: str) -> None:
    """Collect results and write to JSON file."""
    logging.info("Collecting results for build ID: %s", args.build_id)

    # Find all content by build ID
    resp_json = client.find_content_by_build_id(args.build_id).json()
    artifacts = [result["artifacts"] for result in resp_json["results"]]

    if not artifacts:
        logging.warning("No artifacts found for build ID: %s", args.build_id)
        return

    # Get file locations for all artifacts
    file_locations_json = client.get_file_locations(artifacts).json()["results"]

    # Map artifacts to their file URLs
    results = {}
    logging.info("Mapping %d artifacts to file URLs", len(artifacts))

    for artifact in artifacts:
        artifact_href = list(artifact.values())[0]
        artifact_key = list(artifact.keys())[0]

        for file_info in file_locations_json:
            if file_info["pulp_href"] == artifact_href:
                results[artifact_key] = file_info["file"]
                break

    # Write results to JSON file
    _write_results_file(args.output_json, results)

    # Handle artifact results for Konflux if requested
    if args.artifact_results:
        _handle_artifact_results(client, args, date, artifact_repository_prn)


def _write_results_file(output_path: str, results: Dict[str, str]) -> None:
    """Write results dictionary to JSON file."""
    with open(output_path, "w", encoding="utf-8") as outfile:
        logging.info("Writing %d results to %s", len(results), output_path)
        json.dump(results, outfile, indent=2)


def _handle_artifact_results(client: PulpClient, args: argparse.Namespace, date: str,
                           artifact_repository_prn: str) -> None:
    """Handle artifact results for Konflux integration."""
    labels = create_labels(args.build_id, "", args.namespace, args.parent_package, date)

    # Upload results file as artifact
    content_upload_response = client.create_file_content(
        artifact_repository_prn, args.output_json, args.build_id, labels
    )
    resp = client.wait_for_finished_task(content_upload_response.json()['task'])

    # Find the created content
    artifact_href = next(
        (a for a in resp.json()["created_resources"] if "content" in a),
        None
    )

    if not artifact_href:
        logging.error("No content artifact found in task response")
        return

    content_resp = client.find_content_by_href(artifact_href).json()["results"]
    if not content_resp:
        logging.error("No content found for href: %s", artifact_href)
        return

    content_list_location = client.get_file_locations([content_resp[0]["artifacts"]]).json()["results"][0]

    # Parse and write artifact results
    try:
        image_url_path, image_digest_path = args.artifact_results.split(",")

        with open(image_url_path, "w", encoding="utf-8") as f:
            f.write(content_list_location["file"])

        with open(image_digest_path, "w", encoding="utf-8") as f:
            f.write(f"sha256:{content_list_location['sha256']}")

        logging.info("Artifact results written to %s and %s", image_url_path, image_digest_path)

    except ValueError as e:
        logging.error("Invalid artifact_results format: %s", e)


def setup_logging(debug: bool) -> None:
    """Setup logging configuration."""
    level = logging.DEBUG if debug else logging.INFO
    logging.basicConfig(
        level=level,
        format='%(asctime)s - %(levelname)s - %(message)s'
    )


def main() -> None:
    """Main function for Pulp upload operations."""
    args = _parse_arguments()
    setup_logging(args.debug)

    try:
        # Initialize client and timestamp
        client = PulpClient.create_from_config_file(
            path=args.config, domain=args.domain, namespace=args.namespace
        )
        date_str = datetime.now(timezone.utc).strftime('%Y-%m-%d %H:%M:%S')

        # Setup repositories
        repositories = _setup_repositories(client, args.repository_name)

        # Process uploads
        _process_uploads(client, args, repositories, date_str)

        logging.info("All operations completed successfully")

    except requests.exceptions.RequestException as e:
        logging.error("Fatal error during execution: %s", e)
        sys.exit(1)


def _parse_arguments() -> argparse.Namespace:
    """Parse and validate command line arguments."""
    parser = argparse.ArgumentParser(
        description="Upload RPM packages, logs, and SBOM files to Pulp repositories",
        formatter_class=argparse.RawDescriptionHelpFormatter
    )

    # Required arguments
    parser.add_argument("--repository_name", required=True,
                       help="Base name for the repositories")
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
    parser.add_argument("--domain",
                       help="Pulp domain to use for uploading")
    parser.add_argument("--output_json", default=DEFAULT_OUTPUT_JSON,
                       help="Output file for upload results JSON")
    parser.add_argument("--artifact_results",
                       help="Comma-separated paths for Konflux artifact results (url_path,digest_path)")
    parser.add_argument("-d", "--debug", action="store_true",
                       help="Enable debug logging")

    return parser.parse_args()


def _setup_repositories(client: PulpClient, repository_name: str) -> Dict[str, str]:
    """Setup all required repositories and return their identifiers."""
    logging.info("Setting up repositories for: %s", repository_name)

    repositories = {}
    repo_types = ["rpms", "logs", "sbom", "artifacts"]

    for repo_type in repo_types:
        prn, href = create_or_get_repository(client, repository_name, repo_type)
        repositories[f"{repo_type}_prn"] = prn
        if href:  # RPM repositories have href, file repositories don't
            repositories[f"{repo_type}_href"] = href

    return repositories


def _process_uploads(client: PulpClient, args: argparse.Namespace,
                    repositories: Dict[str, str], date_str: str) -> None:
    """Process all upload operations."""
    # Ensure RPM repository href exists
    rpm_href = repositories.get("rpms_href")
    if not rpm_href:
        raise ValueError("RPM repository href is required but not found")

    # Process each architecture
    _process_architecture_uploads(client, args, repositories, date_str, rpm_href)

    # Upload SBOM
    upload_sbom(client, args, repositories["sbom_prn"], date_str)

    # Collect and save results
    collect_results(client, args, date_str, repositories["artifacts_prn"])


def _process_architecture_uploads(client: PulpClient, args: argparse.Namespace,
                                repositories: Dict[str, str], date_str: str, rpm_href: str) -> None:
    """Process uploads for all supported architectures."""
    processed_archs = []

    for arch in SUPPORTED_ARCHITECTURES:
        arch_path = os.path.join(args.rpm_path, arch)
        if os.path.exists(arch_path):
            logging.info("Processing architecture: %s", arch)
            upload_rpms_logs(arch_path, args, client, arch, rpm_href, repositories["logs_prn"], date_str)
            processed_archs.append(arch)
        else:
            logging.debug("Skipping %s - path does not exist: %s", arch, arch_path)

    if not processed_archs:
        logging.warning("No architecture directories found in %s", args.rpm_path)
    else:
        logging.info("Processed architectures: %s", ", ".join(processed_archs))


if __name__ == "__main__":
    main()
