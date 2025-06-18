#!/usr/bin/python3
"""
Pulp doesn't provide an API client, we are implementing it for ourselves.
"""

import argparse
import concurrent.futures
import datetime
import glob
import json
import logging
import os
import sys
import time
import tomllib
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

    def __init__(self, config: Dict[str, Union[str, int]], domain: Optional[str] = None):
        """Initialize the Pulp client."""
        self.domain = domain
        self.config = config
        self.timeout = DEFAULT_TIMEOUT
        
        retry_strategy = Retry(
            total=4,
            backoff_factor=2,
            status_forcelist=RETRY_STATUS_CODES,
        )
        adapter = HTTPAdapter(max_retries=retry_strategy)

        self.session = requests.Session()
        self.session.mount("http://", adapter)
        self.session.mount("https://", adapter)

    @classmethod
    def create_from_config_file(cls, path: Optional[str] = None, domain: Optional[str] = None) -> "PulpClient":
        """
        Create a Pulp client from a standard configuration file that is
        used by the `pulp` CLI tool.
        """
        config_path = Path(path or DEFAULT_CONFIG_PATH).expanduser()
        with open(config_path, "rb") as fp:
            config = tomllib.load(fp)
        return cls(config["cli"], domain)

    @property
    def headers(self) -> Optional[Dict[str, str]]:
        """Get headers for requests."""
        return None

    @property
    def auth(self) -> Tuple[str, str]:
        """Get authentication credentials."""
        return (str(self.config["username"]), str(self.config["password"]))

    @property
    def cert(self) -> Tuple[str, str]:
        """Get client certificate information."""
        return (str(self.config["cert"]), str(self.config["key"]))

    @property
    def request_params(self) -> Dict[str, Any]:
        """Get default parameters for requests."""
        params = {}
        if self.headers:
            params["headers"] = self.headers
        if all(self.cert):
            params["cert"] = self.cert
        else:
            params["auth"] = self.auth
        return params

    def url(self, endpoint: str) -> str:
        """Build a fully qualified URL for a given API endpoint."""
        if self.domain:
            domain = self.domain.replace("-tenant", "")
        else:
            domain = str(self.config["domain"])

        relative = os.path.normpath("/".join([
            str(self.config["api_root"]),
            domain,
            endpoint,
        ]))

        # Normpath removes the trailing slash. If it was there, put it back
        if endpoint.endswith("/"):
            relative += "/"
        return str(self.config["base_url"]) + relative

    def _get_single_resource(self, endpoint: str, name: str) -> Response:
        """Helper method to get a single resource by name."""
        url = self.url(f"{endpoint}?")
        url += urlencode({"name": name, "offset": 0, "limit": 1})
        return self.session.get(url, timeout=self.timeout, **self.request_params)

    def _create_repository(self, endpoint: str, name: str) -> Response:
        """Helper method to create a repository."""
        url = self.url(endpoint)
        data = {"name": name, "autopublish": True}
        return self.session.post(url, json=data, timeout=self.timeout, **self.request_params)

    def _create_distribution(self, endpoint: str, name: str, repository: str, basepath: Optional[str] = None) -> Response:
        """Helper method to create a distribution."""
        url = self.url(endpoint)
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
        url = self.url("api/v3/content/rpm/packages/upload/")
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
        url = self.url("api/v3/content/file/files/")
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
        while True:
            logging.info("Waiting for %s to finish.", task)
            response = self.get_task(task)
            if not response.ok:
                logging.error(f"There was an error processing the task: {response.text}")
                break
            if response.json()["state"] not in ["waiting", "running"]:
                break
            if time.time() > start + timeout:
                logging.error("Timed out waiting for %s", task)
                break
            time.sleep(TASK_SLEEP_INTERVAL)
        logging.info("Task finished: %s", task)
        return response

    def find_content_by_build_id(self, build_id: str) -> Response:
        """Find content by build ID."""
        url = self.url(f"api/v3/content/?pulp_label_select=build_id~{build_id}")
        return self.session.get(url, timeout=self.timeout, **self.request_params)

    def get_file_locations(self, artifacts: List[Dict[str, str]]) -> Response:
        """Get file locations for artifacts."""
        hrefs = [list(artifact.values())[0] for artifact in artifacts]
        hrefs_string = ','.join(hrefs)
        url = self.url(f"api/v3/artifacts/?pulp_href__in={hrefs_string}")
        return self.session.get(url, timeout=self.timeout, **self.request_params)


def check_response(response: Response) -> None:
    """Check if a response is successful, exit if not."""
    if not response.ok:
        logging.error(f"An error occurred while completing a request: {response.text}")
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


def upload_log(client: PulpClient, file_repository_prn: str, log_path: str, build_id: str, labels: Dict[str, str]) -> None:
    """Upload log file."""
    logging.info(f"Uploading log file: {log_path}")
    content_upload_response = client.create_file_content(file_repository_prn, log_path, build_id, labels)
    client.wait_for_finished_task(content_upload_response.json()['task'])


def upload_rpms_logs(rpm_path: str, args: argparse.Namespace, client: PulpClient, arch: str, 
                     rpm_repository_href: str, file_repository_prn: str, date: str) -> None:
    """Upload RPMs and logs for a specific architecture."""
    rpms = glob.glob(os.path.join(rpm_path, "*.rpm"))
    logs = glob.glob(os.path.join(rpm_path, "*.log"))

    labels = create_labels(args.build_id, arch, args.namespace, args.parent_package, date)
    
    # Upload RPMs in parallel
    with concurrent.futures.ThreadPoolExecutor(max_workers=DEFAULT_MAX_WORKERS) as executor:
        futures = [executor.submit(create_rpm_content, client, rpm, labels) for rpm in rpms]
        rpm_results_artifacts = [future.result() for future in concurrent.futures.as_completed(futures)]

    # Upload logs sequentially
    for log in logs:
        upload_log(client, file_repository_prn, log, args.build_id, labels)

    # Add RPM content to repository
    if rpm_results_artifacts:
        rpm_repo_results = client.add_content(rpm_repository_href, rpm_results_artifacts)
        client.wait_for_finished_task(rpm_repo_results.json()['task'])


def create_or_get_repository(client: PulpClient, repository_name: str, repo_type: str) -> Tuple[str, Optional[str]]:
    """
    Create or get a repository of the specified type.
    
    Args:
        client: PulpClient instance
        repository_name: Base name for the repository
        repo_type: Type of repository ('rpms', 'logs', 'sbom')
        
    Returns:
        Tuple of (repository_prn, repository_href) where href is None for file repos
    """
    full_name = f"{repository_name}/{repo_type}"

    if repo_type == "rpms":
        get_method = client.get_rpm_repository
        create_method = client.create_rpm_repository
        distro_method = client.create_rpm_distribution
    else:
        get_method = client.get_file_repository
        create_method = client.create_file_repository
        distro_method = client.create_file_distribution

    # Try getting the repo first if it already exists
    repository_response = get_method(full_name)
    if repository_response.json()["results"]:
        logging.info("%s Repository already exists", repo_type.capitalize())
        result = repository_response.json()["results"][0]
        return result["prn"], result.get("pulp_href")

    # Create repository
    logging.info("Creating the %s repository", repo_type)
    repository_response = create_method(full_name)
    check_response(repository_response)

    # Get the repository details
    repository_response = get_method(full_name)
    check_response(repository_response)

    result = repository_response.json()["results"][0]
    repository_prn = result["prn"]
    repository_href = result.get("pulp_href")

    # Create distribution
    logging.info("Creating the %s distribution", repo_type)
    distro_response = distro_method(repository_name, repository_prn, basepath=repository_name)
    check_response(distro_response)

    return repository_prn, repository_href


def upload_sbom(client: PulpClient, args: argparse.Namespace, sbom_repository_prn: str, date: str) -> None:
    """Upload SBOM file."""
    labels = create_labels(args.build_id, "", args.namespace, args.parent_package, date)
    logging.info(f"Uploading SBOM file: {args.sbom_path}")
    content_upload_response = client.create_file_content(sbom_repository_prn, args.sbom_path, args.build_id, labels)
    client.wait_for_finished_task(content_upload_response.json()['task'])


def collect_results(client: PulpClient, build_id: str, output_json: str) -> None:
    """Collect results and write to JSON file."""
    logging.info("Collecting results...")
    resp_json = client.find_content_by_build_id(build_id).json()
    artifacts = [result["artifacts"] for result in resp_json["results"]]

    if not artifacts:
        logging.warning("No artifacts found for build ID")
        return

    file_locations_json = client.get_file_locations(artifacts).json()["results"]

    results = {}
    logging.info("Collecting file URLs for uploaded files.")

    for artifact in artifacts:
        for file_info in file_locations_json:
            if file_info["pulp_href"] == list(artifact.values())[0]:
                results[list(artifact.keys())[0]] = file_info["file"]

    # Write results to file
    with open(output_json, "w") as outfile:
        logging.info("Writing results to %s", output_json)
        json.dump(results, outfile, indent=2)


def setup_logging(debug: bool) -> None:
    """Setup logging configuration."""
    level = logging.DEBUG if debug else logging.INFO
    logging.basicConfig(
        level=level,
        format='%(asctime)s - %(levelname)s - %(message)s'
    )


def main() -> None:
    """Main function."""
    parser = argparse.ArgumentParser(description="Create a pulp repository and distribution.")
    parser.add_argument("--repository_name", type=str, required=True, help="Name of the repository")
    parser.add_argument("--rpm_path", type=str, required=True, help="Root path to the RPM packages")
    parser.add_argument("--sbom_path", type=str, required=True, help="Path to the SBOM file")
    parser.add_argument("--config", type=str, help="Path to the config file")
    parser.add_argument("--build_id", type=str, required=True, help="Build ID for this run")
    parser.add_argument("--namespace", type=str, required=True, help="Namespace this is running out of")
    parser.add_argument("--parent_package", type=str, required=True, help="Parent package this is ran for")
    parser.add_argument("--domain", type=str, help="Domain to use for uploading")
    parser.add_argument("--output_json", default=DEFAULT_OUTPUT_JSON, type=str,
                        help="Where to create the results JSON file")
    parser.add_argument("-d", "--debug", action="store_true", help="Enable debug output")

    args = parser.parse_args()

    setup_logging(args.debug)

    # Create timestamp
    now_utc = datetime.datetime.now(datetime.timezone.utc)
    date_str = now_utc.strftime('%Y-%m-%d %H:%M:%S')

    # Create client
    client = PulpClient.create_from_config_file(path=args.config, domain=args.domain)

    # Create repositories
    _, rpm_repository_href = create_or_get_repository(client, args.repository_name, "rpms")
    log_repository_prn, _ = create_or_get_repository(client, args.repository_name, "logs")
    sbom_repository_prn, _ = create_or_get_repository(client, args.repository_name, "sbom")

    # Ensure rpm_repository_href is not None for RPM repositories
    if rpm_repository_href is None:
        raise ValueError("RPM repository href should not be None")

    # Process each architecture
    for arch in SUPPORTED_ARCHITECTURES:
        current_path = os.path.join(args.rpm_path, arch)
        if os.path.exists(current_path):
            upload_rpms_logs(current_path, args, client, arch, rpm_repository_href, log_repository_prn, date_str)
        else:
            logging.info("Path %s does not exist, skipping %s", current_path, arch)

    # Upload SBOM
    upload_sbom(client, args, sbom_repository_prn, date_str)

    # Collect and save results
    collect_results(client, args.build_id, args.output_json)


if __name__ == "__main__":
    main()
