#!/usr/bin/env python3
"""
Pulp API client for uploading RPM packages, logs, and SBOM files.

This module provides a client for interacting with Pulp API to manage
RPM repositories, file repositories, and content uploads with OAuth2 authentication.
"""

# Standard library imports
import json
import logging
import os
import time
import traceback
from datetime import datetime, timedelta
from pathlib import Path
from typing import Any, Dict, List, Optional, Tuple, Union
from urllib.parse import urlencode

# Third-party imports
import requests
from requests.models import Response

# Local imports
from pulp_utils import (
    DEFAULT_TIMEOUT, DEFAULT_TASK_TIMEOUT,
    create_session_with_retry, validate_file_path,
    sanitize_error_message, read_file_with_base64_decode
)

# Optional imports with fallback
try:
    import tomllib
except ImportError:
    # Fallback for Python < 3.11
    import tomli as tomllib

# ============================================================================
# Constants
# ============================================================================

TASK_SLEEP_INTERVAL = 5


# ============================================================================
# Authentication Classes
# ============================================================================

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
            logging.error("Failed to retrieve OAuth2 token: %s", sanitize_error_message(str(e)))
            logging.error("Traceback: %s", sanitize_error_message(traceback.format_exc()))
            raise

    @property
    def access_token(self) -> Optional[str]:
        """Get the current access token (for debugging/inspection)."""
        return self._access_token

    @property
    def expires_at(self) -> Optional[datetime]:
        """Get the token expiration time (for debugging/inspection)."""
        return self._expire_at


# ============================================================================
# Main Client Class
# ============================================================================

# pylint: disable=too-many-public-methods
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
        """Create a requests session with retry strategy and connection pool configuration."""
        return create_session_with_retry()

    def close(self) -> None:
        """Close the session and release all connections."""
        if hasattr(self, 'session') and self.session:
            self.session.close()
            logging.debug("PulpClient session closed and connections released")

    def __enter__(self):
        """Context manager entry."""
        return self

    def __exit__(self, exc_type, exc_val, exc_tb):
        """Context manager exit - ensures session is closed."""
        self.close()

    def _chunked_get(self, url: str, params: Optional[Dict[str, Any]] = None,
                     chunk_param: Optional[str] = None, chunk_size: int = 50,
                     **kwargs) -> Response:
        # Perform a GET request with chunking for large parameter lists.
        #
        # This is a workaround for the fact that requests with large parameter
        # values using "GET" method fails with "Request Line is too large".
        # Hence, this splits the parameter value into chunks of the given size,
        # and makes a separate request for each chunk. The results are aggregated
        # into a single response.
        #
        # Note: - chunks are created on only one parameter at a time.
        #       - response object of the last chunk is returned with the aggregated results.

        if not params or not chunk_param or chunk_param not in params:
            # No chunking needed, make regular request
            return self.session.get(url, params=params, **kwargs)

        # Extract the parameter value and check if it needs chunking
        param_value = params[chunk_param]
        if not isinstance(param_value, str) or ',' not in param_value:
            # Not a comma-separated list, make regular request
            return self.session.get(url, params=params, **kwargs)

        values = [v.strip() for v in param_value.split(',')]

        if len(values) <= chunk_size:
            # Small list, make regular request
            return self.session.get(url, params=params, **kwargs)

        # Need to chunk the request
        logging.debug("Chunking parameter '%s' with %d values for request %s",
                     chunk_param, len(values), url)

        all_results = []
        chunks = [values[i:i + chunk_size] for i in range(0, len(values), chunk_size)]
        last_response = None

        for i, chunk in enumerate(chunks, 1):
            logging.debug("Processing chunk %d/%d with %d values", i, len(chunks), len(chunk))

            # Create params for this chunk
            chunk_params = params.copy()
            chunk_params[chunk_param] = ','.join(chunk)

            try:
                response = self.session.get(url, params=chunk_params, **kwargs)
                self._check_response(response, f"chunked request {i}")
                last_response = response

                # Parse and aggregate results
                chunk_data = response.json()
                if chunk_data.get('results'):
                    all_results.extend(chunk_data['results'])

            except Exception as e:
                logging.error("Failed to process chunk %d: %s", i, sanitize_error_message(str(e)))
                logging.error("Traceback: %s", sanitize_error_message(traceback.format_exc()))
                raise

        # Create aggregated response
        if last_response:
            aggregated_data = {
                "count": len(all_results),
                "results": all_results
            }

            # Modify response content to return aggregated results from all chunks
            # intentionally modifying _content
            # pylint: disable=W0212 (protected-access)
            last_response._content = json.dumps(aggregated_data).encode('utf-8')
            return last_response

        # Fallback: return empty response
        return self.session.get(url, params={chunk_param: ""}, **kwargs)

    @classmethod
    def create_from_config_file(cls, path: Optional[str] = None, domain: Optional[str] = None,
                                 namespace: Optional[str] = None) -> "PulpClient":
        """
        Create a Pulp client from a standard configuration file that is
        used by the `pulp` CLI tool.

        Args:
            path: Path to the config file (default: ~/.config/pulp/cli.toml)
            domain: Optional domain override
            namespace: Optional namespace override

        Returns:
            PulpClient instance

        Raises:
            FileNotFoundError: If the config file doesn't exist
            ValueError: If the config file is malformed or missing required sections
        """
        config_path = Path(path or "~/.config/pulp/cli.toml").expanduser()

        # Check if config file exists
        if not config_path.exists():
            logging.error("Pulp config file not found: %s", config_path)
            raise FileNotFoundError(f"Pulp config file not found: {config_path}")

        try:
            # Read and decode base64 if encoded
            _, decoded_content = read_file_with_base64_decode(str(config_path))
            config = tomllib.loads(decoded_content.decode('utf-8'))
        except OSError as e:
            # File system errors (FileNotFoundError, PermissionError, etc.)
            logging.error("Failed to read config file: %s", config_path)
            logging.error("Error: %s", sanitize_error_message(str(e)))
            raise FileNotFoundError(f"Pulp config file not found or cannot be read: {config_path}") from e
        except (ValueError, KeyError) as e:
            # TOML parsing errors (TOMLDecodeError is a subclass of ValueError in tomllib/tomli)
            error_msg = str(e)
            sanitized_error = sanitize_error_message(error_msg)
            error_type = type(e).__name__

            if "TOMLDecodeError" in error_type or "Expected '='" in error_msg:
                logging.error("Failed to parse TOML config file: %s", config_path)
                logging.error("The config file appears to be malformed.")
                logging.error("Error type: %s", error_type)
                logging.error("Error message: %s", sanitized_error)
                logging.error("Please check the TOML syntax in the config file.")
                logging.error("Common issues:")
                logging.error("  - Missing '=' after a key in a key/value pair")
                logging.error("  - Incomplete key-value pairs")
                logging.error("  - Trailing syntax errors at the end of the file")
                logging.error("  - Invalid TOML structure")
                raise ValueError(f"Malformed TOML config file: {sanitized_error}") from e

            logging.error("Failed to load Pulp client from config file: %s", config_path)
            logging.error("Error type: %s", error_type)
            logging.error("Error message: %s", sanitized_error)
            raise ValueError(f"Failed to load config file: {sanitized_error}") from e

        # Validate that config has required 'cli' section
        if "cli" not in config:
            logging.error("Config file missing required 'cli' section: %s", config_path)
            raise ValueError(f"Config file missing required 'cli' section: {config_path}")

        return cls(config["cli"], domain, namespace)

    @property
    def headers(self) -> Optional[Dict[str, str]]:
        """
        Get headers for requests.

        Returns:
            None (no custom headers are currently used)
        """
        return None

    @property
    def auth(self) -> OAuth2ClientCredentialsAuth:
        """
        Get authentication credentials.

        Returns:
            OAuth2ClientCredentialsAuth instance for API authentication
        """
        if not self._auth:
            # Set up OAuth2 authentication with correct Red Hat SSO token URL
            token_url = ("https://sso.redhat.com/auth/realms/redhat-external/"
                        "protocol/openid-connect/token")

            self._auth = OAuth2ClientCredentialsAuth(
                client_id=str(self.config["client_id"]),
                client_secret=str(self.config["client_secret"]),
                token_url=token_url,
            )
        return self._auth

    @property
    def cert(self) -> Tuple[str, str]:
        """
        Get client certificate information.

        Returns:
            Tuple of (cert_path, key_path) for client certificate authentication
        """
        return (str(self.config.get("cert")), str(self.config.get("key")))

    @property
    def request_params(self) -> Dict[str, Any]:
        """
        Get default parameters for requests.

        Returns:
            Dictionary containing default request parameters including
            authentication and certificate information
        """
        params = {}
        if self.headers:
            params["headers"] = self.headers
        if self.config.get("cert"):
            params["cert"] = self.cert
        else:
            params["auth"] = self.auth
        return params

    def _url(self, endpoint: str) -> str:
        """
        Build a fully qualified URL for a given API endpoint.

        Args:
            endpoint: API endpoint path (e.g., "api/v3/repositories/rpm/rpm/")

        Returns:
            Complete URL including base URL, API root, domain, and endpoint
        """
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
        """
        Get the domain name, removing -tenant suffix.

        Returns:
            Domain name with -tenant suffix removed if present
        """
        if self.domain:
            return self.domain.replace("-tenant", "")
        if self.config.get("domain"):
            return str(self.config["domain"])
        return self.namespace.replace("-tenant", "")

    def get_domain(self) -> str:
        """Public method to get the domain name, removing -tenant suffix."""
        return self._get_domain()

    def _get_single_resource(self, endpoint: str, name: str) -> Response:
        """
        Helper method to get a single resource by name.

        Args:
            endpoint: API endpoint for the resource type
            name: Name of the resource to retrieve

        Returns:
            Response object containing the resource data
        """
        url = self._url(f"{endpoint}?")
        url += urlencode({"name": name, "offset": 0, "limit": 1})
        return self.session.get(url, timeout=self.timeout, **self.request_params)


    def _check_response(self, response: Response, operation: str = "request") -> None:
        """Check if a response is successful, raise exception if not."""
        if not response.ok:
            logging.error("Failed to %s: %s - %s", operation, response.status_code,
                         sanitize_error_message(response.text))

            # Enhanced error logging for server errors
            if response.status_code >= 500:
                logging.error("Server error details:")
                logging.error("  Status Code: %s", response.status_code)
                # Sanitize headers to prevent credential leakage
                headers_dict = dict(response.headers)
                logging.error("  Headers: %s", sanitize_error_message(str(headers_dict)))
                logging.error("  URL: %s", response.url)
                logging.error("  Request Method: %s",
                             response.request.method if response.request else "Unknown")

                # Try to parse error details
                try:
                    error_data = response.json()
                    logging.error("  Error Data: %s", sanitize_error_message(str(error_data)))
                except (ValueError, json.JSONDecodeError):
                    logging.error("  Raw Response: %s", sanitize_error_message(response.text))

            # Sanitize error message in exception
            sanitized_text = sanitize_error_message(response.text)
            raise requests.RequestException(
                f"Failed to {operation}: {response.status_code} - {sanitized_text}"
            )

    def check_response(self, response: Response, operation: str = "request") -> None:
        """Public method to check if a response is successful, raise exception if not."""
        self._check_response(response, operation)


    # ============================================================================
    # Content Management Methods
    # ============================================================================


    def upload_content(self, file_path: str, labels: Dict[str, str],
                      *, file_type: str, upload_method: str, arch: str = None) -> str:
        """
        Generic file upload function with validation and error handling.

        Args:
            file_path: Path to the file to upload
            labels: Labels to attach to the uploaded content
            file_type: Type of file for error messages (e.g., 'RPM', 'SBOM')
            upload_method: Method to use for upload ('rpm' or 'file')
            arch: Architecture for the uploaded content (required for RPMs)

        Returns:
            Pulp href of the uploaded content

        Raises:
            FileNotFoundError: If the file does not exist
            PermissionError: If the file cannot be read
            ValueError: If the file is empty or arch is missing for RPMs
        """
        # Validate file before upload
        validate_file_path(file_path, file_type)

        try:
            # Call the appropriate upload method
            if upload_method == "rpm":
                if not arch:
                    raise ValueError("arch parameter is required for RPM uploads")
                # Handle RPM upload directly
                url = self._url("api/v3/content/rpm/packages/upload/")
                with open(file_path, "rb") as fp:
                    file_name = os.path.basename(file_path)
                    data = {
                        "pulp_labels": json.dumps(labels),
                        "relative_path": f"{labels.get('build_id', '')}/{arch}/{file_name}"
                    }
                    files = {"file": fp}
                    response = self.session.post(
                        url, data=data, files=files, timeout=self.timeout, **self.request_params
                    )
            else:
                response = self.create_file_content(
                    "", file_path,
                    build_id=labels.get("build_id", ""),
                    pulp_label=labels, arch=arch
                )

            self._check_response(response, f"upload {file_type}")
            return response.json()["pulp_href"]

        except requests.RequestException as e:
            logging.error("Request failed for %s %s: %s", file_type, file_path, sanitize_error_message(str(e)))
            logging.error("Traceback: %s", sanitize_error_message(traceback.format_exc()))
            raise
        except Exception as e:
            logging.error("Unexpected error uploading %s %s: %s", file_type, file_path, sanitize_error_message(str(e)))
            logging.error("Traceback: %s", sanitize_error_message(traceback.format_exc()))
            raise

    def create_file_content(self, repository: str, content_or_path: Union[str, Path],
                           *, build_id: str, pulp_label: Dict[str, str],
                           filename: Optional[str] = None, arch: Optional[str] = None) -> Response:
        """
        Create content for a file artifact from either a file path or in-memory content.

        Args:
            repository: Repository PRN
            content_or_path: Either a file path (str/Path) or in-memory content (str)
            build_id: Build identifier for relative path
            pulp_label: Labels to attach to the content
            filename: Optional filename for in-memory content
                     (required when content_or_path is string content)
            arch: Optional architecture to include in relative path

        Returns:
            Response object from the API call
        """
        url = self._url("api/v3/content/file/files/")
        data = {
            "repository": repository,
            "pulp_labels": json.dumps(pulp_label)
        }

        # Determine if content_or_path is a file path or in-memory content
        if isinstance(content_or_path, (str, Path)) and os.path.exists(str(content_or_path)):
            # File path - read from file
            file_path = Path(content_or_path)
            file_name = file_path.name
            # Include arch in relative path if provided
            if arch:
                data["relative_path"] = f"{build_id}/{arch}/{file_name}"
            else:
                data["relative_path"] = f"{build_id}/{file_name}"

            with open(file_path, "rb") as fp:
                files = {"file": fp}
                return self.session.post(
                    url, data=data, files=files, timeout=self.timeout, **self.request_params
                )
        else:
            # In-memory content
            if not filename:
                raise ValueError("filename is required when providing in-memory content")

            content = str(content_or_path)
            # Include arch in relative path if provided
            if arch:
                data["relative_path"] = f"{build_id}/{arch}/{filename}"
            else:
                data["relative_path"] = f"{build_id}/{filename}"
            files = {"file": (filename, content, "application/json")}
            return self.session.post(
                url, data=data, files=files, timeout=self.timeout, **self.request_params
            )

    def add_content(self, repository: str, artifacts: List[str]) -> Response:
        """
        Add a list of artifacts to a repository.

        Args:
            repository: Repository href to add content to
            artifacts: List of artifact hrefs to add to the repository

        Returns:
            Response object from the add content request
        """
        modify_path = os.path.join(repository, "modify/")
        url = str(self.config["base_url"]) + modify_path
        data = {"add_content_units": artifacts}
        return self.session.post(url, json=data, timeout=self.timeout, **self.request_params)

    # ============================================================================
    # Task Management Methods
    # ============================================================================

    def _get_task(self, task: str) -> Response:
        """
        Get detailed information about a task.

        Args:
            task: Task href to get information for

        Returns:
            Response object containing task information
        """
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
            response = self._get_task(task)

            if not response.ok:
                logging.error("Error processing task %s: %s", task, sanitize_error_message(response.text))
                return response

            task_state = response.json().get("state")
            if task_state not in ["waiting", "running"]:
                logging.info("Task finished: %s (state: %s)", task, task_state)
                return response

            time.sleep(TASK_SLEEP_INTERVAL)

        logging.error("Timed out waiting for task %s after %d seconds", task, timeout)
        return response


    # ============================================================================
    # Content Query Methods
    # ============================================================================

    def find_content(self, search_type: str, search_value: str) -> Response:
        """
        Find content by various criteria.

        Args:
            search_type: Type of search ('build_id' or 'href')
            search_value: Value to search for

        Returns:
            Response object containing content matching the search criteria
        """
        if search_type == "build_id":
            url = self._url(f"api/v3/content/?pulp_label_select=build_id~{search_value}")
        elif search_type == "href":
            url = self._url(f"api/v3/content/?pulp_href__in={search_value}")
        else:
            raise ValueError(f"Unknown search type: {search_type}")

        return self.session.get(url, timeout=self.timeout, **self.request_params)

    def get_file_locations(self, artifacts: List[Dict[str, str]]) -> Response:
        """
        Get file locations for artifacts.

        Args:
            artifacts: List of artifact dictionaries containing hrefs

        Returns:
            Response object containing file location information
        """
        hrefs = [list(artifact.values())[0] for artifact in artifacts]
        url = self._url("api/v3/artifacts/")
        params = {
            "pulp_href__in": ','.join(hrefs)
        }
        return self._chunked_get(url, params=params, chunk_param="pulp_href__in",
                                timeout=self.timeout, chunk_size=20,
                                **self.request_params)

    def get_rpm_by_pkgIDs(self, pkg_ids: List[str]) -> Response:
        """
        Get RPMs by package IDs.

        Args:
            pkg_ids: List of package IDs (checksums) to search for

        Returns:
            Response object containing RPM information for matching package IDs
        """
        url = self._url("api/v3/content/rpm/packages/")
        params = {
            "pkgId__in": ",".join(pkg_ids)
        }
        return self._chunked_get(url, params=params, chunk_param="pkgId__in",
                                timeout=self.timeout, **self.request_params)


    def gather_content_data(self, build_id: str,
                           extra_artifacts: List[Dict[str, str]] = None) -> \
                           Tuple[List[Dict[str, Any]], List[Dict[str, str]]]:
        """
        Gather content data and artifacts for a build ID.

        Args:
            build_id: Build identifier
            extra_artifacts: Optional extra artifacts to include

        Returns:
            Tuple of (content_results, artifacts)
        """
        # Find all content by build ID
        try:
            resp = self.find_content("build_id", build_id)
            logging.debug("Content response status: %s", resp.status_code)
            logging.debug("Content response headers: %s", dict(resp.headers))

            resp_json = resp.json()
            logging.debug("Content response JSON: %s", resp_json)
            content_results = resp_json["results"]
        except Exception as e:
            logging.error("Failed to get content by build ID: %s", sanitize_error_message(str(e)))
            resp_text = resp.text if 'resp' in locals() else "No response"
            logging.error("Response text: %s", sanitize_error_message(resp_text))
            logging.error("Traceback: %s", sanitize_error_message(traceback.format_exc()))
            raise

        if not content_results:
            logging.warning("No content found for build ID: %s", build_id)
            return [], []

        # Extract artifacts and content data
        artifacts = [result["artifacts"] for result in content_results]

        # Add extra artifacts if provided
        if extra_artifacts:
            logging.debug("Adding %d extra artifacts", len(extra_artifacts))
            artifacts.extend(extra_artifacts)
            # Also add them to content_results for processing
            for extra_artifact in extra_artifacts:
                # Create a minimal content entry for extra artifacts
                content_results.append({
                    "artifacts": extra_artifact,
                    "pulp_labels": {}  # Extra artifacts might not have labels
                })

        return content_results, artifacts


    def build_results_structure(self, content_results: List[Dict[str, Any]],
                              file_info_map: Dict[str, Dict[str, Any]]) -> \
                              Dict[str, Any]:
        """
        Build the results structure from content and file info.

        Args:
            content_results: Content data from Pulp
            file_info_map: Mapping of artifact hrefs to file info

        Returns:
            Structured results dictionary
        """
        results = {"artifacts": {}}

        logging.debug("Mapping %d artifacts to structured results", len(file_info_map))

        for content in content_results:
            artifact = content.get("artifacts", {})
            if not artifact:
                continue

            artifact_href = list(artifact.values())[0]
            artifact_key = list(artifact.keys())[0]

            # Get file info
            file_info = file_info_map.get(artifact_href)
            if not file_info:
                logging.warning("No file info found for artifact href: %s", artifact_href)
                continue

            # Structure the result with pulp_href as key
            results["artifacts"][artifact_key] = {
                "labels": content.get("pulp_labels", {}),
                "url": file_info["file"],
                "sha256": file_info.get("sha256", "")
            }

            logging.debug("Added result for %s: %s", artifact_key, artifact_href)

        return results

    # ============================================================================
    # Repository Management API Methods
    # ============================================================================

    def _create_repository(self, endpoint: str, name: str) -> Response:
        """
        Helper method to create a repository.

        Args:
            endpoint: API endpoint for repository creation
            name: Name of the repository to create

        Returns:
            Response object from the repository creation request
        """
        url = self._url(endpoint)
        data = {"name": name, "autopublish": True}
        return self.session.post(url, json=data, timeout=self.timeout, **self.request_params)

    def _create_distribution(self,
                             endpoint: str,
                             name: str,
                             repository: str,
                             *, basepath: Optional[str] = None,
                             publication: Optional[str] = None) -> Response:
        """
        Helper method to create a distribution.

        Args:
            endpoint: API endpoint for distribution creation
            name: Name of the distribution to create
            repository: Repository PRN or href to associate with the distribution
            basepath: Base path for the distribution (defaults to name)
            publication: Publication href to associate with the distribution (optional)

        Returns:
            Response object from the distribution creation request
        """
        url = self._url(endpoint)
        if publication:
            data = {
                "name": name,
                "base_path": basepath or name,
                "publication": publication,
            }
        else:
            data = {
                "name": name,
                "repository": repository,
                "base_path": basepath or name,
            }
        return self.session.post(url, json=data, timeout=self.timeout, **self.request_params)

    def repository_operation(self, operation: str, repo_type: str, name: str,
                            *, repository: Optional[str] = None, basepath: Optional[str] = None,
                            publication: Optional[str] = None, distribution_href: Optional[str] = None) -> Response:
        """
        Perform repository or distribution operations.

        Args:
            operation: Operation to perform ('create_repo', 'get_repo', 'create_distro', 'get_distro', 'update_distro')
            repo_type: Type of repository/distribution ('rpm' or 'file')
            name: Name of the repository/distribution
            repository: Repository PRN or href (for distribution operations)
            basepath: Base path for distribution (for distribution creation)
            publication: Publication href (for distribution operations)
            distribution_href: Full href of distribution (for update operations)

        Returns:
            Response object from the operation
        """
        if operation == "create_repo":
            endpoint = f"api/v3/repositories/{repo_type}/{repo_type}/"
            return self._create_repository(endpoint, name)
        if operation == "get_repo":
            endpoint = f"api/v3/repositories/{repo_type}/{repo_type}/"
            return self._get_single_resource(endpoint, name)
        if operation == "create_distro":
            endpoint = f"api/v3/distributions/{repo_type}/{repo_type}/"
            return self._create_distribution(endpoint, name, repository,
                                            basepath=basepath, publication=publication)
        if operation == "get_distro":
            endpoint = f"api/v3/distributions/{repo_type}/{repo_type}/"
            return self._get_single_resource(endpoint, name)
        if operation == "update_distro":
            url = str(self.config["base_url"]) + distribution_href
            data = {"publication": publication}
            return self.session.patch(url, json=data, timeout=self.timeout, **self.request_params)

        raise ValueError(f"Unknown operation: {operation}")
