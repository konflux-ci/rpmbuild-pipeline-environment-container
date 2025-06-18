#!/usr/bin/python3
"""
Pulp doesn't provide an API client, we are implementing it for ourselves
"""

import argparse
import concurrent.futures
import glob
import os
import time
import tomllib
import json
from urllib.parse import urlencode
import requests
from requests.adapters import HTTPAdapter
from urllib3.util import Retry
import datetime
import logging


class PulpClient:
    """
    A client for interacting with Pulp API.

    API documentation:
    - https://docs.pulpproject.org/pulp_rpm/restapi.html
    - https://docs.pulpproject.org/pulpcore/restapi.html

    A note regarding PUT vs PATCH:
    - PUT changes all data and therefore all required fields needs to be sent
    - PATCH changes only the data that we are sending

    A lot of the methods require repository, distribution, publication, etc,
    to be the full API endpoint (called "pulp_href"), not simply their name.
    If method argument doesn't have "name" in its name, assume it expects
    pulp_href. It looks like this:
    /pulp/api/v3/publications/rpm/rpm/5e6827db-260f-4a0f-8e22-7f17d6a2b5cc/
    """

    @classmethod
    def create_from_config_file(cls, path=None, domain=None):
        """
        Create a Pulp client from a standard configuration file that is
        used by the `pulp` CLI tool
        """
        path = os.path.expanduser(path or "~/.config/pulp/cli.toml")
        with open(path, "rb") as fp:
            config = tomllib.load(fp)
        return cls(config["cli"], domain)

    def __init__(self, config, domain=None):
        self.domain = domain
        self.config = config
        self.timeout = 60
        retry_strategy = Retry(
            total=4,  # maximum number of retries
            backoff_factor=2,
            status_forcelist=[
                429,
                500,
                502,
                503,
                504,
            ],  # the HTTP status codes to retry on
        )

        adapter = HTTPAdapter(max_retries=retry_strategy)

        # create a new session object
        self.session = requests.Session()
        self.session.mount("http://", adapter)
        self.session.mount("https://", adapter)

    @property
    def headers(self):
        return None

    @property
    def auth(self):
        """
        https://requests.readthedocs.io/en/latest/user/authentication/
        """
        return (self.config["username"], self.config["password"])

    @property
    def cert(self):
        """
        See Client Side Certificates
        https://docs.python-requests.org/en/latest/user/advanced/
        """
        return (self.config["cert"], self.config["key"])

    def url(self, endpoint):
        """
        A fully qualified URL for a given API endpoint
        """
        if self.domain:
            domain = f"{self.domain}".replace("-tenant", "")
        else:
            domain = self.config["domain"]

        relative = os.path.normpath("/".join([
            self.config["api_root"],
            domain,
            endpoint,
        ]))

        # Normpath removes the trailing slash. If it was there, put it back
        if endpoint[-1] == "/":
            relative += "/"
        return self.config["base_url"] + relative

    @property
    def request_params(self):
        """
        Default parameters for our requests
        """
        params = {"timeout": self.timeout}
        if self.headers:
            params = {"headers": self.headers}
        if all(self.cert):
            params["cert"] = self.cert
        else:
            params["auth"] = self.auth
        return params

    def create_rpm_repository(self, name):
        """
        Create an RPM repository
        https://docs.pulpproject.org/pulp_rpm/restapi.html#tag/Repositories:-Rpm/operation/repositories_rpm_rpm_create
        """
        url = self.url("api/v3/repositories/rpm/rpm/")
        data = {"name": name, "autopublish": True}
        return self.session.post(url, json=data, **self.request_params)

    def get_rpm_repository(self, name):
        """
        Get a single RPM repository
        https://docs.pulpproject.org/pulp_rpm/restapi.html#tag/Repositories:-Rpm/operation/repositories_rpm_rpm_list
        """
        # There is no endpoint for querying a single repository by its name,
        # even Pulp CLI does this workaround
        url = self.url("api/v3/repositories/rpm/rpm/?")
        url += urlencode({"name": name, "offset": 0, "limit": 1})
        return self.session.get(url, **self.request_params)

    def get_distribution(self, name):
        """
        Get a single RPM distribution
        https://docs.pulpproject.org/pulp_rpm/restapi.html#tag/Distributions:-Rpm/operation/distributions_rpm_rpm_list
        """
        # There is no endpoint for querying a single repository by its name,
        # even Pulp CLI does this workaround
        url = self.url("api/v3/distributions/rpm/rpm/?")
        url += urlencode({"name": name, "offset": 0, "limit": 1})
        return self.session.get(url, **self.request_params)

    def get_task(self, task):
        """
        Get a detailed information about a task
        """
        url = self.config["base_url"] + task
        return self.session.get(url, **self.request_params)

    def create_rpm_distribution(self, name, repository, basepath=None):
        """
        Create an RPM distribution
        https://docs.pulpproject.org/pulp_rpm/restapi.html#tag/Distributions:-Rpm/operation/distributions_rpm_rpm_create
        """
        url = self.url("api/v3/distributions/rpm/rpm/")
        data = {
            "name": name,
            "repository": repository,
            "base_path": basepath or name,
        }
        return self.session.post(url, json=data, **self.request_params)

    def create_rpm_content(self, path, pulp_label):
        """
        Create content for a given artifact
        https://docs.pulpproject.org/pulp_rpm/restapi.html#tag/Content:-Packages/operation/content_rpm_packages_create
        """
        url = self.url("api/v3/content/rpm/rpmpackages/")
        with open(path, "rb") as fp:
            data = {"pulp_labels": json.dumps(pulp_label)}
            files = {"file": fp}
            package =  self.session.post(
                url, data=data, files=files, **self.request_params)
        return package

    def add_content(self, repository, artifacts):
        """
        Add a list of artifacts to a repository
        https://pulpproject.org/pulp_rpm/restapi/#tag/Repositories:-Rpm/operation/repositories_rpm_rpm_modify
        """
        path = os.path.join(repository, "modify/")
        url = self.config["base_url"] + path
        data = {"add_content_units": artifacts}
        return self.session.post(url, json=data, **self.request_params)

    def create_file_repository(self, name):
        """
        Create an File repository
        https://docs.pulpproject.org/pulp_file/restapi.html#tag/Repositories:-File/operation/repositories_file_file_create
        """
        url = self.url("api/v3/repositories/file/file/")
        data = {"name": name, "autopublish": True}
        return self.session.post(url, json=data, **self.request_params)

    def get_file_repository(self, name):
        """
        Get a single File repository
        https://docs.pulpproject.org/pulp_rpm/restapi.html#tag/Repositories:-File/operation/repositories_rpm_rpm_list
        """
        # There is no endpoint for querying a single repository by its name,
        # even Pulp CLI does this workaround
        url = self.url("api/v3/repositories/file/file/?")
        url += urlencode({"name": name, "offset": 0, "limit": 1})
        return self.session.get(url, **self.request_params)

    def create_file_distribution(self, name, repository, basepath=None):
        """
        Create an File distribution
        https://docs.pulpproject.org/pulp_rpm/restapi.html#tag/Distributions:-File/operation/distributions_rpm_rpm_create
        """
        url = self.url("api/v3/distributions/file/file/")
        data = {
            "name": name,
            "repository": repository,
            "base_path": basepath or name,
        }
        return self.session.post(url, json=data, **self.request_params)

    def create_file_content(self, repository, path, build_id, pulp_label):
        """
        Create content for a given artifact
        https://docs.pulpproject.org/pulp_file/restapi.html#tag/Content:-Files/operation/content_file_files_create
        """
        url = self.url("api/v3/content/file/files/")
        with open(path, "rb") as fp:
            # Relative path is the file name that will be created in the repository
            # Can include '/' if there is a desire to put it in a directory
            file_name = path.split("/")[-1]
            data = {"repository": repository, "relative_path": f"{build_id}/{file_name}", "pulp_labels": json.dumps(pulp_label)}
            files = {"file": fp}
            return self.session.post(
                url, data=data, files=files, **self.request_params)

    def wait_for_finished_task(self, task, timeout=86400):
        """
        Pulp task (e.g. creating a publication) can be running for an
        unpredictably long time. We need to wait until it is finished to know
        what it actually did.
        """
        start = time.time()
        while True:
            logging.info(f"Waiting for {task} to finish.")
            response = self.get_task(task)
            if not response.ok:
                logging.error(f"There was an error processing the task: {response.text}")
                break
            if response.json()["state"] not in ["waiting", "running"]:
                break
            if time.time() > start + timeout:
                logging.error(f"Timed out waiting for {task}")
                break
            time.sleep(5)
        logging.info(f"Task finished: {task}")
        return response

    def find_content_by_build_id(self, build_id):
        url = self.url(f"api/v3/content/?pulp_label_select=build_id~{build_id}")
        return self.session.get(url, **self.request_params)

    def get_file_locations(self, artifacts):
        hrefs = [list(artifact.values())[0] for artifact in artifacts]
        hrefs_string = ','.join(hrefs)
        url = self.url(f"api/v3/artifacts/?pulp_href__in={hrefs_string}")
        return self.session.get(url, **self.request_params)
    
def create_rpm_content(client, rpm, labels):
    logging.info(f"Uploading rpm file: {rpm}")
    content_upload_response = client.create_rpm_content(rpm, labels)
    check_response(content_upload_response)
    return content_upload_response.json()["pulp_href"]
    
def upload_log(client, file_repository_prn, log, build_id, labels):
    logging.info(f"Uploading log file: {log}")
    content_upload_response = client.create_file_content(file_repository_prn, log, build_id, labels)
    client.wait_for_finished_task(content_upload_response.json()['task'])
    
def upload_rpms_logs(rpm_path, args, client, arch, rpm_repository_href, file_repository_prn):
    rpms = glob.glob(os.path.join(rpm_path,"*.rpm"))
    logs = glob.glob(os.path.join(rpm_path,"*.log"))

    labels = {
        "date": f"{now_utc.strftime('%Y-%m-%d %H:%M:%S')}",
        "build_id": f"{args.build_id}",
        "arch": f"{arch}",
        "namespace": f"{args.namespace}",
        "parent_package": f"{args.parent_package}"
    }
    to_await = []
    with concurrent.futures.ThreadPoolExecutor(max_workers=3) as executor:
        to_await = [executor.submit(create_rpm_content, client, rpm, labels) for rpm in rpms]
        rpm_results_artifacts = [future.result() for future in concurrent.futures.as_completed(to_await)]

    for log in logs:
        upload_log(client, file_repository_prn, log, args.build_id, labels)

    rpm_repo_results = client.add_content(rpm_repository_href, rpm_results_artifacts)
    client.wait_for_finished_task(rpm_repo_results.json()['task'])

def collect_results(client, build_id, output_json):
    # Collect results
    resp_json = client.find_content_by_build_id(build_id).json()

    artifacts = [result["artifacts"] for result in resp_json["results"]]

    file_locations_json = client.get_file_locations(artifacts).json()["results"]

    results = {}
    logging.info(f"Collecting Quay URLs for uploaded files.")

    for artifact in artifacts:
        for file in file_locations_json:
            if file["pulp_href"] == list(artifact.values())[0]:
                results[list(artifact.keys())[0]] = file["file"]

    # write to a results file
    with open(output_json, "w") as outfile:
        logging.info(f"Writing Quay URL results to {output_json}")
        outfile.write(json.dumps(results, indent = 2))

def upload_sbom(client, args):
    labels = {
        "date": f"{now_utc.strftime('%Y-%m-%d %H:%M:%S')}",
        "build_id": f"{args.build_id}",
        "namespace": f"{args.namespace}",
        "parent_package": f"{args.parent_package}"
    }
    logging.info(f"Uploading sbom file: {args.sbom_path}")
    content_upload_response = client.create_file_content(file_repository_prn, args.sbom_path, args.build_id,labels)
    client.wait_for_finished_task(content_upload_response.json()['task'])

def check_response(request):
    if not request.ok:
        logging.info(f"An error occured while completing a request: {request.text}")

if __name__ == "__main__":
    parser = argparse.ArgumentParser(description="Create a pulp repository and distribution.")
    parser.add_argument("--repository_name", type=str, help="Name of the repository")
    parser.add_argument("--rpm_path", type=str, help="Root path to the RPM packages")
    parser.add_argument("--sbom_path", type=str, help="Root path to the RPM packages")
    parser.add_argument("--config", type=str, help="Path to the Config")
    parser.add_argument("--build_id", type=str, help="Build id for this run")
    parser.add_argument("--namespace", type=str, help="Namespace this is running out of")
    parser.add_argument("--parent_package", type=str, help="Parent package this is ran for")
    parser.add_argument("--domain", type=str, help="Domain to use for uploading")
    parser.add_argument("--output_json", type=str, help="Where to create the pulp_results json")
    parser.add_argument("-d", "--debug", default=False, action="store_true",
                        help="Debugging output")
    now_utc = datetime.datetime.now(datetime.timezone.utc)

    # Parse the argument
    args = parser.parse_args()
    repository_name = args.repository_name
    rpm_path = args.rpm_path
    config_path = args.config or None
    domain = args.domain or None

    if args.debug:
        logging.basicConfig(level=logging.DEBUG)
    else:
        logging.basicConfig(level=logging.INFO)

    client = PulpClient.create_from_config_file(path=config_path, domain=domain)

    # Create rpm repository
    logging.info("Creating the RPM repository if needed")
    repository_response = client.create_rpm_repository(repository_name + "/rpms")
    check_response(repository_response)

    # Get the rpm repository
    repository_response = client.get_rpm_repository(repository_name + "/rpms")
    check_response(repository_response)

    # Get the pulp_href for the rpm repository
    rpm_repository_prn = repository_response.json()["results"][0]["prn"]
    rpm_repository_href = repository_response.json()["results"][0]["pulp_href"]

    # Create an rpm distribution
    logging.info("Creating the RPM distribution if needed")
    distro_response = client.create_rpm_distribution(repository_name, rpm_repository_prn, basepath=repository_name)
    check_response(distro_response)

    # Create file repository
    logging.info("Creating the log file repository if needed")
    repository_response = client.create_file_repository(repository_name+ "/logs")
    check_response(repository_response)

    # Get the file repository
    repository_response = client.get_file_repository(repository_name + "/logs")
    check_response(repository_response)

    # Get the pulp_href for the file repository
    file_repository_prn = repository_response.json()["results"][0]["prn"]

    # Create an file distribution
    logging.info("Creating the log file distribution if needed")
    distro_response = client.create_file_distribution(repository_name, file_repository_prn, basepath=repository_name)
    check_response(distro_response)

    # Create sbom repository
    logging.info("Creating the sbom file repository if needed")
    repository_response = client.create_file_repository(repository_name+ "/sbom")
    check_response(distro_response)

    # Get the sbom repository
    repository_response = client.get_file_repository(repository_name + "/sbom")
    check_response(distro_response)

    # Get the pulp_href for the sbom repository
    file_repository_prn = repository_response.json()["results"][0]["prn"]

    # Create an sbom distribution
    logging.info("Creating the sbom file distribution if needed")
    distro_response = client.create_file_distribution(repository_name, file_repository_prn, basepath=repository_name)
    check_response(distro_response)

    archs = ["x86_64", "aarch64", "s390x", "ppc64le"]
    for arch in archs:
        current_path = f"{rpm_path}/{arch}"
        upload_rpms_logs(current_path, args, client, arch, rpm_repository_href, file_repository_prn)

    upload_sbom(client, args)
    collect_results(client, args.build_id, args.output_json)
