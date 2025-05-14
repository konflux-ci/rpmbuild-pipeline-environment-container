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
import sys
from urllib.parse import urlencode
import requests
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
    def create_from_config_file(cls, path=None):
        """
        Create a Pulp client from a standard configuration file that is
        used by the `pulp` CLI tool
        """
        path = os.path.expanduser(path or "~/.config/pulp/cli.toml")
        with open(path, "rb") as fp:
            config = tomllib.load(fp)
        return cls(config["cli"])

    def __init__(self, config):
        self.config = config
        self.timeout = 60

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
        domain = self.config["domain"]
        # if domain == "default":
        #     domain = ""

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
        return requests.post(url, json=data, **self.request_params)

    def get_rpm_repository(self, name):
        """
        Get a single RPM repository
        https://docs.pulpproject.org/pulp_rpm/restapi.html#tag/Repositories:-Rpm/operation/repositories_rpm_rpm_list
        """
        # There is no endpoint for querying a single repository by its name,
        # even Pulp CLI does this workaround
        url = self.url("api/v3/repositories/rpm/rpm/?")
        url += urlencode({"name": name, "offset": 0, "limit": 1})
        return requests.get(url, **self.request_params)

    def get_distribution(self, name):
        """
        Get a single RPM distribution
        https://docs.pulpproject.org/pulp_rpm/restapi.html#tag/Distributions:-Rpm/operation/distributions_rpm_rpm_list
        """
        # There is no endpoint for querying a single repository by its name,
        # even Pulp CLI does this workaround
        url = self.url("api/v3/distributions/rpm/rpm/?")
        url += urlencode({"name": name, "offset": 0, "limit": 1})
        return requests.get(url, **self.request_params)

    def get_task(self, task):
        """
        Get a detailed information about a task
        """
        url = self.config["base_url"] + task
        return requests.get(url, **self.request_params)

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
        return requests.post(url, json=data, **self.request_params)

    def create_rpm_content(self, repository, path, pulp_label):
        """
        Create content for a given artifact
        https://docs.pulpproject.org/pulp_rpm/restapi.html#tag/Content:-Packages/operation/content_rpm_packages_create
        """
        url = self.url("api/v3/content/rpm/packages/")
        with open(path, "rb") as fp:
            data = {"repository": repository, "pulp_labels": json.dumps(pulp_label)}
            files = {"file": fp}
            return requests.post(
                url, data=data, files=files, **self.request_params)

    def create_file_repository(self, name):
        """
        Create an File repository
        https://docs.pulpproject.org/pulp_file/restapi.html#tag/Repositories:-File/operation/repositories_file_file_create
        """
        url = self.url("api/v3/repositories/file/file/")
        data = {"name": name, "autopublish": True}
        return requests.post(url, json=data, **self.request_params)

    def get_file_repository(self, name):
        """
        Get a single File repository
        https://docs.pulpproject.org/pulp_rpm/restapi.html#tag/Repositories:-File/operation/repositories_rpm_rpm_list
        """
        # There is no endpoint for querying a single repository by its name,
        # even Pulp CLI does this workaround
        url = self.url("api/v3/repositories/file/file/?")
        url += urlencode({"name": name, "offset": 0, "limit": 1})
        return requests.get(url, **self.request_params)

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
        return requests.post(url, json=data, **self.request_params)

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
            return requests.post(
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
                logging.error(f"There was an error processing the task: {response}")
                break
            if response.json()["state"] not in ["waiting", "running"]:
                break
            if time.time() > start + timeout:
                logging.error(f"Timed out waiting for {task}")
                break
            time.sleep(5)
        return response

    def find_content_by_build_id(self, build_id):
        url = self.url(f"api/v3/content/?pulp_label_select=build_id~{build_id}")
        return requests.get(url, **self.request_params)

    def get_file_locations(self, artifacts):
        hrefs = [list(artifact.values())[0] for artifact in artifacts]
        hrefs_string = ','.join(hrefs)
        url = self.url(f"api/v3/artifacts/?pulp_href__in={hrefs_string}")
        return requests.get(url, **self.request_params)
    
def upload_rpm(client, rpm_repository_prn, rpm, labels):
    logging.info(f"Uploading rpm file: {rpm}")
    content_upload_response = client.create_rpm_content(rpm_repository_prn, rpm, labels)
    client.wait_for_finished_task(content_upload_response.json()['task'])
    
def upload_log(client, file_repository_prn, log, build_id, labels):
    logging.info(f"Uploading log file: {log}")
    content_upload_response = client.create_file_content(file_repository_prn, log, build_id, labels)
    client.wait_for_finished_task(content_upload_response.json()['task'])
    
def upload_rpms_logs(rpm_path, args, client, arch, rpm_repository_prn, file_repository_prn):
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
        to_await.extend([executor.submit(upload_rpm, client, rpm_repository_prn, rpm, labels) for rpm in rpms])
        to_await.extend([executor.submit(upload_log, client, file_repository_prn, log, args.build_id, labels) for log in logs])
        results = [future.result() for future in concurrent.futures.as_completed(to_await)]

def collect_results(client, build_id):
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
    with open("pulp_results.json", "w") as outfile:
        logging.info(f"Writing Quay URL results to pulp_results.json")
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
        logging.error(f"An error occured while completing a request: {request.text}")
        sys.exit(1)

if __name__ == "__main__":
    parser = argparse.ArgumentParser(description="Create a pulp repository and distribution.")
    parser.add_argument("--repository_name", type=str, help="Name of the repository")
    parser.add_argument("--rpm_path", type=str, help="Root path to the RPM packages")
    parser.add_argument("--sbom_path", type=str, help="Root path to the RPM packages")
    parser.add_argument("--config", type=str, help="Path to the Config")
    parser.add_argument("--build_id", type=str, help="Build id for this run")
    parser.add_argument("--namespace", type=str, help="Namespace this is running out of")
    parser.add_argument("--parent_package", type=str, help="Parent package this is ran for")
    parser.add_argument("-d", "--debug", default=False, action="store_true",
                        help="Debugging output")
    now_utc = datetime.datetime.now(datetime.timezone.utc)

    # Parse the argument
    args = parser.parse_args()
    repository_name = args.repository_name
    rpm_path = args.rpm_path
    config_path = args.config or None

    if args.debug:
        logging.basicConfig(level=logging.DEBUG)
    else:
        logging.basicConfig(level=logging.INFO)

    client = PulpClient.create_from_config_file(path=config_path)

    # Create rpm repository
    logging.info("Creating the RPM repository if needed")
    repository_response = client.create_rpm_repository(repository_name + "/rpms")
    check_response(repository_response)

    # Get the rpm repository
    repository_response = client.get_rpm_repository(repository_name + "/rpms")
    check_response(repository_response)

    # Get the pulp_href for the rpm repository
    rpm_repository_prn = repository_response.json()["results"][0]["prn"]

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
        upload_rpms_logs(current_path, args, client, arch, rpm_repository_prn, file_repository_prn)

    upload_sbom(client, args)
    collect_results(client, args.build_id)
