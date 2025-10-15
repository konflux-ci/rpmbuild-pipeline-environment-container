#!/usr/bin/python3
import datetime
import hashlib
import itertools
import json
import logging
import os
import re
import subprocess
from argparse import ArgumentParser

import koji


STAGING_DIR = "oras-staging"
CG_IMPORT_JSON = "cg_import.json"
SBOM_JSON = "sbom-spdx.json"
NVR_FILE = "nvr.log"

# This is a metadata file that can be offered by RHEL/Fedora pipeline flavors
# that employ Koji buildroots. The file provides info related to the utilized
# Koji buildroot. The expected file format is JSON with key-value pairs:
# repo_id: koji build repo id
# buildroot_tag: koji build tag
# event_id: koji event id of build repo creation
# {"repo_id": <repo_id>, "buildroot_tag": <buildroot_tag>, "event_id": <event_id>}
KOJI_BUILDROOT_METADATA_FILE = "/tmp/konflux-extra-koji-metadata.json"

# TODO - pipeline_url

srpm = None
rpms = {}
noarch_rpms = []
source_archs = {}
logs = []
buildroots = {}

current_time = datetime.datetime.now()


def symlink(src, arch, prepend_arch=False):
    """
    Symlink arch/src/file to STAGING_DIR/file, it works for rpms but not
    for logs, which can have identical names and thus they are copied to
    STAGING_DIR/arch/file (with prepend_arch=True)
    """
    if prepend_arch:
        dst = os.path.join(STAGING_DIR, arch, src)
        src = os.path.join('../..', arch, src)
    else:
        dst = os.path.join(STAGING_DIR, src)
        src = os.path.join('..', arch, src)
    logging.debug(f"Symlinking {dst} -> {src}")
    os.symlink(src, dst)


def handle_archdir(arch):
    # need to be global here as local scope is used otherwise
    global srpm
    logging.info(f"Handling archdir {arch}")
    logging.debug(f"Contents of archdir {arch} are {os.listdir(arch)}")
    for filename in os.listdir(arch):
        logging.debug(f"Handling filename {filename}")
        if filename.endswith('.noarch.rpm'):
            if filename not in noarch_rpms:
                noarch_rpms.append(filename)
                source_archs[filename] = arch
                symlink(filename, arch)
        elif filename.endswith('.src.rpm'):
            if not srpm:
                srpm = filename
                source_archs[filename] = arch
                symlink(filename, arch)
        elif filename.endswith('.rpm'):
            rpms.setdefault(arch, []).append(filename)
            symlink(filename, arch)
        elif filename.endswith('.log'):
            log_dir = os.path.join(STAGING_DIR, arch)
            if not os.path.exists(log_dir):
                os.mkdir(log_dir)
            logs.append((arch, filename))
            symlink(filename, arch, prepend_arch=True)
        else:
            continue
    # buildroot
    buildroots[arch] = {
        "content_generator": {
            "name": "konflux",
            "version": "0.1"
        },
        "container": {
            "type": "docker",
            "arch": arch,
        },
        "host": {
            "os": "RHEL",
            "arch": arch,
        },
        "components": [],
        "tools": [],
        "extra": {
            "konflux": {
                "pipeline_id": options.pipeline_id,
            }
        },
    }


def prepare_arch_data():
    # we're in results dir, so only archdirs should be present
    for arch in sorted(os.listdir()):
        if not os.path.isdir(arch):
            continue
        if arch == STAGING_DIR:
            continue
        handle_archdir(arch)


def get_metadata():
    """
    Gather data from temp koji metadata file.
    """
    if os.path.exists(KOJI_BUILDROOT_METADATA_FILE):
        with open(KOJI_BUILDROOT_METADATA_FILE, "r", encoding="utf-8") as fo:
            metadata = fo.read()
        return json.loads(metadata)

    return {}


def generate_oras_filelist():
    # generate oras filelists
    with open('oras-push-list.txt', 'wt') as f:
        f.write(f'{srpm}:application/x-rpm\n')
        for arch, arch_rpms in rpms.items():
            for rpm in arch_rpms:
                f.write(f'{rpm}:application/x-rpm\n')
        for rpm in noarch_rpms:
            f.write(f'{rpm}:application/x-rpm\n')
        for arch, log in logs:
            f.write(f'{arch}/{log}:text/plain\n')
        f.write(f'{CG_IMPORT_JSON}:application/json\n')
        #f.write(f'{SBOM_JSON}:application/json\n')


def sha256sum(path: str):
    checksum = hashlib.sha256()
    with open(path, "rb") as f:
        while True:
            chunk = f.read(1024 ** 2)
            if not chunk:
                break
            checksum.update(chunk)
    return checksum.hexdigest()


# create cg_import.json
def create_md_file(options, extra_metadata=None):
    path = os.path.join(STAGING_DIR, srpm)
    nevr = koji.get_header_fields(path, ['name', 'version', 'epoch', 'release'])
    extra = {
        "_export_source": {
            "source": "konflux",
            "pipeline": options.pipeline_id,
        },
        "source": {
            "original_url": options.source_url,
        },
        "typeinfo": {
            "rpm": {},
        }
    }

    # only add these entries if extra_metadata exists
    # see KOJI_BUILDROOT_METADATA_FILE for more information
    if extra_metadata:
        for key in extra_metadata:
            extra["_export_source"][key] = extra_metadata[key]

    build = {
        "name": nevr["name"],
        "version": nevr["version"],
        "release": nevr["release"],
        "epoch": nevr["epoch"],
        "source": options.source_url,
        "extra": extra,
        "start_time": options.start_time,
        "end_time": options.end_time,
        "owner": options.owner,
    }

    # create buildroot ids
    for idx, arch in enumerate(buildroots.keys()):
        buildroots[arch]['id'] = idx

    output = []
    # SRPM + noarch
    for rpm in noarch_rpms + [srpm]:
        path = os.path.join(STAGING_DIR, rpm)
        nevra = koji.get_header_fields(path, ['name', 'version', 'release', 'epoch', 'arch'])
        output.append({
            'buildroot_id': buildroots[source_archs[rpm]]['id'],
            'filename': rpm,
            'name': nevra['name'],
            'version': nevra['version'],
            'release': nevra['release'],
            'epoch': nevra['epoch'],
            'arch': nevra['arch'],
            'filesize': os.path.getsize(path),
            'checksum_type': 'sha256',
            'checksum': sha256sum(path),
            'type': 'rpm',
        })

    # arch rpms
    for arch in rpms:
        for rpm in rpms[arch]:
            path = os.path.join(STAGING_DIR, rpm)
            nevra = koji.get_header_fields(path, ['name', 'version', 'release', 'epoch', 'arch'])
            output.append({
                'buildroot_id': buildroots[arch]['id'],
                'filename': rpm,
                'name': nevra['name'],
                'version': nevra['version'],
                'release': nevra['release'],
                'epoch': nevra['epoch'],
                'arch': nevra['arch'],
                'filesize': os.path.getsize(path),
                'checksum_type': 'sha256',
                'checksum': sha256sum(path),
                'type': 'rpm',
            })

    # logs
    for arch, log in logs:
        path = os.path.join(STAGING_DIR, arch, log)
        output.append({
            "buildroot_id": buildroots[arch]['id'],
            "relpath": arch,
            "subdir": arch,
            "filename": log,
            "filesize": os.path.getsize(path),
            "arch": "noarch",
            "checksum_type": "sha256",
            "checksum": sha256sum(path),
            "type": "log",
        })

    md = {
        "metadata_version": 0,
        "build": build,
        "buildroots": list(buildroots.values()),
        "output": output,
    }

    json.dump(md, open(os.path.join(STAGING_DIR, CG_IMPORT_JSON), 'wt'), indent=2)


# from https://github.com/RedHatProductSecurity/security-data-guidelines/blob/main/sbom/examples/rpm/from-koji.py
license_replacements = {
    " and ": " AND ",
    " or ": " OR ",
    "ASL 2.0": "Apache-2.0",
    "Public Domain": "LicenseRef-Fedora-Public-Domain", # TODO: exception for redhat-ca-certificates
}

# from https://github.com/RedHatProductSecurity/security-data-guidelines/blob/main/sbom/examples/rpm/from-koji.py
def get_license(filename):
    licensep = subprocess.run(
        stdout=subprocess.PIPE,
        check=True,
        args=[
            "rpm",
            "-qp",
            "--qf",
            "%{LICENSE}",
            filename,
        ],
    )
    license = licensep.stdout.decode("utf-8")
    return clean_license(license)

def clean_license(license):
    for orig, repl in license_replacements.items():
        license = re.sub(orig, repl, license)
    return license


def create_sbom():
    # https://github.com/RedHatProductSecurity/security-data-guidelines/blob/main/sbom/examples/rpm/openssl-3.0.7-18.el9_2.spdx.json
    sbom = {
        "spdxVersion": "SPDX-2.3",
        "dataLicense": "CC0-1.0",
        "SPDXID": "SPDXRef-DOCUMENT",
        "creationInfo": {
            "created": current_time.isoformat(),
            "creators": [
                "Tool: Konflux" # TODO: missing version
            ],
        },
        #"dataLicense": "", # required
        "name": srpm[:-8],
        #documentNamespace": "https://access.redhat.com/security/data/sbom/beta/spdx/openssl-3.0.7-18.el9_2.json",
        "documentNamespace": "TODO",
        "packages": [],
        "files": [], # are ok to be empty for rpm
        "relationships": [
            {
                "spdxElementId": "SPDXRef-DOCUMENT",
                "relationshipType": "DESCRIBES",
                "relatedSpdxElement": "SPDXRef-SRPM"
            },
        ],
    }

    # produced (s)rpms
    rpm_spdxids = []
    for rpm in [srpm] + noarch_rpms + list(itertools.chain(*rpms.values())):
        path = os.path.join(STAGING_DIR, rpm)
        nevra = koji.get_header_fields(path, ['name', 'version', 'release', 'epoch', 'arch'])
        if nevra['arch'] == 'src':
            spdxid = "SPDXRef-SRPM"
        else:
            spdxid = f"SPDXRef-{nevra['arch']}-{nevra['name']}"
        rpm_spdxids.append(spdxid)
        sbom['packages'].append({
            "SPDXID": spdxid,
            "name": nevra['name'],
            "versionInfo": f"{nevra['version']}-{nevra['release']}",
            "supplier": "Organization: Red Hat",
            "downloadLocation": "NOASSERTION",
            "packageFileName": rpm,
            "builtDate": datetime.date.today().isoformat(),
            "licenseConcluded": get_license(os.path.join(STAGING_DIR, rpm)),
            "externalRefs": [
                {
                    "referenceCategory": "PACKAGE-MANAGER",
                    "referenceType": "purl",
                    "referenceLocator": f"pkg:rpm/redhat/{nevra['name']}@{nevra['version']}-{nevra['release']}?arch={nevra['arch']}",
                }
            ],
            "checksums": [
                {
                    "algorithm": "SHA256",
                    "checksumValue": sha256sum(os.path.join(STAGING_DIR, rpm)), #TODO: it is already in cg_metadata
                }
            ],
        })
        # all rpms are created from our SRPM
        if nevra['arch'] != 'src':
            sbom['relationships'].append({
                "spdxElementId": spdxid,
                "relationshipType": "GENERATED_FROM",
                "relatedSpdxElement": "SPDXRef-SRPM",
            })

    # Add buildroots
    for arch, arch_rpms in rpms.items():
        lockfile_path = os.path.join(arch, 'results/buildroot_lock.json')
        if not os.path.exists(lockfile_path):
            logging.error(f"Missing buildroot_lock.json for {arch}")
            continue
        lockfile = json.load(open(lockfile_path, "rt"))
        buildroot = lockfile['buildroot']
        for rpm in buildroot['rpms']:
            component = {k: v for k, v in rpm.items()
                         if k in ['name', 'version', 'release', 'arch', 'epoch',
                                  'sigmd5', 'signature']}
            component["type"] = "rpm"
            buildroots[arch]['components'].append(component)

            spdxid = f"SPDXRef-{rpm['arch']}-{rpm['name']}"
            pkg = {
                "SPDXID": spdxid,
                "name": rpm['name'],
                "versionInfo": f"{rpm['version']}-{rpm['release']}",
                "supplier": "Organization: Red Hat",
                "downloadLocation": rpm["url"], # private url is acceptable
                "packageFileName": os.path.basename(rpm['url']),
                "licenseConcluded": clean_license(rpm['license']),
                "externalRefs": [
                    {
                        "referenceCategory": "PACKAGE-MANAGER",
                        "referenceType": "purl",
                        "referenceLocator": f"pkg:rpm/redhat/{nevra['name']}@{nevra['version']}-{nevra['release']}?arch={nevra['arch']}",
                    }
                ],
                "checksums": [
                    {
                        "algorithm": "SHA256",
                        "checksumValue": sha256sum(os.path.join(arch, "results/buildroot_repo", os.path.basename(rpm['url']))),
                        #"checksumValue": rpm["sigmd5"],
                        # TODO - we can either pull it from buildroot repo of cachi2
                    }
                ],
                # TODO: - signature to annotation/comment?
            }
            if 'sigmd5' in rpm:
                pkg["annotations"] = {
                    "annotationType": "OTHER",
                    "annotator": "Tool: Konflux",
                    "annotationDate": current_time.isoformat(),
                    "comment": f"sigmd5: {rpm['sigmd5']}",
                }
            sbom['packages'].append(pkg)
            for built_rpm in arch_rpms + [srpm]:
                path = os.path.join(STAGING_DIR, built_rpm)
                nevra = koji.get_header_fields(path, ['name', 'version', 'release', 'epoch', 'arch'])
                if nevra['arch'] == 'src':
                    built_rpm_spdxid = "SPDXRef-SRPM"
                else:
                    built_rpm_spdxid = f"SPDXRef-{nevra['arch']}-{nevra['name']}"
                sbom['relationships'].append({
                    "spdxElementId": built_rpm_spdxid,
                    "relationshipType": "BUILD_DEPENDENCY_OF",
                    "relatedSpdxElement": spdxid,
                    "comment": "Buildroot component"
                })

    '''
    # Add sources to packages
    {
      "SPDXID": "SPDXRef-Source0-origin",
      "name": "openssl",
      "versionInfo": "3.0.7",
      "downloadLocation": "https://openssl.org/source/openssl-3.0.7.tar.gz",
      "packageFileName": "openssl-3.0.7.tar.gz",
      "checksums": [
        {
          "algorithm": "SHA256",
          "checksumValue": "83049d042a260e696f62406ac5c08bf706fd84383f945cf21bd61e9ed95c396e"
        }
      ],
      "externalRefs": [
        {
          "referenceCategory": "PACKAGE-MANAGER",
          "referenceType": "purl",
          "referenceLocator": "pkg:generic/openssl@3.0.7?download_url=https://openssl.org/source/openssl-3.0.7.tar.gz&checksum=sha256:83049d042a260e696f62406ac5c08bf706fd84383f945cf21bd61e9ed95c396e"
        }
      ]
    },
    {
      "SPDXID": "SPDXRef-Source0",
      "name": "openssl",
      "versionInfo": "3.0.7",
      "downloadLocation": "https://github.com/(RH openssl midstream repo)/archive/refs/tags/3.0.7.tar.gz",
      "packageFileName": "openssl-3.0.7-hobbled.tar.gz",
      "checksums": [
        {
          "algorithm": "SHA256",
          "checksumValue": "4105046836812ed422922f851a57500118a99cc0f009b7eff2b3436110393377"
        }
      ],
      "externalRefs": [
        {
          "referenceCategory": "PACKAGE-MANAGER",
          "referenceType": "purl",
          "referenceLocator": "pkg:generic/openssl@3.0.7?download_url=https://github.com/(RH openssl midstream repo)/archive/refs/tags/3.0.7.tar.gz&checksum=sha256:4105046836812ed422922f851a57500118a99cc0f009b7eff2b3436110393377"
        }
      ]
    },
    {

    # Add sources to relationships
    {
      "spdxElementId": "SPDXRef-Source0",
      "relationshipType": "GENERATED_FROM",
      "relatedSpdxElement": "SPDXRef-Source0-origin"
    },
    {
      "spdxElementId": "SPDXRef-SRPM",
      "relationshipType": "CONTAINS",
      "relatedSpdxElement": "SPDXRef-Source0"
    },

    # TODO: buildroot contents
    '''

    # in the end we can update documentDescribes
    sbom['documentDescribes'] = rpm_spdxids
    json.dump(sbom, open(os.path.join(STAGING_DIR, SBOM_JSON), 'wt'), indent=2)


def write_nvr():
    if srpm:
        with open(NVR_FILE, "wt") as fo:
           fo.write(srpm[:-8])


if __name__ == "__main__":
    parser = ArgumentParser()
    parser.add_argument("--source-url", action="store", required=True,
                        help="Original url for sources checkout")
    parser.add_argument("--start-time", type=int, action="store", required=True,
                        help="Build pipeline start timestamp [%(type)s]")
    parser.add_argument("--end-time", type=int, action="store", required=True,
                        help="Build pipeline end timestamp [%(type)s]")
    parser.add_argument("--pipeline-id", action="store", required=True)
    parser.add_argument("--owner", type=str, default=None,
                        help="Build owner if known")
    parser.add_argument("-d", "--debug", default=False, action="store_true",
                        help="Debugging output")
    options = parser.parse_args()

    if options.debug:
        logging.basicConfig(level=logging.DEBUG)
    else:
        logging.basicConfig(level=logging.INFO)

    if not os.path.exists(STAGING_DIR):
        os.makedirs(STAGING_DIR)

    logging.info("Preparing arch data")
    prepare_arch_data()
    logging.info("Gathering extra metadata")
    extra_metadata = get_metadata()
    logging.info("Creating md file")
    create_md_file(options, extra_metadata)
    logging.info("Creating SBOM")
    create_sbom()
    logging.info("Generating oras filelist")
    generate_oras_filelist()
    write_nvr()
