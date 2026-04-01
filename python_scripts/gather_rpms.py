#!/usr/bin/python3
"""Gather built RPMs, prepare staging directory and CG import metadata for Koji."""
import datetime
import json
import logging
import os
from argparse import ArgumentParser
import pprint

import koji

from common_utils import calc_checksum


STAGING_DIR = "oras-staging"
CG_IMPORT_JSON = "cg_import.json"
NVR_FILE = "nvr.log"
ANCESTORS_JSON = "ancestors.json"
BROOT_ARCH_RPMS_JSON = "buildroot_rpms.json"

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
# An overall {arch: {"rpms": [rpm...], lockfile: "<arch>/results/buildroot_lock.json"},...} dict,
# to gather all (S)RPMs per buildroot arch, instead of relying on the symlink dest,
# so that we can generate the correct SBOM later with `merge_sbom`.
broot_arch_rpms = {}

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
    logging.debug("Symlinking %s -> %s", dst, src)
    os.symlink(src, dst)


def pick_sbom(rpm_filename, arch):
    """Select and symlink SBOM file for the given RPM."""
    sbom_filename = rpm_filename[:-4] + ".sbom.json"
    arch_sbom_path = os.path.join(arch, sbom_filename)
    logging.info("Picking SBOM %s for %s/%s", arch_sbom_path, arch, rpm_filename)
    if not os.path.exists(arch_sbom_path):
        # TODO: Revert to raising an error once sbom.json files are reliably available.
        logging.warning("SBOM file %s not found for %s/%s, skipping symlink creation",
                        arch_sbom_path, arch, rpm_filename)
        return
    symlink(sbom_filename, arch)


def pick_ancestors(arch, srpm_filename):
    """Select and symlink ancestors.json for the given SRPM arch."""
    ancestor_json = os.path.join(arch, 'results', ANCESTORS_JSON)
    if os.path.exists(ancestor_json):
        dst = os.path.join(STAGING_DIR, ANCESTORS_JSON)
        src = os.path.join('..', arch, 'results', ANCESTORS_JSON)
        logging.debug("Symlinking %s -> %s", dst, src)
        os.symlink(src, dst)
    else:
        logging.warning(
            "Missing %s for selected SRPM %s in %s", ANCESTORS_JSON, srpm_filename, arch
        )


def prepare_koji_broot(arch, pipeline_id, lockfile_path=None):
    """Prepare Koji buildroot data for CG metadata.

    Note: lockfile_path is optional and can be not found, we will skip components if it's missing.
    """
    buildroot = {
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
                "pipeline_id": pipeline_id,
            }
        },
    }
    buildroots[arch] = buildroot
    # components
    if not lockfile_path:
        logging.warning(
            "No lockfile path provided for %s, skipping Koji buildroot components", arch)
        return
    if not os.path.exists(lockfile_path):
        logging.error("Lockfile: %s for %s", lockfile_path, arch)
        return
    with open(lockfile_path, "rt", encoding='utf-8') as f:
        lockfile = json.load(f)
    for rpm in lockfile['buildroot']['rpms']:
        component = {k: v for k, v in rpm.items()
                        if k in ['name', 'version', 'release', 'arch', 'epoch',
                                'sigmd5', 'signature']}
        component["type"] = "rpm"
        buildroot['components'].append(component)


def handle_archdir(arch, pipeline_id):
    """Process architecture directory to collect RPMs."""
    # need to be global here as local scope is used otherwise
    global srpm  # pylint: disable=W0603 global-statement
    logging.info("Handling archdir %s", arch)
    logging.debug("Contents of archdir %s are %s", arch, os.listdir(arch))
    all_rpms = []
    for filename in os.listdir(arch):
        logging.debug("Handling filename %s", filename)
        if filename.endswith('.noarch.rpm'):
            if filename not in noarch_rpms:
                noarch_rpms.append(filename)
                source_archs[filename] = arch
                all_rpms.append(filename)
                symlink(filename, arch)
                pick_sbom(rpm_filename=filename, arch=arch)
        elif filename.endswith('.src.rpm'):
            if not srpm:
                srpm = filename
                source_archs[filename] = arch
                all_rpms.append(filename)
                symlink(filename, arch)
                pick_sbom(rpm_filename=filename, arch=arch)
                pick_ancestors(arch, filename)
        elif filename.endswith('.rpm'):
            rpms.setdefault(arch, []).append(filename)
            all_rpms.append(filename)
            symlink(filename, arch)
            pick_sbom(rpm_filename=filename, arch=arch)
        elif filename.endswith('.log'):
            log_dir = os.path.join(STAGING_DIR, arch)
            if not os.path.exists(log_dir):
                os.mkdir(log_dir)
            logs.append((arch, filename))
            symlink(filename, arch, prepend_arch=True)
        else:
            continue

    # buildroots
    if all_rpms:
        lockfile_path = os.path.join(arch, 'results', 'buildroot_lock.json')
        broot_arch_rpms[arch] = {
            "filelist": all_rpms,
            # we don't symlink buildroot_lock.json, just note its location
            "lockfile": os.path.abspath(lockfile_path)
        }
        logging.debug("(S)RPMs built in %s Buildroot:\n%s", arch, pprint.pformat(rpms, indent=2))
        logging.debug("Buildroot lockfile: %s", broot_arch_rpms[arch]["lockfile"])
        prepare_koji_broot(arch, pipeline_id, lockfile_path=lockfile_path)
    else:
        logging.warning("No (S)RPMs found in archdir %s", arch)


def create_broot_arch_rpms_file():
    """Create buildroot arch (S)RPMs JSON file."""
    with open(os.path.join(STAGING_DIR, BROOT_ARCH_RPMS_JSON), 'wt', encoding='utf-8') as f:
        json.dump(broot_arch_rpms, f, indent=2)


def prepare_arch_data(cli_options):
    """Process all architecture directories to collect RPMs."""
    # we're in results dir, so only archdirs should be present
    for arch in sorted(os.listdir()):
        if not os.path.isdir(arch):
            continue
        if arch == STAGING_DIR:
            continue
        handle_archdir(arch, cli_options.pipeline_id)


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
    """Generate ORAS push file list for artifact upload."""
    with open('oras-push-list.txt', 'wt', encoding='utf-8') as f:
        f.write(f'{srpm}:application/x-rpm\n')
        for arch, arch_rpms in rpms.items():
            for rpm in arch_rpms:
                f.write(f'{rpm}:application/x-rpm\n')
        for rpm in noarch_rpms:
            f.write(f'{rpm}:application/x-rpm\n')
        for arch, log in logs:
            f.write(f'{arch}/{log}:text/plain\n')
        f.write(f'{CG_IMPORT_JSON}:application/json\n')


def create_md_file(cli_options, extra_metadata=None):
    """Create CG import JSON metadata file."""
    path = os.path.join(STAGING_DIR, srpm)
    nevr = koji.get_header_fields(path, ['name', 'version', 'epoch', 'release'])
    extra = {
        "_export_source": {
            "source": "konflux",
            "pipeline": cli_options.pipeline_id,
        },
        "source": {
            "original_url": cli_options.source_url,
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
        "source": cli_options.source_url,
        "extra": extra,
        "start_time": cli_options.start_time,
        "end_time": cli_options.end_time,
        "owner": cli_options.owner,
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
            'checksum': calc_checksum(path, algorithm='sha256'),
            'type': 'rpm',
        })

    # arch rpms
    for arch, arch_rpms in rpms.items():
        for rpm in arch_rpms:
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
                'checksum': calc_checksum(path, algorithm='sha256'),
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
            "checksum": calc_checksum(path, algorithm='sha256'),
            "type": "log",
        })

    md = {
        "metadata_version": 0,
        "build": build,
        "buildroots": list(buildroots.values()),
        "output": output,
    }

    with open(os.path.join(STAGING_DIR, CG_IMPORT_JSON), 'wt', encoding='utf-8') as f:
        json.dump(md, f, indent=2)


def write_nvr():
    """Write NVR (Name-Version-Release) to log file."""
    if srpm:
        with open(NVR_FILE, "wt", encoding="utf-8") as fo:
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
    prepare_arch_data(options)
    logging.info("Createting buildroot arch (S)RPMs file")
    create_broot_arch_rpms_file()
    logging.info("Gathering extra metadata")
    logging.info("Creating md file")
    create_md_file(options, get_metadata())
    logging.info("Generating oras filelist")
    generate_oras_filelist()
    write_nvr()
