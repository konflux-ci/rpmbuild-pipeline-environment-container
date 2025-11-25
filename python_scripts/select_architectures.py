#! /usr/bin/python3

import argparse
import glob
import json
import os
import random
import re
import rpm
from specfile import Specfile, exceptions

WORKDIR = '/var/workdir/source'
CONFIG_DIR = "/etc/konflux-rpmbuild-pipeline"


def safe_attr(name, tags):
    """
    Return evaluated spec file attribute or empty string
    """
    try:
        return getattr(tags, name).expanded_value
    except AttributeError:
        return ""


def get_arches(name, tags):
    """
    Evaluated %{exclusivearch|excludearch|buildarch} as a list
    """
    name_map = {
        'exclusivearch': 'ExclusiveArch',
        'excludearch': 'ExcludeArch',
        'buildarch': 'BuildArch',
    }
    values = safe_attr(name, tags).split()
    unknown = " ".join([x for x in values if x.startswith("%")])
    if unknown:
        print(f"Unknown macros in {name_map[name]}: {unknown}")
        return set()
    return set(values)


def get_macros(specfile_path):
    """
    RPM 4.19 deprecated the %patchN macro. RPM 4.20 removed it completely.
    The macro works on RHEL <= 10 but does not work on Fedora 41+.
    We can no longer even parse RPM spec files with the %patchN macros.
    When we build for old streams, we define the %patchN macros
    manually to be a no-op. It wouldn't build, but we only need to
    extract a few tags that are not affected by patches. Ideally we
    would define %patchN as a parametric macro forwarding arguments to
    %patch -P N, but specfile library doesn't accept that.
    Since N can be any number including zero-prefixed numbers,
    we regex-search the spec file for %patchN uses and define only the macros
    found.
    """
    macros = []
    # Only do this on RPM 4.19.90+ (4.19.9x were pre-releases of 4.20)
    if tuple(int(i) for i in rpm.__version_info__) < (4, 19, 90):
        return macros

    print(f"Checking {specfile_path} for %patchN statements")
    try:
        with open(specfile_path, "rb") as specfile:
            # Find all uses of %patchN in the spec files
            # Using a benevolent regex: commented out macros, etc. match as
            # well
            for patch in re.findall(b"%{?patch(\\d+)\\b", specfile.read()):
                # We operate on bytes because we don't know the spec encoding
                # but the matched part only includes ASCII digits
                patch = f"patch{patch.decode('ascii')}"
                print(f"Defining '%{patch} %dnl' macro")
                macros.append((patch, "%dnl"))
    except OSError:
        pass

    return macros


def get_specfile(workdir=WORKDIR):
    specfile_path = glob.glob(os.path.join(workdir, '*.spec'))

    if len(specfile_path) == 0:
        raise RuntimeError("no spec file available")

    if len(specfile_path) > 1:
        raise RuntimeError(f"too many specfiles: {', '.join(specfile_path)}")

    macros = get_macros(specfile_path[0])

    try:
        spec = Specfile(specfile_path[0], macros=macros)
    except TypeError as ex:
        raise RuntimeError("No .spec file") from ex
    except exceptions.RPMException as ex:
        raise RuntimeError("No .spec file") from ex
    except OSError as ex:
        raise RuntimeError(ex) from ex

    return spec


def get_params():
    parser = argparse.ArgumentParser()
    parser.add_argument('selected_architectures', nargs='+', help="List of selected architectures")
    parser.add_argument('--hermetic', action="store_true", default=False,
                        help="If existing, use hermetic build")
    parser.add_argument('--results-file', help="Path to result filename")
    parser.add_argument('--platforms', help=f"Platform specifiers, as configured within {CONFIG_DIR}",
                        default="normal")
    parser.add_argument("--workdir", default=WORKDIR,
                        help=("Working directory where we read/write files "
                              f"(default {WORKDIR})"))
    args = parser.parse_args()
    return args


def _main():
    args = get_params()

    output_file = os.path.join(args.workdir, "selected-architectures.json")
    if args.results_file:
        output_file = args.results_file

    allowed_architectures = set(args.selected_architectures)
    print(f"Trying to build for {allowed_architectures}")

    spec = get_specfile(args.workdir)

    # pylint: disable=no-member
    tags = spec.tags(spec.parsed_sections.package).content
    arches = {}
    for name in ['exclusivearch', 'excludearch', 'buildarch']:
        arches[name] = get_arches(name, tags)

    # the pipeline can provide its own file
    with open(os.path.join(CONFIG_DIR, f"mpc-platforms-{args.platforms}.json"),
              "r", encoding="utf-8") as fd:
        architecture_decision = json.load(fd)

    # Set the value to 'localhost' if you want to skip the corresponding
    # task (the tasks are modified so they do nothing on localhost).
    if not args.hermetic:
        for key in architecture_decision:
            if key.startswith("deps-"):
                print(f"non-hermetic build, disabling {key} task")
                architecture_decision[key] = "localhost"

    build_architectures = allowed_architectures
    if arches['exclusivearch']:
        print(f"Limit to ExclusiveArch: {arches["exclusivearch"]}")
        build_architectures &= arches["exclusivearch"]
    if arches['excludearch']:
        print(f"Avoid ExcludeArch: {arches["excludearch"]}")
        build_architectures -= arches["excludearch"]
    if arches['buildarch'] == set(['noarch']):
        selected_architectures = [random.choice(list(build_architectures))]
        print(f"We've randomly selected {selected_architectures[0]} from "
              f"{build_architectures}")
    else:
        # this case we catch other buildArch values instead of noarch, for example buildArch: x86_64.
        # Value buildArch should be noarch only or specfile should be without buildArch,
        # but we allow build on all build architectures or list of build architectures
        # as result of buildExclusive and buildExclude when buildArch is something else than noarch.
        selected_architectures = build_architectures

    # skip disabled architectures
    for key in architecture_decision:
        found = False
        for arch_ok in selected_architectures:
            if key.endswith("-" + arch_ok):
                found = True
                break
        if found:
            continue
        print(f"disabling {key} because it is not a selected architecture")
        architecture_decision[key] = "localhost"

    print(f"Writing into {output_file}")
    content = json.dumps(architecture_decision, indent=4) + "\n"
    print(content, end="")
    with open(output_file, "w", encoding="utf-8") as fd:
        fd.write(content)


if __name__ == "__main__":
    _main()
