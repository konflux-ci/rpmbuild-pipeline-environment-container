#! /usr/bin/python3
import argparse
import glob
import json
import os
import random
from specfile import Specfile


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
        return []
    return values


def get_specfile():
    specfile_path = glob.glob(os.path.join('/var/workdir/source', '*.spec'))

    if len(specfile_path) == 0:
        raise RuntimeError("no spec file available")

    if len(specfile_path) > 1:
        raise RuntimeError(f"too many specfiles: {', '.join(specfile_path)}")

    try:
        spec = Specfile(specfile_path[0])
    except TypeError as ex:
        raise RuntimeError("No .spec file") from ex
    except OSError as ex:
        raise RuntimeError(ex) from ex

    return spec


def get_params():
    parser = argparse.ArgumentParser()
    parser.add_argument('selected_architectures', nargs='+', help="List of selected architectures")
    parser.add_argument('--hermetic', action="store_true", default=False,
                        help="If existing, use hermetic build")
    parser.add_argument('--results-file', required=True, help="Path to result filename")
    args = parser.parse_args()
    return args


args = get_params()

selected_architectures = args.selected_architectures
print(f"Trying to build for {selected_architectures}")

spec = get_specfile()

tags = spec.tags(spec.parsed_sections.package).content
arches = {}
for name in ['exclusivearch', 'excludearch', 'buildarch']:
    arches[name] = get_arches(name, tags)

architecture_decision = {
    "deps-x86_64": "linux/amd64",
    "deps-i686": "linux/amd64",
    "deps-aarch64": "linux/arm64",
    "deps-s390x": "linux/s390x",
    "deps-ppc64le": "linux/ppc64le",
    "build-x86_64": "linux/amd64",
    "build-i686": "linux/amd64",
    "build-aarch64": "linux/arm64",
    "build-s390x": "linux/s390x",
    "build-ppc64le": "linux/ppc64le",
}

# Set the value to 'localhost' if you want to skip the corresponding
# task (the tasks are modified so they do nothing on localhost).
if not args.hermetic:
    for key in architecture_decision.keys():
        if key.startswith("deps-"):
            print(f"non-hermetic build, disabling {key} task")
            architecture_decision[key] = "localhost"
if arches == ['noarch']:
    # when exclusivearch
    if arches['exclusivearch']:
        build_arches = arches['exclusivearch']
        # remove excludeArches
        build_arches = list(set(build_arches) - set(arches['excludearch']))
    else:
        # default build arches
        build_arches = ['x86_64', 'i686', 'aarch64', 's390x', 'ppc64le']
        # build arches without excludeArch
        build_arches = list(set(build_arches) - set(arches['excludearch']))
    selected_architectures = [random.choice(build_arches)]

# skip disabled architectures
for key in architecture_decision.keys():
    found = False
    for arch_ok in selected_architectures:
        if key.endswith("-" + arch_ok):
            found = True
            break
    if found:
        continue
    print(f"disabling {key} because it is not a selected architecture")
    architecture_decision[key] = "localhost"

print(f"Writing into {args.results_file}")
with open(args.results_file, "w") as fd:
    json.dump(architecture_decision, fd)
print(json.dumps(architecture_decision))
