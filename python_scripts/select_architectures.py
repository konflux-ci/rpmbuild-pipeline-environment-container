#! /usr/bin/python3

import argparse
import json
import os
import random

from rpm_utils import (
    search_specfile,
    get_arch_specific_tags,
)


WORKDIR = '/var/workdir/source'


def apply_platform_overrides(platform_labels, architecture_decision):
    """
    Parses the list of MPL strings (e.g., "linux-d320-m8xlarge/amd64") and overrides the default 'build-*'
    keys in architecture_decision.
    """
    arch_map = {
        "amd64": "x86_64",
        "arm64": "aarch64",
        "s390x": "s390x",
        "ppc64le": "ppc64le",
    }

    for platform_string in platform_labels:
        found_match = False

        for mpl_arch, target_arch in arch_map.items():
            if platform_string.endswith(mpl_arch):
                found_match = True

                build_key = f"build-{target_arch}"

                if build_key in architecture_decision:
                    print(f"Applying override for {build_key}: {platform_string}")
                    architecture_decision[build_key] = platform_string
                break

        if not found_match:
            print(
                f"Warning: Unknown architecture suffix in override '{platform_string}'. Expected ending with one of "
                f"{list(arch_map.keys())}.")

def get_params():
    """
    Parse command-line arguments.
    """
    parser = argparse.ArgumentParser()
    parser.add_argument('selected_architectures', nargs='+', help="List of selected architectures")
    parser.add_argument('--hermetic', action="store_true", default=False,
                        help="If existing, use hermetic build")
    parser.add_argument('--results-file', help="Path to result filename")
    parser.add_argument("--workdir", default=WORKDIR,
                        help=("Working directory where we read/write files "
                              f"(default {WORKDIR})"))
    parser.add_argument('--platform-labels', nargs='*', default=[], help="List of platform override MPLs")
    parser.add_argument("--macro-overrides-file",
                        default="/etc/arch-specific-macro-overrides.json",
                        help="JSON file with RPM macro overrides")
    parser.add_argument(
        "--target-distribution", default="fedora-rawhide",
        help=("Select the distribution version we build for, e.g., 'rhel-10'. "
              "The default is 'fedora-rawhide'.  This option affects how "
              "some macros in given specfile are expanded, transitively "
              "affecting ExcludeArch, ExclusiveArch and BuildArch values."))
    args = parser.parse_args()
    return args


def _main():
    args = get_params()

    output_file = os.path.join(args.workdir, "selected-architectures.json")
    if args.results_file:
        output_file = args.results_file

    allowed_architectures = set(args.selected_architectures)
    print(f"Trying to build for {allowed_architectures}")

    spec = search_specfile(args.workdir)
    arches = get_arch_specific_tags(spec, args.macro_overrides_file,
                                    args.target_distribution)
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

    # Apply Platform Overrides
    if args.platform_labels:
        print(f"Found platform overrides: {args.platform_labels}")
        apply_platform_overrides(args.platform_labels, architecture_decision)

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
