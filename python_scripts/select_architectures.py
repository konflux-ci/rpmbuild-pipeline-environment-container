#! /usr/bin/python3
"""
Determine which architectures to build for by parsing ExclusiveArch,
ExcludeArch, and BuildArch tags from an RPM spec file.

Outputs selected-architectures.json mapping each build-{arch}/deps-{arch}
task to a container platform (e.g. "linux/amd64") or "localhost" (disabled).

Architecture filtering matches Koji's getArchList() (kojid lines 1379-1409):
intersect with ExclusiveArch, subtract ExcludeArch, then re-add noarch if it
appears in BuildArch or ExclusiveArch and is not excluded.  The noarch build
platform is selected deterministically via NOARCH_PLATFORM_PRIORITY rather
than Koji's random.choice().
"""

import argparse
import json
import os

from norpm.specfile import specfile_expand, ParserHooks
from norpm.exceptions import NorpmError

from rpm_utils import create_macro_registry, search_specfile


WORKDIR = '/var/workdir/source'

# koji selects noarch build arch randomly. Arch pool can be limited by
# per-tag settings (extra.noarch_arches). We can implement it later if needed,
# for now it makes more sense to have fixed priority order based on general
# availability of architectures. If there is not anything available from this list,
# any remaining available arch is used.
NOARCH_PLATFORM_PRIORITY = ["x86_64", "aarch64"]


def get_arches(name, tags):
    """
    Evaluated %{exclusivearch|excludearch|buildarch} as a list
    """
    name_map = {
        'exclusivearch': 'ExclusiveArch',
        'excludearch': 'ExcludeArch',
        'buildarch': 'BuildArch',
    }
    values = tags.get(name, set())
    unknown = " ".join([x for x in values if x.startswith("%")])
    if unknown:
        print(f"Unknown macros in {name_map[name]}: {unknown}")
        return set()
    return set(values)


def apply_platform_overrides(platform_labels, architecture_decision):
    """
    Parses the list of MPL strings (e.g., "linux-d320-m8xlarge/amd64") and overrides the default 'build-*'
    keys in architecture_decision.
    """
    arch_map = {
        "amd64": ["x86_64", "i686"],
        "arm64": ["aarch64"],
        "s390x": ["s390x", "s390"],
        "ppc64le": ["ppc64le"],
    }

    for platform_string in platform_labels:
        found_match = False

        for mpl_arch, target_archs in arch_map.items():
            if platform_string.endswith(mpl_arch):
                for target_arch in target_archs:
                    found_match = True

                    build_key = f"build-{target_arch}"

                    if build_key in architecture_decision:
                        print(f"Applying override for {build_key}: {platform_string}")
                        architecture_decision[build_key] = platform_string
            if found_match:
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


class TagHooks(ParserHooks):
    """ Gather access to spec tags """
    def __init__(self):
        self.tags = {}
    def tag_found(self, name, value, _tag_raw):
        """ Gather EclusiveArch, ExcludeArch and BuildArch... """
        if name not in ["exclusivearch", "excludearch", "buildarch"]:
            return
        if name not in self.tags:
            self.tags[name] = set()
        # even multiple exclu*arch statements are accepted
        self.tags[name].update(value.split())


def get_arch_specific_tags(specfile, database, target_distribution):
    """
    Parse given specfile (against macros from TARGET_DISTRIBUTION) and read ExclusiveArch,
    ExcludeArch and BuildArch statements.  Return a dictionary with
    `<tagname>: set()` where tagname is .tolower().
    """
    registry = create_macro_registry(
    # %dist contains %lua mess, it's safer to clear it (we don't need it)
    macro_overrides={
        "dist": ""
    },
    database=database, target_distribution=target_distribution)

    tags = TagHooks()
    try:
        with open(specfile, "r", encoding="utf8") as fd:
            specfile_expand(fd.read(), registry, tags)
    except NorpmError as err:
        print("WARNING: Building for all architectures since "
              f"the spec file parser failed: failed: {err}")

    arches = {}
    for name in ['exclusivearch', 'excludearch', 'buildarch']:
        arches[name] = get_arches(name, tags.tags)
    return arches


# pylint: disable=too-many-branches,too-many-statements
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
        "deps-s390": "linux/s390x",
        "deps-s390x": "linux/s390x",
        "deps-ppc64le": "linux/ppc64le",
        "deps-noarch": "linux/amd64",
        "build-x86_64": "linux/amd64",
        "build-i686": "linux/amd64",
        "build-aarch64": "linux/arm64",
        "build-s390": "linux/s390x",
        "build-s390x": "linux/s390x",
        "build-ppc64le": "linux/ppc64le",
        "build-noarch": "linux/amd64",
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

    build_architectures = set(allowed_architectures)
    if arches['exclusivearch']:
        print(f"Limit to ExclusiveArch: {arches['exclusivearch']}")
        build_architectures &= arches["exclusivearch"]
    if arches['excludearch']:
        print(f"Avoid ExcludeArch: {arches['excludearch']}")
        build_architectures -= arches["excludearch"]

    # Koji noarch re-addition (kojid lines 1407-1409): if noarch appears in
    # BuildArch or ExclusiveArch (and is not in ExcludeArch), add it to the
    # build set so the noarch task is enabled.
    if 'noarch' not in arches['excludearch'] and \
            ('noarch' in arches.get('buildarch', set()) or
             'noarch' in arches.get('exclusivearch', set())):
        build_architectures.add('noarch')

    if not build_architectures:
        raise SystemExit(
            f"Error: No valid architectures remain after applying "
            f"ExclusiveArch ({arches['exclusivearch']}) and "
            f"ExcludeArch ({arches['excludearch']}) filters "
            f"against allowed architectures ({allowed_architectures})")

    if arches['buildarch'] == {'noarch'}:
        if 'noarch' not in build_architectures:
            raise SystemExit(
                "Error: BuildArch is noarch but noarch is excluded by "
                f"ExcludeArch ({arches['excludearch']})")
        selected_architectures = {'noarch'}
    elif arches['buildarch']:
        build_architectures &= arches['buildarch']
        if not build_architectures:
            raise SystemExit(
                f"Error: BuildArch ({arches['buildarch']}) does not match "
                f"any allowed architecture ({allowed_architectures})")
        selected_architectures = build_architectures
    else:
        selected_architectures = build_architectures

    # Pick a platform for build-noarch from available real architectures,
    # respecting ExclusiveArch/ExcludeArch constraints (Koji choose_taskarch
    # parity).  Falls back to all allowed architectures if no real arches
    # remain after filtering (e.g. ExclusiveArch: noarch).
    if 'noarch' in selected_architectures:
        real_arches = build_architectures - {'noarch'}
        if not real_arches:
            real_arches = allowed_architectures
        for preferred in NOARCH_PLATFORM_PRIORITY:
            if preferred in real_arches:
                architecture_decision["build-noarch"] = \
                    architecture_decision[f"build-{preferred}"]
                architecture_decision["deps-noarch"] = \
                    architecture_decision[f"deps-{preferred}"]
                print(f"noarch platform selected from {preferred}: "
                      f"{architecture_decision['build-noarch']}")
                break
        else:
            fallback = sorted(real_arches)[0]
            architecture_decision["build-noarch"] = \
                architecture_decision[f"build-{fallback}"]
            architecture_decision["deps-noarch"] = \
                architecture_decision[f"deps-{fallback}"]
            print(f"Warning: no architecture in NOARCH_PLATFORM_PRIORITY "
                  f"matched available arches {real_arches}, "
                  f"build-noarch falling back to {fallback}: "
                  f"{architecture_decision['build-noarch']}")

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
