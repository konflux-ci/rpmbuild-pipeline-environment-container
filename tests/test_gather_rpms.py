"""
Tests gather-rpms.py.
"""

import json
import os
import pathlib
import shutil
import subprocess
import tempfile
from unittest import TestCase, skipUnless
import deepdiff

GATHER_RPMS_DATA = os.path.join(
    os.path.dirname(os.path.realpath(__file__)), # tests
    '../test-source-rpms/gather-rpms',
)

def symlink_tree(source_dir, target_dir, ignore=None):
    """Useful for creating fire and forget copy of testing data"""
    source = pathlib.Path(source_dir).resolve()
    target = pathlib.Path(target_dir).resolve()

    for file_path in source.rglob('*'):
        if ignore is not None and ignore in file_path.parts:
            continue
        # Create a relative path to maintain structure
        relative_path = file_path.relative_to(source)
        new_target = target / relative_path

        if file_path.is_dir():
            new_target.mkdir(parents=True, exist_ok=True)
        else:
            # Ensure the parent directory exists
            new_target.parent.mkdir(parents=True, exist_ok=True)
            new_target.symlink_to(file_path)


@skipUnless(
    getattr(shutil.rmtree, "avoids_symlink_attacks", False),
    "System is vulnerable to symlink attacks; skipping full run test."
)
@skipUnless(
    os.path.exists(GATHER_RPMS_DATA),
    "Gather RPM data are not present; skipping full run test"
)
class TestGatherRPMsRun(TestCase):
    """
    Functional test which runs whole gather-rpms.py script against
    real poplated build directory.
    """
    def setUp(self):
        self.maxDiff = None
        self.original_dir = os.getcwd()
        self.workdir = tempfile.mkdtemp()

        # symlink test data
        symlink_tree(os.path.join(GATHER_RPMS_DATA), self.workdir, ignore="correct")
        os.chdir(self.workdir)

    def tearDown(self):
        os.chdir(self.original_dir)
        shutil.rmtree(self.workdir)
        return super().tearDown()

    def clean_sbom(self, sbom):
        """Delete all records with date of SBOM generation"""
        del sbom['creationInfo']['created']
        for pkg in sbom['packages']:
            if 'builtDate' in pkg:
                del pkg['builtDate']
            if 'annotations' in pkg:
                for annotation in pkg['annotations']:
                    del annotation['annotationDate']

        return sbom

    def test_whole_run(self):
        """Runs gather-rpms.py script"""
        script_path = os.path.join(os.path.dirname(__file__),
                                   '../python_scripts/gather-rpms.py')
        subprocess.run([script_path,
                        "--source-url", "source_url",
                        "--start-time", "100",
                        "--end-time", "1000",
                        "--pipeline-id", "1234",
                        "--owner", "test_owner"],
                       check=True)

        # compare nvr.log
        with open("nvr.log", "rt", encoding='utf-8') as fo:
            actual = fo.read().strip()
        correct = "at-3.2.5-17.fc42"
        self.assertEqual(correct, actual)

        # compare oras-push-list.txt
        with open("oras-push-list.txt", "rt", encoding='utf-8') as fo:
            actual = sorted(fo.readlines())
        correct_path = os.path.join(GATHER_RPMS_DATA, "correct/oras-push-list.txt")
        with open(correct_path, "rt", encoding='utf-8') as fo:
            correct = sorted(fo.readlines())
        self.assertEqual(correct, actual)

        # compare cg_import.json
        with open("oras-staging/cg_import.json", "rt", encoding='utf-8') as fo:
            actual = json.load(fo)
            json.dump(actual, open('/tmp/x.json', 'wt'), indent=2)
        correct_path = os.path.join(GATHER_RPMS_DATA, "correct/cg_import.json")
        with open(correct_path, "rt", encoding='utf-8') as fo:
            correct = json.load(fo)
        diff = deepdiff.DeepDiff(correct, actual, ignore_order=True,
                                 cutoff_distance_for_pairs=1, cutoff_intersection_for_pairs=1)
        if diff:
            self.fail(diff.pretty())

        # compare sbom-spdx.json
        with open("oras-staging/sbom-spdx.json", "rt", encoding='utf-8') as fo:
            actual = json.load(fo)
        correct_path = os.path.join(GATHER_RPMS_DATA, "correct/sbom-spdx.json")
        with open(correct_path, "rt", encoding='utf-8') as fo:
            correct = json.load(fo)
        actual = self.clean_sbom(actual)
        correct = self.clean_sbom(correct)
        diff = deepdiff.DeepDiff(correct, actual, ignore_order=True,
                                 cutoff_distance_for_pairs=1, cutoff_intersection_for_pairs=1)
        if diff:
            self.fail(diff.pretty())
