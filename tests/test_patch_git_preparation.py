"""
Test patch-git-prepare.sh script
"""

import os
import subprocess
import tempfile
from pathlib import Path


def test_patch_git_prep():
    """
    Just run the script against our repo, and compare with the expected output.
    """

    root_dir = Path(__file__).parent.parent.absolute()
    script_path = root_dir / "patch-git-prepare.sh"
    expected_file = root_dir / "tests" / "patch-git-example-output.txt"
    repos_dir = root_dir / "test-git-repos" / "git-repos"
    repo_tarball = repos_dir / "rpmbuild-pipeline-git.tar.gz"

    # Extract the test repository into the temporary directory
    with tempfile.TemporaryDirectory() as tmp_dir:
        workdir = Path(tmp_dir)

        subprocess.run(
            ["tar", "-xzf", str(repo_tarball), "-C", str(workdir)],
            check=True
        )

        git_dir = workdir / "rpmbuild-pipeline-git"
        env = os.environ.copy()
        env["GIT_CONFIG_COUNT"] = "1"
        env["GIT_CONFIG_KEY_0"] = "safe.directory"
        env["GIT_CONFIG_VALUE_0"] = str(git_dir)

        r = subprocess.run(
            [str(script_path)],
            capture_output=True,
            text=True,
            check=False,
            cwd=git_dir,
            env=env,
        )

        if r.returncode:
            raise RuntimeError(f"Command errored: {r.stderr}")

        generated_file = git_dir / "patch-git-generated-log.txt"
        actual_content = generated_file.read_text()
        expected_content = expected_file.read_text()

        assert actual_content == expected_content
