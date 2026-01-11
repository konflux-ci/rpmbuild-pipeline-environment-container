#! /bin/sh -x

# See these discussions:
# https://github.com/konflux-ci/rpmbuild-pipeline/issues/112
# https://github.com/konflux-ci/rpmbuild-pipeline-environment-container/pull/105

set -e
export TZ=UTC LC_ALL=C.utf8
git log --first-parent --no-decorate --no-renames --raw --pretty=fuller --date=default > patch-git-generated-log.txt
git rev-parse HEAD > patch-git-generated-commit.txt
echo v1 >> patch-git-generated-commit.txt
