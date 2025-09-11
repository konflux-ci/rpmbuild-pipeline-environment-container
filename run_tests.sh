#! /bin/bash

set -e
args=()

# download test source rpms
mkdir -p test-source-rpms
for file in python3-pytest-8.3.5-8.fc44.noarch.rpm pytest-8.3.5-8.fc44.src.rpm; do
  # skip already downloaded files
  test -f "test-source-rpms/$file" && continue
curl "https://github.com/konflux-ci/rpmbuild-pipeline-test-sources/raw/refs/heads/main/$file" --location -o "test-source-rpms/$file"
done

coverage=( --cov-report term-missing --cov python_scripts )
for arg; do
    case $arg in
    --no-coverage) coverage=() ;;
    *) args+=( "$arg" ) ;;
    esac
done

abspath=$(readlink -f .)
export PYTHONPATH="${PYTHONPATH+$PYTHONPATH:}$abspath"
"${PYTHON:-python3}" -m pytest -s tests "${coverage[@]}" "${args[@]}"
