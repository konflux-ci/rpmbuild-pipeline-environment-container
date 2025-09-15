#! /bin/bash

set -e
args=()

# download test source rpms
mkdir -p test-source-rpms

curl_options=(--location --connect-timeout 60 --retry 3 --retry-delay 10
    --remote-time --show-error --fail)

cache_url=https://github.com/konflux-ci/rpmbuild-pipeline-test-sources/raw/refs/heads/main/

# $1 directory
# $@ files to download from GitHub
download_files()
{
    target=$1; shift
    mkdir -p "$target"
    for file in "$@"; do
      base=$(basename "$file")
      # skip already downloaded files
      test -f "$target/$file" && continue
    curl "${curl_options[@]}" "$cache_url/$file" --location -o "$target/$base"
    done
}

# Cache those files locally.
download_files test-source-rpms python3-pytest-8.3.5-8.fc44.noarch.rpm pytest-8.3.5-8.fc44.src.rpm

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
