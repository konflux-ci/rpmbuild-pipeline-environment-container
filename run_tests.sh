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
      dirname=$(dirname "$file")
      mkdir -p "$target/$dirname"
      # skip already downloaded files
      test -f "$target/$file" && continue
    curl "${curl_options[@]}" "$cache_url/$file" --location -o "$target/$dirname/$base"
    done
}

# Cache those files locally.
download_files test-source-rpms \
                valid-noarch-subpackage/test-noarch-check-1-1.fc42.src.rpm \
                valid-noarch-subpackage/aarch64/test-noarch-check-1-1.fc42.aarch64.rpm \
                valid-noarch-subpackage/aarch64/test-noarch-check-noarch-1-1.fc42.noarch.rpm \
                valid-noarch-subpackage/x86_64/test-noarch-check-1-1.fc42.x86_64.rpm\
                valid-noarch-subpackage/x86_64/test-noarch-check-noarch-1-1.fc42.noarch.rpm \
                broken-noarch-subpackage/test-noarch-check-1-1.fc42.src.rpm \
                broken-noarch-subpackage/aarch64/test-noarch-check-1-1.fc42.aarch64.rpm \
                broken-noarch-subpackage/aarch64/test-noarch-check-noarch-1-1.fc42.noarch.rpm \
                broken-noarch-subpackage/x86_64/test-noarch-check-1-1.fc42.x86_64.rpm \
                broken-noarch-subpackage/x86_64/test-noarch-check-noarch-1-1.fc42.noarch.rpm

download_files test-git-repos git-repos/rpmbuild-pipeline-git.tar.gz

coverage=( --cov-report term-missing --cov python_scripts )
for arg; do
    case $arg in
    --no-coverage) coverage=() ;;
    *) args+=( "$arg" ) ;;
    esac
done

abspath=$(readlink -f .)
export PYTHONPATH="${PYTHONPATH+$PYTHONPATH:}$abspath/python_scripts"
"${PYTHON:-python3}" -m pytest -s tests "${coverage[@]}" "${args[@]}"
