# hadolint global ignore=DL3020,DL3041 # ADD vs COPY, dnf install without specific version
FROM registry.fedoraproject.org/fedora:45@sha256:dbb22055c0c19f4eba2afbbb717667b0c76aa956c4283700041980ad3710bb73
# https://github.com/containers/buildah/issues/3666#issuecomment-1351992335
VOLUME /var/lib/containers

ADD rpmautospec-norpm.patch /
ADD repofiles/fedora-infra.repo /etc/yum.repos.d

RUN \
    dnf -y --nodocs --setopt=install_weak_deps=False install \
        mock koji dist-git-client patch python3-norpm python3-specfile python3-click redhat-rpm-config \
        acl rpmautospec jq rpmlint podman skopeo dnf-utils license-validate && \
    rpmautospec_dir="$(python3 -c 'import importlib.util; print(importlib.util.find_spec("rpmautospec").submodule_search_locations[0])')" && \
    patch "$rpmautospec_dir/specparser.py" < rpmautospec-norpm.patch && \
    grep -q 'parser_type = "norpm"' "$rpmautospec_dir/specparser.py" && \
    dnf -y clean all && \
    useradd mockbuilder && \
    usermod -a -G mock mockbuilder

ADD site-defaults.cfg /etc/mock/site-defaults.cfg

ADD python_scripts/*.py /usr/local/bin

# TODO: We need to find a better place for this datafile (and autogenerate it)
# https://raw.githubusercontent.com/praiskup/norpm-macro-overrides/refs/heads/main/distro-arch-specific.json
ADD arch-specific-macro-overrides.json /etc/arch-specific-macro-overrides.json

ADD patch-git-prepare.sh /usr/local/bin

# TODO: Find a better way to ensure that we never execute RPMSpecParser in Konflux.
RUN sed -i 's/# Note: These calls will alter the results of any subsequent macro expansion/sys.exit(1)/' \
    /usr/lib/python3.*/site-packages/rpmautospec/specparser.py

# Assert utility versions
RUN test "$(rpm --eval '%[ v"'"$(rpm -q --qf '%{VERSION}\n' mock)"'" >= v"6.4" ]')" = "1"

ADD resolv.conf /etc/resolv.conf

RUN grep sys.exit /usr/lib/python3.*/site-packages/rpmautospec/specparser.py
