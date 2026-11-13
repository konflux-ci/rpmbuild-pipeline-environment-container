# hadolint global ignore=DL3020,DL3041 # ADD vs COPY, dnf install without specific version
FROM registry.fedoraproject.org/fedora:45@sha256:e15959f36d52307f176f8c068009f6f1451c3b238b37a1f03e56dbfa4526e8b1
# https://github.com/containers/buildah/issues/3666#issuecomment-1351992335
VOLUME /var/lib/containers

ADD rpmautospec-norpm.patch /
ADD repofiles/fedora-infra.repo /etc/yum.repos.d

RUN \
    dnf -y --nodocs --setopt=install_weak_deps=False install \
        mock koji dist-git-client patch python3-norpm python3-specfile python3-click redhat-rpm-config \
        acl rpmautospec jq rpmlint podman skopeo dnf-utils license-validate && \
    SPECPARSER=$(find /usr/lib -path "*/rpmautospec/specparser.py" -print -quit) && \
    patch "$SPECPARSER" < rpmautospec-norpm.patch && \
    grep -q 'parser_type = "norpm"' "$SPECPARSER" && \
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
RUN SPECPARSER=$(find /usr/lib -path "*/rpmautospec/specparser.py" -print -quit) && \
    sed -i 's/# Note: These calls will alter the results of any subsequent macro expansion/sys.exit(1)/' "$SPECPARSER"

# Assert utility versions
RUN test "$(rpm --eval '%[ v"'"$(rpm -q --qf '%{VERSION}\n' mock)"'" >= v"6.4" ]')" = "1"

ADD resolv.conf /etc/resolv.conf

RUN SPECPARSER=$(find /usr/lib -path "*/rpmautospec/specparser.py" -print -quit) && \
    grep sys.exit "$SPECPARSER"
