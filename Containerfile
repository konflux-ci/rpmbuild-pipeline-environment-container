FROM registry.fedoraproject.org/fedora:43@sha256:5a739680e58e043503f121690ffa3472bfa7290fb2841b6ad7421f5fe79e829a

# https://github.com/containers/buildah/issues/3666#issuecomment-1351992335
VOLUME /var/lib/containers

ADD rpmautospec-norpm.patch /
ADD repofiles/fedora-infra.repo /etc/yum.repos.d

RUN \
    dnf -y --nodocs --setopt=install_weak_deps=False install \
        mock koji dist-git-client patch python3-norpm python3-specfile redhat-rpm-config \
        acl rpmautospec jq rpmlint podman skopeo dnf-utils license-validate && \
    patch /usr/lib/python3.14/site-packages/rpmautospec/pkg_history.py < rpmautospec-norpm.patch && \
    dnf -y clean all && \
    useradd mockbuilder && \
    usermod -a -G mock mockbuilder

ADD site-defaults.cfg /etc/mock/site-defaults.cfg

ADD python_scripts/*.py /usr/local/bin
RUN ln -s merge_sboms.py /usr/local/bin/merge_syft_sbom.py

# TODO: We need to find a better place for this datafile (and autogenerate it)
ADD arch-specific-macro-overrides.json /etc/arch-specific-macro-overrides.json

ADD patch-git-prepare.sh /usr/local/bin

# TODO: Find a better way to ensure that we never execute RPMSpecParser in Konflux.
RUN sed -i 's/# Note: These calls will alter the results of any subsequent macro expansion/sys.exit(1)/' \
    /usr/lib/python3.*/site-packages/rpmautospec/specparser.py

# Assert utility versions
RUN test "$(rpm --eval '%[ v"'"$(rpm -q --qf '%{VERSION}\n' mock)"'" >= v"6.4" ]')" = "1"

ADD resolv.conf /etc/resolv.conf

RUN grep sys.exit /usr/lib/python3.*/site-packages/rpmautospec/specparser.py
