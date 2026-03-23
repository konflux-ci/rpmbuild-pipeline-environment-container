FROM registry.fedoraproject.org/fedora:43@sha256:64697270f3cff210f09d8a086fe9c578247f64b2b3205c13e2094fe380f4137c

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

ADD python_scripts/gather_rpms.py /usr/local/bin/gather_rpms.py
ADD python_scripts/check_noarch.py /usr/local/bin/check_noarch.py
ADD python_scripts/common_utils.py /usr/local/bin/common_utils.py
ADD python_scripts/gen_ancestors_from_src.py /usr/local/bin/gen_ancestors_from_src.py
ADD python_scripts/merge_sboms.py /usr/local/bin/merge_sboms.py
RUN ln -s merge_sboms.py /usr/local/bin/merge_syft_sbom.py
ADD python_scripts/rpm_utils.py /usr/local/bin/rpm_utils.py
ADD python_scripts/select_architectures.py /usr/local/bin/select_architectures.py
ADD python_scripts/validate_sbom.py /usr/local/bin/validate_sbom.py

# TODO: We need to find a better place for this datafile (and autogenerate it)
ADD arch-specific-macro-overrides.json /etc/arch-specific-macro-overrides.json

ADD patch-git-prepare.sh /usr/bin

# TODO: Find a better way to ensure that we never execute RPMSpecParser in Konflux.
RUN sed -i 's/# Note: These calls will alter the results of any subsequent macro expansion/sys.exit(1)/' \
    /usr/lib/python3.*/site-packages/rpmautospec/specparser.py

# Assert utility versions
RUN test "$(rpm --eval '%[ v"'"$(rpm -q --qf '%{VERSION}\n' mock)"'" >= v"6.4" ]')" = "1"

ADD resolv.conf /etc/resolv.conf

RUN grep sys.exit /usr/lib/python3.*/site-packages/rpmautospec/specparser.py