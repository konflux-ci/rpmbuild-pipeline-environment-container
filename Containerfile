FROM registry.fedoraproject.org/fedora:43@sha256:2b488d41acd2548c568790f7b13b24a7c64ef2a817428e639b913bb74a8e1cdd

# https://github.com/containers/buildah/issues/3666#issuecomment-1351992335
VOLUME /var/lib/containers

ADD rpmdiff.patch /rpmdiff.patch
ADD rpmautospec-norpm.patch /

RUN \
    dnf -y install mock koji dist-git-client patch python3-norpm python3-specfile redhat-rpm-config acl rpmautospec && \
    patch /usr/lib/python3.14/site-packages/koji/rpmdiff.py < /rpmdiff.patch && \
    patch /usr/lib/python3.14/site-packages/rpmautospec/pkg_history.py < rpmautospec-norpm.patch && \
    dnf remove -y patch && \
    dnf -y clean all && \
    useradd mockbuilder && \
    usermod -a -G mock mockbuilder

ADD specparser.py /usr/lib/python3.14/site-packages/rpmautospec/
ADD site-defaults.cfg /etc/mock/site-defaults.cfg

ADD python_scripts/gather-rpms.py /usr/bin
ADD python_scripts/pulp_upload.py /usr/bin
ADD python_scripts/pulp_client.py /usr/bin
ADD python_scripts/pulp_transfer.py /usr/bin

ADD python_scripts/check_noarch.py /usr/local/bin/check_noarch.py
ADD python_scripts/merge_syft_sbom.py /usr/local/bin/merge_syft_sbom.py
ADD python_scripts/select_architectures.py /usr/local/bin/select_architectures.py

# TODO: We need to find a better place for this datafile (and autogenerate it)
ADD arch-specific-macro-overrides.json /etc/arch-specific-macro-overrides.json

# TODO: Find a better way to ensure that we never execute RPMSpecParser in Konflux.
RUN sed -i 's/# Note: These calls will alter the results of any subsequent macro expansion/sys.exit(1)/' \
    /usr/lib/python3.*/site-packages/rpmautospec/specparser.py

# Assert utility versions
RUN test "$(rpm --eval '%[ v"'"$(rpm -q --qf '%{VERSION}\n' mock)"'" >= v"6.4" ]')" = "1"

RUN grep sys.exit /usr/lib/python3.*/site-packages/rpmautospec/specparser.py
