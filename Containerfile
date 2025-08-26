FROM registry.fedoraproject.org/fedora:42@sha256:23d30b33e7412bb3d1e93201dbb66d3b7af07925acbfc483e87c9b57e42899c1

# https://github.com/containers/buildah/issues/3666#issuecomment-1351992335
VOLUME /var/lib/containers

ADD rpmdiff.patch /rpmdiff.patch
ADD mock-6.3-lockfile-repoquery.patch /

RUN \
    dnf -y install mock koji dist-git-client patch python3-specfile redhat-rpm-config acl && \
    patch /usr/lib/python3.13/site-packages/koji/rpmdiff.py < /rpmdiff.patch && \
    patch /usr/lib/python3.13/site-packages/mockbuild/plugins/buildroot_lock.py < mock-6.3-lockfile-repoquery.patch && \
    dnf remove -y patch && \
    dnf -y clean all && \
    useradd mockbuilder && \
    usermod -a -G mock mockbuilder

ADD site-defaults.cfg /etc/mock/site-defaults.cfg

ADD gather-rpms.py /usr/bin
ADD pulp-upload.py /usr/bin

ADD python_scripts/check_noarch.py /usr/local/bin/check_noarch.py
ADD python_scripts/merge_syft_sbom.py /usr/local/bin/merge_syft_sbom.py
ADD python_scripts/select_architectures.py /usr/local/bin/select_architectures.py
