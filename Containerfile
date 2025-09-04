FROM registry.fedoraproject.org/fedora:42@sha256:e51c1ae2fa4a7b29352f2666cb4c4ccec6a70f5f5d8a778b1ab10a2857aff458

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
