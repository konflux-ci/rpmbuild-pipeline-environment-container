FROM registry.fedoraproject.org/fedora:42@sha256:babf2015b8d51ee33f47988c2df7cd1b5656de209c0d8a59103dba5a75bc3cd1

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
