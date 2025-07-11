FROM registry.fedoraproject.org/fedora:43@sha256:9ba8f7825cf1992a20b4b2b1a19317f9f8081e23ac9351ab211e193d8ca49ee0

# https://github.com/containers/buildah/issues/3666#issuecomment-1351992335
VOLUME /var/lib/containers

ADD rpmdiff.patch /rpmdiff.patch

RUN \
    dnf -y install mock koji dist-git-client patch python3-specfile redhat-rpm-config && \
    patch /usr/lib/python3.13/site-packages/koji/rpmdiff.py < /rpmdiff.patch && \
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
