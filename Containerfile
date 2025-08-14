FROM registry.fedoraproject.org/fedora:44@sha256:5191d9fd7771a4b2bc30b28a09816a1cecce55ee7a3532f9b2915c38fa9fc611

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
