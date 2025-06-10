FROM registry.fedoraproject.org/fedora:42@sha256:4e2ac5a754dc80babb40100857d27a028f7cbb077bf0a7e4cc66c2533c37c6a2

# https://github.com/containers/buildah/issues/3666#issuecomment-1351992335
VOLUME /var/lib/containers

ADD rpmdiff.patch /rpmdiff.patch

RUN \
    dnf -y install mock koji dist-git-client patch python3-specfile && \
    patch /usr/lib/python3.13/site-packages/koji/rpmdiff.py < /rpmdiff.patch && \
    dnf remove -y patch && \
    dnf -y clean all && \
    useradd mockbuilder && \
    usermod -a -G mock mockbuilder

ADD site-defaults.cfg /etc/mock/site-defaults.cfg

ADD gather-rpms.py /usr/bin
