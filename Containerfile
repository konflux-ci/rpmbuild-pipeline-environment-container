FROM registry.fedoraproject.org/fedora:41

# https://github.com/containers/buildah/issues/3666#issuecomment-1351992335
VOLUME /var/lib/containers

RUN \
    dnf -y install mock koji dist-git-client && \
    dnf -y clean all && \
    useradd mockbuilder && \
    usermod -a -G mock mockbuilder

ADD gather-rpms.py /usr/bin
