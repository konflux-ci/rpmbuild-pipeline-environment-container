FROM registry.fedoraproject.org/fedora:43@sha256:d47aed1ee2ec5de80f231089188c0033616860cdb9935c7a4d6a0694adc77032

# https://github.com/containers/buildah/issues/3666#issuecomment-1351992335
VOLUME /var/lib/containers

ADD rpmdiff.patch /rpmdiff.patch
ADD rpmautospec-norpm.patch /
ADD repofiles/fedora-infra.repo /etc/yum.repos.d

RUN \
    dnf -y install python3-pip mock koji dist-git-client patch python3-norpm redhat-rpm-config acl rpmautospec jq && \
    patch /usr/lib/python3.14/site-packages/koji/rpmdiff.py < /rpmdiff.patch && \
    patch /usr/lib/python3.14/site-packages/rpmautospec/pkg_history.py < rpmautospec-norpm.patch && \
    dnf remove -y patch && \
    dnf -y clean all && \
    useradd mockbuilder && \
    usermod -a -G mock mockbuilder

ADD specparser.py /usr/lib/python3.14/site-packages/rpmautospec/
ADD site-defaults.cfg /etc/mock/site-defaults.cfg

WORKDIR /src

# Copy package source and install rpmbuild_utils package
COPY rpmbuild_utils ./rpmbuild_utils
COPY pyproject.toml .

# Install package with entry points
RUN pip3 install -e .

WORKDIR /

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
