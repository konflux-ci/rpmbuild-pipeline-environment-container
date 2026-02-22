FROM registry.fedoraproject.org/fedora:43@sha256:2c4de0dcd2fe007ed12637fe5d67b0130da39a2e107751b05b830c6e1c647995

ARG WORKSPACE=/konflux

# https://github.com/containers/buildah/issues/3666#issuecomment-1351992335
VOLUME /var/lib/containers

WORKDIR $WORKSPACE

ENV \
    # python shared library
    PYTHONPATH=$PYTHONPATH:$WORKSPACE

ADD rpmdiff.patch /rpmdiff.patch
ADD rpmautospec-norpm.patch /
ADD repofiles/fedora-infra.repo /etc/yum.repos.d

RUN \
    dnf -y install mock koji dist-git-client patch python3-norpm python3-specfile redhat-rpm-config acl rpmautospec jq && \
    patch /usr/lib/python3.14/site-packages/koji/rpmdiff.py < /rpmdiff.patch && \
    patch /usr/lib/python3.14/site-packages/rpmautospec/pkg_history.py < /rpmautospec-norpm.patch && \
    dnf remove -y patch && \
    dnf -y clean all && \
    useradd mockbuilder && \
    usermod -a -G mock mockbuilder

ADD specparser.py /usr/lib/python3.14/site-packages/rpmautospec/
ADD site-defaults.cfg /etc/mock/site-defaults.cfg

# python lib
ADD python_scripts/lib $WORKSPACE/python_scripts/lib

# python scripts to /usr/local/bin
ADD --chmod=755 python_scripts/bin/*.py /usr/local/bin

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

