# Environment (as an image) for scripts in the RPM Build pipeline

This repository provides the source code for the container image used by the
[RPM Build pipeline][pipeline].

The image primarily installs essential tools such as [Mock, Koji, DistGit
client, etc.](https://github.com/konflux-ci/rpmbuild-pipeline-environment-container/blob/main/Containerfile)
and includes a few scripts and patches.

Use of this image outside the RPM Build pipeline is not supported.  For
documentation, please refer to the [pipeline][].

[pipeline]: https://github.com/konflux-ci/rpmbuild-pipeline

# How to run the scripts:

* Development (local):

```
python3 -m python_scripts.bin.select_architectures --help
```

* Production (in container):

```
select_architectures.py --help  # Scripts installed to /usr/local/bin/
```

