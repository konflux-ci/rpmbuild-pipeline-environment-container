Basic information can be found at [README](README.md). Further related
information is in the pipeline repo at
https://github.com/konflux-ci/rpmbuild-pipeline - for architectural decisions
and integration always check this repository's main branch.

The repository contains an image which is built via [Containerfile],
[Containerfile.dev] extends it for running tests, etc. This image would never
be used in production.

All python scripts should be placed under @python_scripts. All scripts should
pass the pylint tests with [pylintrc] configuration.

All unit tests are located in [tests].

Tests are run via [run_tests.sh] - note that many tests need additional testing
data from a different repository (check the file).

Always conform to licensing in [COPYING], contributors should use
`Assisted-by:` trailer for commits and MRs and `Generated-by:` for substantial
AI-generated code.
