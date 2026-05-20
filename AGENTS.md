Basic information can be found at @README.md, further related information are
in the pipeline repo at https://github.com/konflux-ci/rpmbuild-pipeline - for
architectural decisions and integration always check this repository's main
branch.

Repository contains image which is built via @Containerfile, @Containerfile.dev
extends it for running tests, etc. This image would never be used in
production.

All python scripts should be placed under @python_scripts. All scripts should
pass the pylint tests with @pylintrc configuration.

All unit tests are located in @tests.

Tests are run via @run_tests.sh - note, that many tests needs additional
testing data from different repository (check the file).

Always conform to licensing in @LICENSE, Contributors should use Assisted-by:
trailer for commits and MRs and Generated-by: for source file comments for
substantial AI-generated code.
