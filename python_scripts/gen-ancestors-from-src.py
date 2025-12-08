#!/usr/bin/python3
"""Generate ancestors data for SBOM from source code.

This script analyzes RPM source and generates required ancestors data for
Software Bill of Materials (SBOM) generation by following:

- guide: https://redhatproductsecurity.github.io/security-data-guidelines/sbom/#rpm
- examples: https://github.com/RedHatProductSecurity/security-data-guidelines/tree/main/sbom/examples/rpm/build

Example usage:
    ./gen-ancestors-from-src.py -s /path/to/source/dir -o ancestors.json

"""
from argparse import ArgumentParser
import hashlib
import json
import logging
import os
import re
import subprocess
import sys

from dist_git_client import _load_config as load_dist_git_config
from dist_git_client import get_distgit_config

UPSTREAM_URL_SCHEMES = ("http://", "https://", "ftp://")
RPM_HEADERS = ["description", "license", "sha256header", "sigmd5"]
SOURCE_RE = re.compile(r"^(source(\d+))\s*:\s*((.*/)?(.*))(\d+#.*)?$", re.IGNORECASE)
ARCHIVE_EXTENSIONS = (
    ".tar.gz",
    ".tgz",
    ".tar.bz2",
    ".tbz2",
    ".tar.xz",
    ".txz",
    ".tar.lz",
    ".tar.lzma",
    ".tar.Z",
    ".zip",
    ".rar",
    ".7z",
    ".gz",
    ".bz2",
    ".xz",
    ".lz",
    ".lzma",
    ".Z",
)


def run_command(cmd, capture_output=True, check=True, cwd=None):
    """Execute a command and return the result.

    :param cmd: Command to execute (string or list)
    :type cmd: str or list
    :param capture_output: Whether to capture stdout/stderr
    :type capture_output: bool
    :param check: Whether to raise exception on non-zero exit code
    :type check: bool
    :param cwd: chdir while running the command
    :type cwd: str
    :returns: Completed process object
    :rtype: subprocess.CompletedProcess
    """
    logging.debug("Running command: %s", cmd)
    result = subprocess.run(
        cmd,
        shell=isinstance(cmd, str),
        capture_output=capture_output,
        text=True,
        check=check,
        cwd=cwd,
        encoding="utf-8",
    )
    if result.stdout:
        logging.debug("Command stdout: %s", result.stdout)
    if result.stderr:
        logging.debug("Command stderr: %s", result.stderr)
    result.check_returncode()
    return result


def split_archive_filename(filename):
    """Split filename into base name and archive extension.

    :param filename: Name of the file to split
    :type filename: str
    :returns: (filename_without_extension, extension),
              or (filename, None) if no archive extension found
    :rtype: tuple
    """
    for ext in ARCHIVE_EXTENSIONS:
        if filename.lower().endswith(ext):
            return (filename[: -len(ext)], ext)
    return (filename, None)


def parse_name_version(basename):
    """Parse package name and version from a source filename.

    Attempts to extract the package name and version from a source archive
    filename by splitting on hyphens. Assumes the format is name-version.

    :param basename: file basename to parse
    :type basename: str
    :returns: (package_name, version) where version may be None
    :rtype: tuple
    """
    sname = basename
    sver = None
    parts = basename.split("-")
    sname = "-".join(parts[:-1])
    if not sname:
        sver = None
        sname = basename
    else:
        sver = parts[-1]
    return sname, sver


def calc_checksum(filepath, algorithm="sha256", chunk_size=1024**2):
    """Calculate checksum of a file using specified algorithm.

    :param filepath: Path to the file
    :type filepath: str
    :param algorithm: Hash algorithm (e.g., 'sha256', 'sha512', 'md5')
    :type algorithm: str
    :param chunk_size: Size of chunks to read
    :type chunk_size: int
    :returns: Hexadecimal checksum string
    :rtype: str
    """
    h = hashlib.new(algorithm.lower())
    with open(filepath, "rb") as fp:
        while True:
            data = fp.read(chunk_size)
            if not data:
                break
            h.update(data)
    return h.hexdigest()


def calc_sha256_checksum(filepath, chunk_size=1024**2):
    """Calculate SHA-256 checksum of a file.

    :param filepath: Path to the file
    :type filepath: str
    :param chunk_size: Size of chunks to read
    :type chunk_size: int
    :returns: SHA-256 hexadecimal checksum string
    :rtype: str
    """
    return calc_checksum(filepath, "sha256", chunk_size)


def is_url_accessible(url):
    """Verify whether a URL is accessible.

    Performs an HTTP HEAD request to check if the URL can be reached.
    Automatically follows redirects.

    :param url: URL to verify
    :type url: str
    :returns: True if URL is accessible, False otherwise
    :rtype: bool
    """
    if not url:
        return False

    try:
        import urllib.request
        import urllib.error

        # Create opener that follows redirects (default behavior)
        opener = urllib.request.build_opener(urllib.request.HTTPRedirectHandler)
        req = urllib.request.Request(url, method='HEAD')

        with opener.open(req, timeout=5) as response:
            return response.status == 200
    except Exception as e:
        logging.debug("URL accessibility check failed for %s: %s", url, e)
        return False


def load_distgit_config(srcdir, dist_git_config_dir):
    """Load dist-git configuration for the given source directory.

    Changes to srcdir to detect git remote URL for correct config section.

    :param srcdir: Source directory containing .git/config
    :type srcdir: str
    :param dist_git_config_dir: Path to dist-git-client config directory
    :type dist_git_config_dir: str
    :returns: Tuple of (parsed_url, distgit_config)
    :rtype: tuple
    :raises RuntimeError: If dist-git config cannot be loaded
    """
    original_cwd = os.getcwd()
    try:
        os.chdir(srcdir)
        config = load_dist_git_config(dist_git_config_dir)
        parsed_url, distgit_config = get_distgit_config(config)
        logging.debug("Loaded dist-git config: %s", distgit_config)
        return parsed_url, distgit_config
    finally:
        os.chdir(original_cwd)


def parse_dist_git_sources(sources_file, repo_name, distgit_config, url_verify=True):
    """Parse the sources file from dist-git repo.

    The sources file format follows dist-git-client conventions:
    - Old format (2 parts): checksum filename
    - New format (4 parts): HASHTYPE (filename) = checksum

    Reference: https://github.com/release-engineering/dist-git/blob/main/dist-git-client/dist_git_client.py

    :param sources_file: Path to the sources file
    :type sources_file: str
    :param repo_name: Git repository name
    :type repo_name: str
    :param distgit_config: Dist-git instance configuration
    :type distgit_config: dict
    :param url_verify: Whether to validate lookaside URL accessibility
    :type url_verify: bool
    :returns: Dictionary mapping filename to midstream checksum info
    :rtype: dict
    """
    sources_map = {}
    if not os.path.isfile(sources_file):
        logging.warning("Sources file not found: %s", sources_file)
        return sources_map

    logging.info("Reading sources specification file: %s", sources_file)
    with open(sources_file, "r", encoding="utf-8") as sfd:
        for line in sfd:
            line = line.strip()
            if not line or line.startswith("#"):
                continue

            source_spec = line.split()
            if not source_spec:
                # line full of white-spaces, skip
                continue

            if len(source_spec) == 2:
                # Old format: checksum filename
                # Use default_sum from dist-git config
                default_sum = distgit_config.get("default_sum", "md5")
                checksum, filename = source_spec
                hashtype = default_sum
            elif len(source_spec) == 4:
                # New format: SHA512 (filename) = checksum
                hashtype = source_spec[0]
                filename = os.path.basename(source_spec[1]).strip("()")
                checksum = source_spec[3]
            else:
                logging.warning("Unexpected sources line format: %s", line)
                continue

            # Construct lookaside URL (same as dist_git_client.sources)
            lookaside_url = None
            if "lookaside_location" in distgit_config and "lookaside_uri_pattern" in distgit_config:
                kwargs = {
                    "name": repo_name,
                    "filename": filename,
                    "hashtype": hashtype.lower(),
                    "hash": checksum,
                }
                lookaside_url = '/'.join([
                    distgit_config["lookaside_location"],
                    distgit_config["lookaside_uri_pattern"].format(**kwargs)
                ])
                # Verify the URL is accessible (if validation is enabled)
                if url_verify and not is_url_accessible(lookaside_url):
                    logging.warning("[IMPORTANT] Lookaside URL for %s is not accessible: %s",
                                    filename, lookaside_url)

            sources_map[filename] = {
                "alg": hashtype.upper(),
                "checksum": checksum,
            }
            if lookaside_url:
                sources_map[filename]["url"] = lookaside_url

    logging.debug("Parsed sources file: %s", sources_map)
    return sources_map


def search_specfile(src_dir):
    """Search for a specfile in the given source directory.

    :param src_dir: Source directory to search in
    :type src_dir: str
    :returns: Path to the specfile if found
    :rtype: str
    :raises FileNotFoundError: If no specfile found
    :raises OSError: If multiple specfiles found
    """
    specfiles = []
    for root, _, files in os.walk(src_dir):
        for file in files:
            if file.endswith(".spec"):
                specfiles.append(os.path.join(root, file))
    if len(specfiles) == 0:
        raise FileNotFoundError(f"No specfile found in {src_dir}")
    if len(specfiles) > 1:
        raise OSError(f"Multiple specfiles found: {specfiles}")
    return specfiles[0]


def list_spec_sources(specfile, srcdir=".", url_verify=True):
    """List sources from specfile using rpmdev-spectool.

    :param specfile: Path to the specfile
    :type specfile: str
    :param srcdir: Source directory containing the archives
    :type srcdir: str
    :param url_verify: Whether to validate URL accessibility
    :type url_verify: bool
    :returns: List of source dictionaries
    :rtype: list
    """
    sources = []
    result = run_command(
        [
            "rpmdev-spectool",
            "-d",
            f"_sourcedir {srcdir}",
            "--sources",
            specfile,
        ]
    )
    for line in result.stdout.splitlines():
        m = SOURCE_RE.match(line)
        if not m:
            logging.error("invalid SourceN line: %s", line)
            continue

        (source, idx, loc, _, sfn, _) = m.groups()

        # no need to check if it's a full URL since it is quite simple
        if loc and loc.startswith(UPSTREAM_URL_SCHEMES):
            url = loc
            # Verify the URL is accessible (if validation is enabled)
            if url_verify and not is_url_accessible(url):
                logging.warning("[IMPORTANT] %s: Upstream URL for %s is not accessible: %s",
                                source, sfn, url)
        else:
            url = None
            # TODO: maybe only accept HTTP(S)?
            logging.info(
                "%s: not an accepted url. Expecting %s, but got %s. skipped",
                source, UPSTREAM_URL_SCHEMES, loc
            )
        # Check if this is an archive file without a remote URL
        fbn, ext = split_archive_filename(sfn)
        
        if ext and not url:
            # This is an archive but doesn't have a remote URL
            logging.warning(
                "[IMPORTANT] %s: Archive file %s does not have a remote URL. Location: %s",
                source, sfn, loc
            )

        sname, sver = parse_name_version(fbn)

        src_entry = {
            "url": url,
            "name": sname,
            "version": sver,
            "filename": sfn,
        }

        fp = os.path.join(srcdir, sfn)
        if os.path.isfile(fp):
            src_entry["alg"] = "SHA256"
            src_entry["checksum"] = calc_checksum(fp, algorithm="sha256")
        else:
            logging.error("%s: %s doesn't exist in srcdir: %s", source, sfn, srcdir)
        logging.debug("%s info: %s", source, src_entry)
        sources.append(src_entry)
    return sources


def get_repo_name(remote_url):
    """Extract repository name from parsed git remote URL.

    Follows the same logic as dist_git_client.sources to extract the
    repository name from the URL path.

    :param remote_url: Parsed URL object with path attribute
    :type remote_url: urllib.parse.ParseResult
    :returns: Repository name without .git extension
    :rtype: str
    """
    namespace = remote_url.path.strip('/').split('/')
    repo_name = namespace[-1]  # Get the last part
    if repo_name.endswith(".git"):
        repo_name = repo_name[:-4]
    return repo_name


def list_sources(specfile, srcdir, repo_name, distgit_config, url_verify=True):
    """List sources with midstream information from dist-git sources file.

    Combines spec sources from rpmdev-spectool with midstream checksums
    from the dist-git sources file.

    :param specfile: Path to the specfile
    :type specfile: str
    :param srcdir: Source directory containing archives and sources file
    :type srcdir: str
    :param repo_name: Git repository name
    :type repo_name: str
    :param distgit_config: Dist-git instance configuration
    :type distgit_config: dict
    :param url_verify: Whether to validate URL accessibility
    :type url_verify: bool
    :returns: List of source dictionaries with midstream property
    :rtype: list
    """
    # Get sources from specfile
    sources = list_spec_sources(specfile, srcdir, url_verify)

    # Get sources file path from dist-git config
    sources_file_template = distgit_config.get("sources_file", "sources")
    sources_file_name = sources_file_template.format(name=repo_name)
    sources_file = os.path.join(srcdir, sources_file_name)

    # Parse dist-git sources file for midstream checksums
    midstream_sources = parse_dist_git_sources(sources_file, repo_name, distgit_config, url_verify)

    # Add midstream property to each source
    for src_entry in sources:
        sfn = src_entry["filename"]
        if sfn in midstream_sources:
            src_entry["midstream"] = midstream_sources[sfn]
            logging.debug("Added midstream info for %s: %s", sfn, midstream_sources[sfn])

            # Compare checksums using midstream algorithm
            if "checksum" in midstream_sources[sfn]:
                midstream_alg = midstream_sources[sfn].get("alg", "SHA256")
                midstream_checksum = midstream_sources[sfn]["checksum"]

                # Get local checksum, reusing if algorithm matches
                local_alg = src_entry.get("alg", "").upper()
                local_checksum = None

                if local_alg == midstream_alg.upper():
                    # Reuse already calculated checksum
                    local_checksum = src_entry.get("checksum")
                else:
                    # Need to recalculate with midstream algorithm
                    fp = os.path.join(srcdir, sfn)
                    if os.path.isfile(fp):
                        try:
                            # Replace hyphens in algorithm name without underlines,
                            # for SPDX -> hashlib alg format
                            alg_name = midstream_alg.replace("_", "").lower()
                            local_checksum = calc_checksum(fp, alg_name)
                        except Exception as e:
                            logging.error(
                                "[IMPORTANT] Failed to calculate checksum for %s using algorithm %s: %s",
                                sfn, midstream_alg, e
                            )

                # Compare checksums if local checksum is available
                if local_checksum and local_checksum != midstream_checksum:
                    logging.warning(
                        "[IMPORTANT] Checksum mismatch for %s: local=%s, midstream=%s (algorithm: %s)",
                        sfn, local_checksum, midstream_checksum, midstream_alg
                    )

    return sources


def main():
    parser = ArgumentParser(usage="Generate ancestors data for SBOM from source code")
    parser.add_argument(
        "-s",
        "--source-dir",
        action="store",
        required=True,
        help="Source directory which contains source archive(s) and specfile",
    )
    parser.add_argument(
        "-o",
        "--output-file",
        action="store",
        help="Output file(json) for ancestors data",
    )
    parser.add_argument(
        "--dist-git-config-dir",
        action="store",
        default=None,
        help="Path to dist-git-client config directory (default: $COPR_DISTGIT_CLIENT_CONFDIR or /etc/dist-git-client)",
    )
    parser.add_argument(
        "--no-url-verify",
        action="store_true",
        default=False,
        help="Disable URL accessibility validation",
    )
    parser.add_argument("-d", "--debug", default=False, action="store_true", help="Debug mode")
    options = parser.parse_args()

    if options.debug:
        logging.basicConfig(level=logging.DEBUG)
    else:
        logging.basicConfig(level=logging.INFO)

    # Process dist-git-config-dir with environment variable fallback
    dist_git_config_dir = options.dist_git_config_dir
    if dist_git_config_dir is None:
        dist_git_config_dir = os.environ.get("COPR_DISTGIT_CLIENT_CONFDIR", "/etc/dist-git-client")
    logging.debug("Using dist-git config directory: %s", dist_git_config_dir)

    src_dir = os.path.abspath(options.source_dir)
    if not os.path.isdir(src_dir):
        raise ValueError(f"Source directory {src_dir} does not exist or is not a directory")
    logging.info("Working on sourcedir: %s", src_dir)

    # Load dist-git config early
    parsed_url, distgit_config = load_distgit_config(src_dir, dist_git_config_dir)

    repo_name = get_repo_name(parsed_url)

    specfile = search_specfile(src_dir)
    logging.info("Specfile found: %s", specfile)

    # Determine whether to validate lookaside URLs
    validate_url = not options.no_url_verify

    sources = list_sources(specfile, src_dir, repo_name, distgit_config, validate_url)
    result = {"sources": sources}
    if options.output_file:
        if os.path.exists(options.output_file):
            logging.warning("output file: %s already exists", options.output_file)
        logging.info("Writing RPM manifest to %s", options.output_file)
        fp = open(options.output_file, "wt", encoding="utf-8")
    else:
        fp = sys.stdout
    json.dump(result, fp, indent=2, sort_keys=False)


if __name__ == "__main__":
    main()
