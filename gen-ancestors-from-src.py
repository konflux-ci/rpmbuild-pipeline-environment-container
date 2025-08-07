#!/usr/bin/python3
from argparse import ArgumentParser
import hashlib
import json
import logging
import os
import re
import subprocess
import sys

UPSTREAM_URL_SCHEMAS = ("http://", "https://", "ftp://")
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
    logging.debug(f"Running command: {cmd}")
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
        logging.debug(f"Command stdout: {result.stdout}")
    if result.stderr:
        logging.debug(f"Command stderr: {result.stderr}")
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


def parse_name_version(filename):
    """Parse package name and version from a source filename.

    Attempts to extract the package name and version from a source archive
    filename by splitting on hyphens. Assumes the format is name-version.ext.

    :param filename: Source archive filename to parse
    :type filename: str
    :returns: (package_name, version) where version may be None
    :rtype: tuple
    """
    sname = filename
    sver = None
    fbn, ext = split_archive_filename(filename)
    if ext:
        parts = fbn.split("-")
        sname = "-".join(parts[:-1])
        if not sname:
            sver = None
            sname = fbn
        else:
            sver = parts[-1]
    else:
        logging.warning("%s is not a tarball", filename)
    return sname, sver


def calc_sha256_checksum(filepath, chunk_size=1024**2):
    h = hashlib.sha256()
    with open(filepath, "rb") as fp:
        while True:
            data = fp.read(chunk_size)
            if not data:
                break
            h.update(data)
    return h.hexdigest()


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
    elif len(specfiles) > 1:
        raise OSError(f"Multiple specfiles found: {specfiles}")
    return specfiles[0]


def list_sources(specfile, srcdir="."):
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
        if loc and loc.startswith(UPSTREAM_URL_SCHEMAS):
            url = loc
        else:
            url = None
            # TODO: maybe only accept HTTP(S)?
            logging.info(
                f"{source}: not an accepted url. Expecting {UPSTREAM_URL_SCHEMAS},"
                f" but got {loc}. skipped"
            )

        sname, sver = parse_name_version(sfn)

        src_entry = {
            "url": url,
            "name": sname,
            "version": sver,
            "filename": sfn,
        }

        fp = os.path.join(srcdir, sfn)
        if os.path.isfile(fp):
            src_entry["alg"] = "SHA-256"
            src_entry["checksum"] = calc_sha256_checksum(fp)
        else:
            logging.error("%s: %s doesn't exist in srcdir: %s", source, sfn, srcdir)
        logging.debug("%s info: %s", source, src_entry)
        sources.append(src_entry)
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
    parser.add_argument("-d", "--debug", default=False, action="store_true", help="Debug mode")
    options = parser.parse_args()

    if options.debug:
        logging.basicConfig(level=logging.DEBUG)
    else:
        logging.basicConfig(level=logging.INFO)
    src_dir = os.path.abspath(options.source_dir)
    if not os.path.isdir(src_dir):
        raise ValueError(f"Source directory {src_dir} does not exist or is not a directory")
    logging.info("Working on sourcedir: %s", src_dir)
    specfile = search_specfile(src_dir)
    logging.info(f"Specfile found: {specfile}")
    sources_file = os.path.join(src_dir, "sources")
    if not os.path.isfile(sources_file):
        raise FileNotFoundError(f"Sources file not found in {src_dir}")
    sources = list_sources(specfile, src_dir)
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
