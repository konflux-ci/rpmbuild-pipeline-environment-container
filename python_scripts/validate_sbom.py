#!/usr/bin/python3
"""Validate SPDX SBOM file.

This script validates the final SPDX SBOM JSON file produced by merge_syft_sbom.py.
It checks that URLs from source ancestor data are accessible and valid.

Example usage:
    ./validate_sbom.py merged.spdx.json
    ./validate_sbom.py merged.spdx.json --source-dir /path/to/distgit
    ./validate_sbom.py merged.spdx.json --no-url-verify
"""

import argparse
import hashlib
import json
import logging
import os
import sys
import urllib.request

from common_utils import setup_logging


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
        # Create opener that follows redirects (default behavior)
        opener = urllib.request.build_opener(urllib.request.HTTPRedirectHandler)
        req = urllib.request.Request(url, method='HEAD')

        with opener.open(req, timeout=5) as response:
            return response.status == 200
    except Exception as e:  # pylint: disable=broad-exception-caught
        logging.debug("URL accessibility check failed for %s: %s", url, e)
        return False


def validate_source_checksums(sbom_data, source_dir, checksum_verify=True):
    """Validate checksums in source packages from the SBOM.

    Compares checksums in SBOM against actual files in source directory.

    :param sbom_data: Parsed SBOM JSON data
    :type sbom_data: dict
    :param source_dir: Source directory containing files
    :type source_dir: str or None
    :param checksum_verify: Whether to validate checksums
    :type checksum_verify: bool
    :returns: Dictionary with validation results
    :rtype: dict
    """
    results = {
        'total_sources_with_checksums': 0,
        'verified_checksums': 0,
        'mismatched_checksums': 0,
        'missing_files': 0,
        'failed_checksums': []
    }

    if not checksum_verify or not source_dir:
        return results

    packages = sbom_data.get('packages', [])

    for pkg in packages:
        spdx_id = pkg.get('SPDXID', '')

        # Check if this is a source package
        if not spdx_id.startswith('SPDXRef-Source'):
            continue

        checksums = pkg.get('checksums', [])
        if not checksums:
            continue

        results['total_sources_with_checksums'] += 1

        package_filename = pkg.get('packageFileName', '')
        if not package_filename:
            logging.debug("No packageFileName for %s, skipping checksum validation", spdx_id)
            continue

        # Try to find the file in source directory
        filepath = os.path.join(source_dir, package_filename)
        if not os.path.isfile(filepath):
            results['missing_files'] += 1
            logging.debug("File not found for checksum validation: %s", filepath)
            continue

        # Verify each checksum
        for checksum_entry in checksums:
            algorithm = checksum_entry.get('algorithm', '').upper()
            expected_checksum = checksum_entry.get('checksumValue', '')

            if not algorithm or not expected_checksum:
                continue

            try:
                # Convert SPDX algorithm name to hashlib format
                # SPDX uses names like SHA256, SHA512, MD5
                # hashlib uses lowercase: sha256, sha512, md5
                alg_name = algorithm.replace("-", "").lower()
                actual_checksum = calc_checksum(filepath, alg_name)

                if actual_checksum == expected_checksum:
                    results['verified_checksums'] += 1
                    logging.debug("✓ Checksum verified for %s (%s)", package_filename, algorithm)
                else:
                    results['mismatched_checksums'] += 1
                    results['failed_checksums'].append({
                        'spdx_id': spdx_id,
                        'name': pkg.get('name'),
                        'filename': package_filename,
                        'algorithm': algorithm,
                        'expected': expected_checksum,
                        'actual': actual_checksum
                    })
                    logging.warning(
                        "✗ Checksum mismatch for %s: expected=%s, actual=%s (algorithm: %s)",
                        package_filename, expected_checksum, actual_checksum, algorithm
                    )

            except Exception as e:  # pylint: disable=broad-exception-caught
                logging.error("Failed to calculate checksum for %s: %s", package_filename, e)

    return results


def validate_source_urls(sbom_data, url_verify=True):
    """Validate URLs in source packages from the SBOM.

    Extracts URLs from source packages (SPDXRef-Source*) and validates accessibility.

    :param sbom_data: Parsed SBOM JSON data
    :type sbom_data: dict
    :param url_verify: Whether to validate URL accessibility
    :type url_verify: bool
    :returns: Dictionary with validation results
    :rtype: dict
    """
    results = {
        'total_sources': 0,
        'sources_with_urls': 0,
        'accessible_urls': 0,
        'inaccessible_urls': 0,
        'failed_urls': []
    }

    packages = sbom_data.get('packages', [])

    for pkg in packages:
        spdx_id = pkg.get('SPDXID', '')

        # Check if this is a source package or origin package
        if spdx_id.startswith('SPDXRef-Source'):
            results['total_sources'] += 1

            download_location = pkg.get('downloadLocation', '')

            # Skip NOASSERTION and empty URLs
            if download_location and download_location != 'NOASSERTION':
                results['sources_with_urls'] += 1

                if url_verify:
                    logging.info("Validating URL for %s: %s", spdx_id, download_location)
                    if is_url_accessible(download_location):
                        results['accessible_urls'] += 1
                        logging.debug("✓ %s is accessible", download_location)
                    else:
                        results['inaccessible_urls'] += 1
                        results['failed_urls'].append({
                            'spdx_id': spdx_id,
                            'name': pkg.get('name'),
                            'url': download_location
                        })
                        logging.warning("✗ %s is NOT accessible", download_location)

    return results


def validate_sbom(sbom_file, source_dir=None, url_verify=True, checksum_verify=True):
    """Validate SPDX SBOM file.

    :param sbom_file: Path to SBOM JSON file
    :type sbom_file: str
    :param source_dir: Source directory containing files for checksum validation
    :type source_dir: str or None
    :param url_verify: Whether to validate URL accessibility
    :type url_verify: bool
    :param checksum_verify: Whether to validate checksums
    :type checksum_verify: bool
    :returns: True if validation passes, False otherwise
    :rtype: bool
    """
    logging.info("Loading SBOM file: %s", sbom_file)

    try:
        with open(sbom_file, 'r', encoding='utf-8') as f:
            sbom_data = json.load(f)
    except FileNotFoundError:
        logging.error("SBOM file not found: %s", sbom_file)
        return False
    except json.JSONDecodeError as e:
        logging.error("Invalid JSON in SBOM file: %s", e)
        return False

    # Validate SPDX format
    if 'spdxVersion' not in sbom_data:
        logging.error("Invalid SPDX SBOM: missing spdxVersion")
        return False

    logging.info("SBOM SPDX Version: %s", sbom_data.get('spdxVersion'))
    logging.info("SBOM Document Name: %s", sbom_data.get('name'))

    # Validate source URLs
    logging.info("Validating source package URLs...")
    url_results = validate_source_urls(sbom_data, url_verify)

    # Validate checksums
    checksum_results = {'total_sources_with_checksums': 0, 'verified_checksums': 0,
                       'mismatched_checksums': 0, 'missing_files': 0, 'failed_checksums': []}
    if source_dir and checksum_verify:
        logging.info("Validating source package checksums...")
        checksum_results = validate_source_checksums(sbom_data, source_dir, checksum_verify)

    # Print summary
    print("\n" + "=" * 60)
    print("SBOM Validation Summary")
    print("=" * 60)
    print(f"Total source packages: {url_results['total_sources']}")
    print(f"Sources with URLs: {url_results['sources_with_urls']}")

    if url_verify:
        print(f"Accessible URLs: {url_results['accessible_urls']}")
        print(f"Inaccessible URLs: {url_results['inaccessible_urls']}")

        if url_results['failed_urls']:
            print("\nFailed URL Checks:")
            for failure in url_results['failed_urls']:
                print(f"  - {failure['spdx_id']} ({failure['name']})")
                print(f"    URL: {failure['url']}")

    if source_dir and checksum_verify:
        print("\nChecksum Validation:")
        print(f"Sources with checksums: {checksum_results['total_sources_with_checksums']}")
        print(f"Verified checksums: {checksum_results['verified_checksums']}")
        print(f"Mismatched checksums: {checksum_results['mismatched_checksums']}")
        print(f"Missing files: {checksum_results['missing_files']}")

        if checksum_results['failed_checksums']:
            print("\nFailed Checksum Checks:")
            for failure in checksum_results['failed_checksums']:
                print(f"  - {failure['spdx_id']} ({failure['name']})")
                print(f"    File: {failure['filename']}")
                print(f"    Algorithm: {failure['algorithm']}")
                print(f"    Expected: {failure['expected']}")
                print(f"    Actual:   {failure['actual']}")

    # Determine overall validation result
    url_passed = url_results['inaccessible_urls'] == 0 if url_verify else True
    checksum_passed = checksum_results['mismatched_checksums'] == 0 if (source_dir and checksum_verify) else True
    validation_passed = url_passed and checksum_passed

    if validation_passed:
        print("\n✓ SBOM validation PASSED")
    else:
        print("\n✗ SBOM validation FAILED")

    return validation_passed


def main():
    """Parse command-line arguments and validate SBOM."""
    parser = argparse.ArgumentParser(
        description="Validate SPDX SBOM file",
        usage="validate_sbom.py SBOM_FILE [options]"
    )
    parser.add_argument(
        'sbom_file',
        metavar='SBOM_FILE',
        help="Path to SPDX SBOM JSON file to validate"
    )
    parser.add_argument(
        '-s',
        '--source-dir',
        help="Source directory (distgit repo or SRPM SOURCES dir)"
    )
    parser.add_argument(
        '--no-url-verify',
        action='store_true',
        default=False,
        help="Disable URL accessibility validation"
    )
    parser.add_argument(
        '--no-checksum-verify',
        action='store_true',
        default=False,
        help="Disable checksum validation"
    )
    parser.add_argument(
        '-d',
        '--debug',
        action='store_true',
        default=False,
        help="Debug mode"
    )

    options = parser.parse_args()

    setup_logging(options.debug)

    validate_url = not options.no_url_verify
    validate_checksum = not options.no_checksum_verify
    success = validate_sbom(
        options.sbom_file,
        source_dir=options.source_dir,
        url_verify=validate_url,
        checksum_verify=validate_checksum
    )

    sys.exit(0 if success else 1)


if __name__ == "__main__":
    main()
