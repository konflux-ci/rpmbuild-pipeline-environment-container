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
import json
import logging
import sys
import urllib.request


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


def validate_sbom(sbom_file, url_verify=True):
    """Validate SPDX SBOM file.

    :param sbom_file: Path to SBOM JSON file
    :type sbom_file: str
    :param url_verify: Whether to validate URL accessibility
    :type url_verify: bool
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
    results = validate_source_urls(sbom_data, url_verify)

    # Print summary
    print("\n" + "=" * 60)
    print("SBOM Validation Summary")
    print("=" * 60)
    print(f"Total source packages: {results['total_sources']}")
    print(f"Sources with URLs: {results['sources_with_urls']}")

    if url_verify:
        print(f"Accessible URLs: {results['accessible_urls']}")
        print(f"Inaccessible URLs: {results['inaccessible_urls']}")

        if results['failed_urls']:
            print("\nFailed URL Checks:")
            for failure in results['failed_urls']:
                print(f"  - {failure['spdx_id']} ({failure['name']})")
                print(f"    URL: {failure['url']}")

    validation_passed = results['inaccessible_urls'] == 0 if url_verify else True

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
        '-d',
        '--debug',
        action='store_true',
        default=False,
        help="Debug mode"
    )

    options = parser.parse_args()

    if options.debug:
        logging.basicConfig(level=logging.DEBUG)
    else:
        logging.basicConfig(level=logging.INFO)

    validate_url = not options.no_url_verify
    success = validate_sbom(options.sbom_file, url_verify=validate_url)

    sys.exit(0 if success else 1)


if __name__ == "__main__":
    main()
