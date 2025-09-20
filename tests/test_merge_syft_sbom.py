"""
Tests merge_syft_sbom.py.
"""

import json
import os
import sys
from unittest import TestCase


from python_scripts.merge_syft_sbom import _main as merge_syft_sbom

SELECTED_ARCHES = ["x86_64", "ppc64le", "s390x", "aarch64"]


class TestMergeSyftSbom(TestCase):
    """
    Unit tests for python_scripts/merge_syft_sbom.py.
    """
    def setUp(self):
        self.maxDiff = None

    def test_valid(self):
        """
        Unit test for valid case of merge_syft_sbom python script.
        """
        testdir = os.path.realpath(__file__)
        testdir = os.path.dirname(testdir)
        sbom_spdx = os.path.join(testdir, "sbom_sources", 'sbom-spdx.json')
        syft_sbom = os.path.join(testdir, "sbom_sources", 'syft_sbom.json')
        sbom_merged = os.path.join(testdir, 'sbom_merged.json')
        sys.argv = ["this", "--sbom-spdx", sbom_spdx, '--syft-sbom', syft_sbom, '--sbom-merged', sbom_merged]
        merge_syft_sbom()
        with open(sbom_merged, "r", encoding="utf-8") as rfd:
            results = json.load(rfd)
        assert results == {
            "spdxVersion": "SPDX-2.3",
            "dataLicense": "CC0-1.0",
            "SPDXID": "SPDXRef-DOCUMENT",
            "creationInfo": {"created": "2025-09-20T21:50:00.325906",
                             "creators": ["Tool: Konflux"]},
            "name": "test-pkg-1.1.1-1.el9",
            "documentNamespace": "TODO",
            "packages": [{"SPDXID": "SPDXRef-noarch-test-pkg",
                          "name": "test-pkg",
                          "versionInfo": "1.1.1-1.el9",
                          "supplier": "Organization: Red Hat",
                          "downloadLocation": "NOASSERTION",
                          "packageFileName": "test-pkg-1.1.1-1.el9.src.rpm",
                          "builtDate": "2025-09-23",
                          "licenseConcluded": "LGPL-2.1-only AND GPL-2.0-or-later",
                          "externalRefs": [{"referenceCategory": "PACKAGE-MANAGER",
                                            "referenceType": "purl",
                                            "referenceLocator": "pkg:rpm/redhat/test-pkg@1.1.1-1.el9?arch=noarch"}],
                          "checksums": [{"algorithm": "SHA256",
                                         "checksumValue": "186deeb746c0802fae513f3429cc9f600b08702b1d188fd597c"}]},
                         {"SPDXID": "SPDXRef-noarch-test-pkg",
                          "name": "test-pkg",
                          "versionInfo": "1.1.1-1.el8",
                          "supplier": "Organization: Red Hat",
                          "downloadLocation": "NOASSERTION",
                          "packageFileName": "test-pkg-1.1.1-1.el8.src.rpm",
                          "builtDate": "2025-09-23",
                          "licenseConcluded": "LGPL-2.1-only AND GPL-2.0-or-later",
                          "externalRefs": [{"referenceCategory": "PACKAGE-MANAGER",
                                            "referenceType": "purl",
                                            "referenceLocator": "pkg:rpm/redhat/test-pkg@1.1.1-1.el8?arch=noarch"}],
                          "checksums": [{"algorithm": "SHA256",
                                         "checksumValue": "186deeb746c0802fae513f3429cc9f600b08702b1d188fd597c"}]}],
            "files": [],
            "relationships": [{"spdxElementId": "SPDXRef-DOCUMENT",
                               "relationshipType": "DESCRIBES",
                               "relatedSpdxElement": "SPDXRef-SRPM"},
                              {"spdxElementId": "SPDXRef-noarch-test-pkg",
                               "relationshipType": "GENERATED_FROM",
                               "relatedSpdxElement": "SPDXRef-SRPM"},
                              {"spdxElementId": "SPDXRef-Source0",
                               "relationshipType": "CONTAINS",
                               "relatedSpdxElement": "SPDXRef-SRPM"},
                              {"spdxElementId": "SPDXRef-noarch-test-pkg",
                               "relationshipType": "GENERATED_FROM",
                               "relatedSpdxElement": "SPDXRef-SRPM"}
                              ],
            "documentDescribes": ["SPDXRef-noarch-test-pkg"]
        }
