#!/usr/bin/python3

import json

"""
Expects SBOM created from konflux buildroots and syft-generated one. It will
take the first one and extend it with data from syft.
"""


def merge_sboms(buildroot_sbom, syft_sbom, output_sbom):
    sbom_broot = json.load(open(buildroot_sbom))
    sbom_syft = json.load(open(syft_sbom))

    # https://github.com/RedHatProductSecurity/security-data-guidelines/blob/main/sbom/examples/rpm/build/from-koji.py
    syft_pkgs = sbom_syft.get('packages', [])
    for pkg in syft_pkgs:
        if "externalRefs" not in pkg:
            continue

    sbom_broot['packages'].extend(syft_pkgs)
    sbom_broot['files'].extend(sbom_syft.get("files", []))
    syft_rels = sbom_syft.get("relationships", [])

    # Adjust top-level relationship to document, to link it into Source0
    # of our sources.
    for relationship in syft_rels:
        if (
            relationship["spdxElementId"] == "SPDXRef-DOCUMENT"
            and relationship["relationshipType"] == "DESCRIBES"
        ):
            relationship["spdxElementId"] = "SPDXRef-Source0"  # pick first one
            relationship["relationshipType"] = "CONTAINS"
    sbom_broot['relationships'].extend(syft_rels)

    json.dump(sbom_broot, open(output_sbom, 'wt'))


merge_sboms("sbom-spdx.json", "syft-sbom.json", "sbom-merged.json")
print("Merged sbom-spdx.json and syft-sbom.json to  sbom-merged.json")
