# ADR 0002: Custom User Metadata Passthrough for Koji CG Imports

**Date:** 2026-10-15
**Status:** Accepted
**Relates to:** [RHELBLD-17987](https://redhat.atlassian.net/browse/RHELBLD-17987)

## Context

When Konflux builds RPMs and imports them into Koji/Brew as draft builds using
the Content Generator (CG) API, the downstream promotion step
(`promote-koji-draft-build` in release-service-catalog) selects which draft to
promote by querying Koji for builds matching the git source URL + commit SHA,
then selecting the most recent one (`max_by(.creation_time)`).

This selection is **ambiguous** in two production scenarios:

1. **GitLab auto-merge:** When two merge requests share the same HEAD commit
   SHA (GitLab auto-merges one after the other is merged), both produce draft
   builds with identical `source` metadata. The "latest wins" heuristic promotes
   the build from the wrong MR, causing RoG's `tag_build` job to fail.

2. **Identical zstream branches:** Teams like tzdata maintain identical branches
   across RHEL 9.2 / 9.4 / 9.6 / 9.8 zstreams, so the same commit is built
   multiple times for different targets but has the same SHA in all builds.

These ambiguities have required manual OSCI intervention repeatedly over ~a year.

The non-Konflux RoG path already solves this: it passes `--custom-user-metadata`
to `brew build`, which Koji stores at `build.extra.custom_user_metadata`. RoG
then reads this metadata back to select the correct draft build. The Konflux
path had no equivalent mechanism.

### Existing extension point

`gather_rpms.py` already has a **separate** extension hook for downstream
flavors: `/tmp/konflux-extra-koji-metadata.json` (read by `get_metadata()`).
Keys from that file are merged into `extra._export_source`. That file is written
by the RHEL/"rok" flavor for Koji buildroot info (repo_id / buildroot_tag /
event_id).

However, that hook:
- Is written by a flavor-specific step, not the PipelineRun author
- Merges into `_export_source`, not the Koji-standard `custom_user_metadata`
  location
- Is filesystem-based (`/tmp`), requiring coordination across Tekton steps

## Decision

### Add `--custom-user-metadata` CLI flag to `gather_rpms.py`

The script now accepts a JSON string via `--custom-user-metadata`, validates it
as a JSON object (matching Koji's own CLI validation in
`cli/koji_cli/commands.py:629-637`), and stores it verbatim at
`build.extra.custom_user_metadata` in the generated `cg_import.json`.

- **Top-level key:** The metadata is stored at `build.extra.custom_user_metadata`
  (a sibling of `_export_source`, `source`, and `typeinfo`), not inside
  `_export_source`. This matches the Koji-standard location used by `brew build
  --custom-user-metadata` and expected by Koji's hub code.

- **Generic passthrough:** The script does **not** know or validate which keys
  go inside the JSON object. The pipeline is provider-agnostic (shared with the
  Fedora fork); semantic knowledge lives in the PipelineRun template. For
  example, RoG will put `{"mr_iid": "496", "target_branch": "rhel-9.6.0"}` there,
  while other consumers can define their own schema.

- **Fail loudly:** Invalid JSON or non-object values raise `ValueError` with a
  clear error message echoing the offending value. This is critical because:
  - The value comes from a static PipelineRun template authored by a human, so
    malformed input is deterministic and discovered on the first run
  - Silently dropping the metadata would reintroduce the wrong-build-promoted
    bug at a point where nobody is watching the log
  - This runs in the very last pipeline task, so early validation (immediately
    after `argparse`) minimizes wasted time on error

- **Empty/absent → omit key entirely:** When the value is `None`, empty string,
  or whitespace-only, the key is omitted from `extra` rather than set to `{}`.
  This ensures backward compatibility: existing builds without the metadata are
  indistinguishable from new builds where the param was left empty.

### Pipeline integration via secure environment variable

The `rpmbuild-pipeline` YAML adds a `custom-user-metadata` param to the pipeline
and `import-to-quay` task (both `type: string`, `default: ""`), wired through to
`gather_rpms.py`.

**Security:** The value is passed via Tekton's `env:` mechanism, not script
interpolation. Tekton's `$(params.x)` substitution is textual and happens before
shell parsing, so interpolating arbitrary JSON (with quotes, braces, newlines)
directly into the script body is a command-injection vector. The `env:` pattern
already used in `task/rpmbuild.yaml:317-319` substitutes into a YAML value, not
shell text, and the script references the quoted shell variable:

```yaml
env:
  - name: CUSTOM_USER_METADATA
    value: $(params.custom-user-metadata)
script: |
  extra_args=()
  if [ -n "${CUSTOM_USER_METADATA}" ]; then
      extra_args+=(--custom-user-metadata "${CUSTOM_USER_METADATA}")
  fi
  gather_rpms.py ... "${extra_args[@]}"
```

**Backward compatibility:** The conditional append ensures that when the param is
empty (the default, and the case for Fedora and all existing PipelineRuns), the
flag is never passed. This means old environment images that lack the flag
continue to work — anyone who sets the param is opting in and must use a current
image.

### Separation from the existing `/tmp/konflux-extra-koji-metadata.json` hook

The two extension mechanisms are independent:

- `custom_user_metadata` comes from a CLI flag and lands at
  `build.extra.custom_user_metadata`
- The existing `KOJI_BUILDROOT_METADATA_FILE` is read from `/tmp` and merges
  keys into `build.extra._export_source`

They write to different nesting levels and serve different purposes:
- `_export_source` carries Konflux/flavor-specific context (pipeline_id,
  buildroot info)
- `custom_user_metadata` is the Koji-standard location for arbitrary
  user-supplied build metadata, matching the field set by `brew build
  --custom-user-metadata`

No refactor is warranted; the two channels remain separate.

### Validation by Koji hub

Verified that Koji's CG import preserves arbitrary `build.extra` keys:
`kojihub/kojihub.py:7376` does `dslice(metadata['build'], [..., 'extra', ...])`
then only adds default `typeinfo` keys. The hub calls `json.dumps(data['extra'])`
wholesale (line ~6552) with no key whitelist. Arbitrary keys in
`build.extra.custom_user_metadata` survive `import-cg` and are readable via
`getBuild()['extra']['custom_user_metadata']`.

## Consequences

### For the producer side (this repo and rpmbuild-pipeline)

- `gather_rpms.py` gains one new CLI flag; validation is explicit and fails
  loudly on malformed input
- The pipeline and task gain one new optional param; the default is empty for
  backward compatibility
- No change to existing builds that don't set the param
- The Fedora fork will need to absorb the new param (via `diff-flavor.sh`) but
  it defaults to empty and is documented as generic

### For the consumer side (release-service-catalog, out of scope here)

- The promotion pipeline (`promote-koji-draft-build`) can now filter candidates
  by `extra.custom_user_metadata` before `max_by(.creation_time)`, resolving the
  ambiguity when multiple MRs or zstream branches share a commit SHA
- That change is explicitly a **separate ticket**, keeping producer and consumer
  changes independent

### For PipelineRun authors (e.g., RoG)

- Authors can pass `custom-user-metadata: '{"mr_iid": "{{ pull_request_number
  }}", "target_branch": "{{ target_branch }}"}'` (or any other JSON object) and
  the keys will appear in the Koji build metadata unchanged
- No schema is enforced by the pipeline — coordination with the consumer
  (promotion filter) happens out-of-band via documentation

### Rollout order

Because `pipeline/build-rpm-package.yaml` pins `script-environment-image` by
digest, this must roll out in sequence:

1. Merge the environment-container change; let the image build
2. Let Renovate/mintmaker bump the digest in rpmbuild-pipeline
3. Merge the rpmbuild-pipeline YAML changes

The conditional flag append is a safety net, but out-of-order merges would still
fail loudly on the first PipelineRun that sets the param.

### Technical debt avoided

We deliberately did **not**:
- Hardcode `mr_iid` or `target_branch` as pipeline params — the pipeline stays
  provider-agnostic
- Reuse the existing `/tmp/konflux-extra-koji-metadata.json` hook — that merges
  into `_export_source`, not the Koji-standard `custom_user_metadata` location
- Add a Tekton step to write `/tmp/konflux-extra-koji-metadata.json` from a
  param — that would couple the step ordering, require a shared volume, and
  conflate two independent extension points

The generic passthrough keeps the pipeline flavor-neutral and defers the metadata
schema to the PipelineRun template where GitLab/GitHub-specific knowledge belongs.
