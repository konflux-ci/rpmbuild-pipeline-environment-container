# ADR 0001: Architecture Filtering Parity with Koji

**Date:** 2026-07-08
**Status:** Accepted
**Supersedes:** Initial version (crash-fix only)

## Context

`select_architectures.py` determines which architectures to build for by
parsing `ExclusiveArch`, `ExcludeArch`, and `BuildArch` tags from RPM spec
files.  The reference implementation for this logic is Koji's builder daemon
(`kojid`), specifically the `getArchList()` and `choose_taskarch()` functions.

Koji uses a two-phase architecture model:

1. **`getArchList()`** (kojid:1379) determines *what* to build.  It intersects
   allowed arches with `ExclusiveArch`, subtracts `ExcludeArch`, then
   **re-adds `noarch`** if it appears in `BuildArch` or `ExclusiveArch` (and
   is NOT in `ExcludeArch`) — lines 1407-1409.
2. **`choose_taskarch()`** (kojid:1425) determines *where* noarch builds run.
   It picks a random real architecture from the filtered set to assign as the
   build host.

Previously, `select_architectures.py` collapsed both decisions into a single
random architecture choice for noarch packages, which caused crashes and
lacked a dedicated noarch build task.  The pipeline is adding a `build-noarch`
Tekton task (analogous to the existing per-arch tasks), requiring the script
to emit `build-noarch` as a first-class entry in `selected-architectures.json`.

### Problems fixed

1. **`ExclusiveArch: noarch` caused a crash.**  The intersection of
   `{'noarch'}` with allowed architectures (real arch names) produced an empty
   set, and `random.choice([])` raised `IndexError`.

2. **No error on empty architecture set.**  Any filter combination that
   eliminated all architectures crashed with `IndexError` instead of a
   descriptive error.

3. **Non-noarch `BuildArch` values were ignored.**  `BuildArch: x86_64` did
   not restrict builds to that architecture.

4. **No dedicated noarch task.**  Noarch builds were mapped to a randomly
   chosen real-arch task, preventing the pipeline from treating noarch as a
   distinct build subtask.

## Decision

### `build-noarch` and `deps-noarch` as first-class architecture tasks

The script now emits `build-noarch` and `deps-noarch` in
`architecture_decision` alongside the existing `build-{arch}` / `deps-{arch}`
keys.  Both default to `linux/amd64` and are set to `localhost` (disabled) for
non-noarch packages.  For hermetic noarch builds, `deps-noarch` is set to the
same platform as `build-noarch` so that dependency resolution runs on the
matching architecture.

This matches Koji's model where `noarch` is a first-class entry in the
architecture list returned by `getArchList()`, not merely a property of how a
real-arch task is configured.

### Koji-matching noarch re-addition

Instead of stripping `noarch` from `ExclusiveArch`/`ExcludeArch` before
filtering (the previous approach), the script now directly implements Koji's
re-addition logic (kojid lines 1407-1409):

```python
if 'noarch' not in arches['excludearch'] and \
        ('noarch' in arches.get('buildarch', set()) or
         'noarch' in arches.get('exclusivearch', set())):
    build_architectures.add('noarch')
```

This means `noarch` is only present in the build set when the spec explicitly
requests it via `BuildArch` or `ExclusiveArch`, and it is blocked when
`ExcludeArch: noarch` is specified.

### `noarch` is NOT in the allowed architecture set

The `allowed_architectures` set (populated from CLI args) contains only real
architectures (`x86_64`, `i686`, `aarch64`, `ppc64le`, `s390`, `s390x`).
`noarch` enters the build set exclusively through the re-addition logic above.
This prevents noarch from surviving `ExclusiveArch`/`ExcludeArch` filters
meant for real architectures.

### Deterministic noarch platform selection

When `noarch` is in the selected architectures, the script picks a real
architecture platform to run the build on using a deterministic priority order:

```python
NOARCH_PLATFORM_PRIORITY = ["x86_64", "aarch64"]
```

The selection is **filter-aware**: it picks from real architectures that
survived `ExclusiveArch`/`ExcludeArch` filtering.  If no real arches remain
(e.g., `ExclusiveArch: noarch`), it falls back to all allowed architectures.
If no architecture in the priority list matches, the first available
architecture (sorted alphabetically) is used as a fallback, with a warning.

This replaces `random.choice()` for full determinism across pipeline runs.
Koji supports per-tag `extra.noarch_arches` to limit the noarch builder pool;
the priority list can be extended later if needed.

### BuildArch: noarch produces only the noarch task

When `BuildArch` is exactly `{'noarch'}`, `selected_architectures` is set to
`{'noarch'}` — all real-arch build tasks are disabled.  If noarch was blocked
by `ExcludeArch`, the script raises `SystemExit` with a clear error.

### Clear error on empty architecture set

After applying filters, if `build_architectures` is empty the script raises
`SystemExit` with a diagnostic message listing the filter values and allowed
architectures.  This matches Koji's `BuildError("No matching arches were
found")`.

### Non-noarch BuildArch restriction

When `BuildArch` contains real architecture names, the build is restricted to
the intersection of `BuildArch` and the remaining allowed architectures.  This
matches Koji's behavior where `BuildArch` replaces the architecture list.

### Platform override support

`--platform-labels` overrides propagate to `build-noarch` and `deps-noarch`
naturally: the noarch platform selection reads from the preferred
architecture's `build-{arch}` / `deps-{arch}` keys, which may already be
overridden.  `noarch` is intentionally NOT in the `apply_platform_overrides()`
arch map to avoid conflicts with the priority-based selection.

## Koji Comparison

Systematic trace of 12 scenarios against Koji's `getArchList()` (kojid:1379)
and `choose_taskarch()` (kojid:1425):

| # | Scenario | Koji result | select_architectures.py result | Match? |
|---|----------|-------------|--------------------------------|--------|
| 1 | `BuildArch: noarch`, no filters | noarch task, random builder | build-noarch on x86_64 (priority) | Yes* |
| 2 | `BuildArch: noarch` + `ExclusiveArch: x86_64 aarch64` | noarch on x86_64 or aarch64 | build-noarch on x86_64 (priority) | Yes* |
| 3 | `BuildArch: noarch` + `ExclusiveArch: noarch` | noarch on random tag arch | build-noarch on x86_64 (fallback) | Yes* |
| 4 | `BuildArch: noarch` + `ExclusiveArch: noarch x86_64` | noarch on x86_64 | build-noarch on x86_64 | Yes |
| 5 | `BuildArch: noarch` + `ExcludeArch: s390x` | noarch, not on s390x | build-noarch on x86_64 (priority) | Yes* |
| 6 | `BuildArch: noarch` + `ExclusiveArch: 4 arches` + `ExcludeArch: s390x` | noarch on 1 of 3 | build-noarch on x86_64 (priority) | Yes* |
| 7 | `ExclusiveArch: s390x` (no BuildArch) | builds only s390x | build-s390x only | Yes |
| 8 | `ExcludeArch: s390x` (no BuildArch) | builds 5 arches | 5 arch tasks active | Yes |
| 9 | `ExcludeArch` = all allowed arches | BuildError | SystemExit with message | Yes |
| 10 | `ExclusiveArch: noarch` (no BuildArch) | noarch on random tag arch | build-noarch on x86_64 (fallback) | Yes* |
| 11 | `BuildArch: x86_64` | builds only x86_64 | build-x86_64 only | Yes |
| 12 | No restrictions | builds all arches | all arch tasks active | Yes |

\* Koji uses `random.choice()` for noarch platform selection; we use
deterministic priority (`x86_64 > aarch64`, with alphabetical fallback).  The result is
functionally equivalent — both pick a valid real architecture from the
filtered set.

### Scenarios 3 and 10: now matching Koji

The previous version diverged on scenarios 3 and 10 by being "more
permissive" (building for all arches instead of erroring).  With the Koji
re-addition logic and `build-noarch` as a first-class task, both scenarios now
correctly produce a noarch-only build with platform selection falling back to
allowed architectures — matching Koji's behavior of running the noarch build
on a real architecture.

### Single remaining difference

Koji picks the noarch build host randomly (`random.choice()`); we use a
deterministic priority order.  This is intentional: pipeline runs should be
reproducible, and the choice of noarch build host does not affect build output.

## Consequences

- `build-noarch` and `deps-noarch` appear in `selected-architectures.json`
  for every spec, either as a real platform (noarch builds) or `localhost`
  (disabled).
- Noarch packages produce a single `build-noarch` task (with matching
  `deps-noarch` for hermetic builds) instead of being mapped onto a random
  real-arch task.
- The `noarch` platform selection is deterministic and respects
  `ExclusiveArch`/`ExcludeArch` constraints on which real architectures are
  available.
- `ExcludeArch: noarch` prevents noarch builds, matching Koji kojid line 1407.
- All 12 traced scenarios now match Koji's behavior (the previous intentional
  divergences on scenarios 3 and 10 are resolved).
- `import random` is removed — the script is fully deterministic.
- `check_noarch.py` remains relevant for specs where both arch-specific and
  noarch subpackages exist (e.g., `ExclusiveArch: x86_64 noarch`).
