# Use Redflag in GitHub Actions

The `v0.2.0` Action is prepared in this checkout and must be published before its
release-download examples can run. Published `v0.1.1` still uses the older Action.
See [RELEASES.md](RELEASES.md) for publication status and verification requirements.

The new Action installs a versioned native bundle containing Redflag and pinned
Betterleaks. It verifies the checksum, GitHub build provenance, exact source commit,
platform, engine pin and package inventory before execution. It never compiles Rust
during a scan. GitHub-hosted macOS/Linux/Windows runners provide the required Python
3 and GitHub CLI; self-hosted runners need those tools and a supported architecture.

Pin the Action to the full commit SHA of its published release for a fixed source
identity. A matching `v0.2.0` tag also works and resolves its source commit through
GitHub. Other branch names and unreleased commits do not silently select another
binary. Download or provenance failures stop the job.

## Inspect introduced source changes

```yaml
name: Credential check
on:
  pull_request:
  merge_group:
  push:
    branches: ['**']
permissions:
  contents: read
jobs:
  credentials:
    if: github.event_name != 'push' || !github.event.deleted
    runs-on: ubuntu-24.04
    steps:
      - uses: actions/checkout@d23441a48e516b6c34aea4fa41551a30e30af803 # v6
        with:
          fetch-depth: 0
          persist-credentials: false
      - uses: iammerus/redflag@v0.2.0 # Prefer this release's full commit SHA
        with:
          mode: changes
```

The exact event file selects PR, push or merge-queue ranges. Full history is
required. This workflow excludes tag pushes and deleted branches, which have no
supported introduced-source scope. Added-then-deleted credentials and newly introduced occurrences remain
blocking; unrelated source debt does not become a new finding. Configuration and
reviewed exceptions come from the trusted base by default. New branches require
the explicit trust selection described in [CHANGES.md](CHANGES.md).

Source checks work with fork PRs and a read-only token. They require no build
secrets. This check should run separately from any trusted build that has private
values. Unsupported events or missing required Git objects fail operationally.

Use `base` and optional `head` for an explicit range, or `new-branch: "true"` when
no base exists. These choices replace event selection. `merge-result` requires an
explicit base; `policy-ref` selects a trusted policy revision. An explicit `config`
must itself come from a trusted location.

## Inspect the files about to be published

Run this in the trusted build that already has the declared variables. Select the
exact publication inputs, before the first upload or deployment:

```yaml
- uses: iammerus/redflag@v0.2.0
  env:
    INTERNAL_API_KEY: ${{ secrets.INTERNAL_API_KEY }}
  with:
    mode: artifacts
    paths: |
      dist
    private-env: |
      INTERNAL_API_KEY
    manifest: ${{ runner.temp }}/redflag-publication.json

# If the uploader consumes a copied directory, verify that exact copy.
- uses: iammerus/redflag@v0.2.0
  with:
    mode: verify-artifacts
    manifest: ${{ runner.temp }}/redflag-publication.json
    paths: |
      upload-directory
```

The copy/build step must create `upload-directory` before verification. Publish
only after success, without rebuilding or mutating those inputs. Omit `paths` in
verification mode to recheck the original locations. Private values are not needed
again for verification. Keep manifests outside every publication target.

Artifact `paths` are required and contain one literal path per line; there is no
shell expansion or globbing. Source `path` is a separate input. Private inputs are
environment variable names, never secret values. Missing variables/targets, empty
targets and incomplete archive/decoding coverage fail. Do not grant an untrusted
PR build secrets for the purpose of scanning it. See [ARTIFACTS.md](ARTIFACTS.md).

## Inputs and compatibility

| Input | Scope and default |
| --- | --- |
| `mode` | `scan` by default for legacy compatibility; also `changes`, `artifacts`, `verify-artifacts`. |
| `path` | Source path for `scan`/`changes`; default `.`. |
| `paths` | Literal publication targets, one per line; required for `artifacts`, optional replacement roots for verification. |
| `config`, `no-config` | Explicit trusted policy or built-in defaults; mutually exclusive. Verification uses the manifest's captured policy. |
| `git-history` | `false` by default; applies only to legacy `scan`. |
| `format` | `github` for changes/artifacts, `text` otherwise. All modes accept `json`; legacy scan also accepts `json-report`. |
| `engine` | `betterleaks` for changes/artifacts, with optional `native`. Legacy scan always uses its native detector. |
| `base`, `head`, `new-branch`, `merge-result` | Explicit source selection; absent by default so `changes` uses the GitHub event. |
| `policy-ref`, `max-commits` | Trusted source policy and introduced-range limit. |
| `exceptions` | Explicit reviewed source/artifact policy; artifact mode never inherits source debt. |
| `private-env`, `allow-short-private-value` | Declared names, one per line, for artifact private matching and explicit short-value overrides. |
| `manifest` | Artifact approval output or required verification input. |
| `github-summary` | Optional summary destination instead of `GITHUB_STEP_SUMMARY`; keep outside publication/configuration inputs. |
| `bundle`, `bundle-sha256` | Optional locally supplied bundle and separately trusted digest; both must be present. |

Booleans accept `true` or `false`. Inputs that do not apply to the selected mode
fail before download instead of being silently ignored. The original `path`,
`config` and `git-history` inputs retain their meaning with default `mode: scan`.
Legacy JSON remains an array; modern reports and publication manifests retain
their documented independent schemas.

The Action forwards scanner stdout and preserves exit 0/1/2. Installation failures,
unexpected process failures and invalid inputs exit 2. It does not post comments,
require a hosted account, or send source/private values to a classification service.
The download token is restricted to GitHub API/provenance verification and removed
before scanner execution. The provenance verifier receives only selected OS/runtime
settings and that download token. Betterleaks retains its documented isolated
environment; application build values are not forwarded to it.

## Supplied bundles and local Action tests

A trusted workflow can provide `bundle` and `bundle-sha256`, including for offline
installation or testing `uses: ./` before a release exists. The supplied digest
authorizes those exact bytes; all package/platform/engine checks still run. This
route permits clearly marked development bundles and does not claim GitHub build
attestation. Do not obtain both the bundle and expected digest from an untrusted
PR build. There is no switch to skip integrity checks.

`scripts/test_action.py` checks routing and download gates without remote execution.
`scripts/test_action_integration.py` uses `REDFLAG_TEST_BUNDLE` and
`REDFLAG_TEST_SHA256` to run the actual entry point against clean/private/missing
artifacts, manifest verification, legacy scans, and manual/event introduced ranges.
