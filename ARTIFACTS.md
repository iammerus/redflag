# Inspect files before publication

```sh
redflag artifacts dist --private-env INTERNAL_API_KEY --format json
```

Select the exact files or directories the upload or deploy step will consume.
Repeat `--private-env NAME` for each private value already available to the trusted
build. Redflag reads only those named variables; never pass secret values as CLI
arguments or give an untrusted PR access to build secrets for this check.

Exit codes are **0** for complete inspection without blockers, **1** for blocking occurrences,
and **2** for an operational failure or incomplete inspection. Check the exit code
before uploading. Inspection and report-preparation errors leave both text and
JSON stdout empty; output I/O can still interrupt final delivery. Always check
the exit code.

Artifact scans use pinned Betterleaks 1.8.1 for general credentials, Redflag's
native matcher for declared private values, and existing custom TOML rules plus
the `.netrc` format check. Install the engine beside the Redflag executable:

```sh
python3 scripts/install_engine.py --directory target/release/engines
```

Alternatively, supply `--betterleaks-path PATH` or `REDFLAG_BETTERLEAKS_PATH`.
Redflag checks the executable's pinned SHA-256 before running it. A missing or
modified engine fails with exit 2; scanning never downloads or updates an engine.
`--engine native` selects the legacy general detector explicitly. The existing
`scan` command retains its native rules and JSON array contract.

Artifact selection includes hidden files, HTML, unknown extensions and files under
directories normally excluded from source scans. Source exclusions, allow rules
and inline suppression directives do not apply. Symlinks (including broken links)
and special files are rejected. Target roots are resolved to absolute paths;
overlapping targets are rejected. Missing, unreadable and zero-byte targets fail.
An empty file within a nonempty directory is still inspected and inventoried.

Artifact policy discovery starts at the current workflow directory and searches
for the nearest `redflag.toml` up to the Git repository root (or filesystem root
outside Git). It does not search inside selected output directories. Use
`--config FILE` for an explicit trusted policy or `--no-config` for defaults.
`redflag show-config .` displays the effective policy for that workflow directory.

Private values are matched case-sensitively against original bytes, including
invalid UTF-8, NULs, multiline values, overlaps and read-buffer boundaries. Missing,
empty or non-Unicode environment values fail. Values shorter than eight bytes
require `--allow-short-private-value NAME` for that declared variable. A scan can
declare up to 256 values, each at most 65,536 bytes. Unnamed environment variables
are never inspected. Every artifact finding has a fully redacted snippet, including
native findings next to opaque private values.

The general engine receives private temporary snapshots with a leading newline
and neutral filenames, so upstream filename and binary-type skips cannot silently
reduce coverage. Recognized code files retain a code extension class for generic
source-expression filtering; other files retain unquoted configuration matching.
The exact generic-password markers `YOUR_PASSWORD_HERE` and `your_password_here`
are classified as instructional placeholders. Declared private values still block
when they equal those markers. See [engines/README.md](engines/README.md) for the
bounded normalization policy and adapter digest.
Snapshots use 64 KiB windows with 32 KiB overlap; original line
locations are restored and overlap duplicates are removed. Candidates touching a
window edge are checked with adjacent context; unusually long candidates that
cannot be inspected completely fail operationally. Native custom rules inspect
each original line through a UTF-8 projection with invalid sequences replaced.
Exact private-value matching always sees original raw bytes without these windows.

Live validation, upstream decoding and archive traversal are disabled explicitly.
The child environment is cleared except for fixed runtime limits and Windows OS
locations needed on Windows. Source engine config files, ignore files and inline
allow comments cannot change the pinned policy. A clean engine exit is accepted
only when its inspected-byte counter matches every staged byte and it has no
unexpected warning or error. Engine logs and secret captures are never forwarded.
Decoding and archive inspection remain separate modernization work; transformed
or compressed inner content is not yet certified as inspected.

Artifact JSON uses a version 3 envelope with mode, completion status, scanner
version, grouped logical findings, occurrence IDs, remediation, the original flat
findings and separate observation/group/occurrence counts. See
[REPORTING.md](REPORTING.md) for the schema and identity contract.
Version 3 distinguishes blocking and accepted occurrences. Source baselines never
apply to artifact scans. An explicit `--exceptions FILE` can accept separately
reviewed artifact false positives with exact IDs, reasons, reviewers and expiry;
declared private values always block. There is no artifact exception discovery.
See [EXCEPTIONS.md](EXCEPTIONS.md) for the review and trust contract.
Coverage includes resolved targets,
every selected file's relative path, size and SHA-256, selected private variable
names, resource limits, representations, engine version and executable/config
digests. It contains no private values. The
adapter digest identifies the embedded report and normalization policy. The
existing `scan --format json` array remains compatible.

In GitHub Actions, `--format github` emits general error annotations and appends a
bounded job summary with artifact locations, identities, coverage and remediation.
Place `GITHUB_STEP_SUMMARY` (or `--github-summary FILE`) outside publication inputs
and separate from the manifest and active configuration/exception files. Generated artifacts are not mapped to source-file
lines. See [REPORTING.md](REPORTING.md) for limits and the complete output contract.

Default limits in `[limits]` are 100,000 files, 64 MiB per file, 16 MiB per line,
and 1 GiB of total artifact bytes (`max_files`, `max_file_bytes`, `max_line_bytes`,
`max_total_bytes`). Exceeding a limit is an error, never a silent skip. Override
limits with `--config policy.toml` after reviewing the expected build size.
Artifact inspection holds one bounded file in memory and spools redacted findings
to a private temporary file, retaining bounded location/ID indexes for grouping.
Reports accept at most `limits.max_findings` observations (100,000 by default) and
64 MiB of private input records; budget overruns fail before output.
Engine snapshots require up to roughly twice the selected
input bytes in temporary storage, plus per-file overhead. The engine has a default
120-second subprocess timeout (`limits.engine_timeout_seconds`), a 64 MiB report
limit and a 4 MiB log limit; exceeding any budget fails the scan. Its Go runtime
uses a 256 MiB soft memory target and two execution threads. Content digests describe exactly the bytes inspected;
they do not establish that a later publish step used the same bytes.

## Verify the bytes that will be uploaded

```sh
redflag artifacts dist --private-env INTERNAL_API_KEY --manifest scan-manifest.json
redflag verify-artifacts scan-manifest.json
# Publish dist only if both commands succeed, without rebuilding it in between.
```

Store the manifest outside every selected artifact target and separate from active
configuration and exception inputs. It is written atomically only after a complete
scan and report classification without blockers. Requesting the same manifest for a
rescan invalidates the old file before configuration or input validation, so a
failed rescan cannot leave the previous approved result available. Artifact scans
recheck inventory and hashes before reporting completion to catch changes during
inspection.

If publication consumes a copied directory, verify that directory explicitly:

```sh
redflag verify-artifacts scan-manifest.json --target upload-directory
```

Repeat `--target` in the original selection order for multiple targets. Verification
requires the same relative file inventory and SHA-256 for every file, including
empty files. Added, removed, changed or retyped files fail with exit 2. Metadata
changes such as timestamps do not affect byte identity. The manifest records
scanner/engine versions, the effective configuration digest and declared variable
names; verification does not need the private environment values again.
Manifests use schema version 3 and include the pinned detector identity, policy
audit and exact accepted artifact reviews. Verification validates review expiry
before and after inventory verification. Earlier manifest schemas require a rescan.
Verification reports accepted occurrence counts, including reviewed false positives.

Keep the manifest in a trusted workflow workspace: it is an integrity record,
not a signed attestation, and an edited manifest cannot prove a scan happened.
Verification describes inputs at verification time. Run it immediately before
publication and prevent concurrent rebuilds or mutations; a standalone command
cannot control what a subsequent uploader chooses to read. Only the representations
listed in the manifest were inspected. This does not imply arbitrary compression
or encoding was decoded.
