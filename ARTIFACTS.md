# Inspect files before publication

```sh
redflag artifacts dist --private-env INTERNAL_API_KEY --format json
```

Select the exact files or directories the upload or deploy step will consume.
Repeat `--private-env NAME` for each private value already available to the trusted
build. Redflag reads only those named variables; never pass secret values as CLI
arguments or give an untrusted PR access to build secrets for this check.

Exit codes are **0** for complete inspection without findings, **1** for findings,
and **2** for an operational failure or incomplete inspection. Check the exit code
before uploading. An error leaves JSON stdout empty. Text output can show findings
before a later failure, so text output alone is not a completion signal.

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

The current native detector also inspects each line through a UTF-8 projection
that replaces invalid sequences. It does not interpret arbitrary binary formats.
The report distinguishes this representation from exact raw-byte matching.
Decoding and archive inspection are separate modernization work; this version
does not certify transformed or compressed contents as inspected.

Artifact JSON uses a version 1 envelope with mode, completion status, scanner
version, findings count, coverage and findings. Coverage includes resolved targets,
every selected file's relative path, size and SHA-256, selected private variable
names, resource limits and representations. It contains no private values. The
existing `scan --format json` array remains compatible.

Default limits in `[limits]` are 100,000 files, 64 MiB per file, 16 MiB per line,
and 1 GiB of total artifact bytes (`max_files`, `max_file_bytes`, `max_line_bytes`,
`max_total_bytes`). Exceeding a limit is an error, never a silent skip. Override
limits with `--config policy.toml` after reviewing the expected build size.
Artifact inspection holds one bounded file in memory and spools JSON findings to
a private temporary file. Content digests describe exactly the bytes inspected;
they do not establish that a later publish step used the same bytes.

## Verify the bytes that will be uploaded

```sh
redflag artifacts dist --private-env INTERNAL_API_KEY --manifest scan-manifest.json
redflag verify-artifacts scan-manifest.json
# Publish dist only if both commands succeed, without rebuilding it in between.
```

Store the manifest outside every selected artifact target. It is written atomically
only after a complete scan without findings. Requesting the same manifest for a
rescan invalidates the old file before configuration or input validation, so a
failed rescan cannot leave the previous clean result available. Artifact scans
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

Keep the manifest in a trusted workflow workspace: it is an integrity record,
not a signed attestation, and an edited manifest cannot prove a scan happened.
Verification describes inputs at verification time. Run it immediately before
publication and prevent concurrent rebuilds or mutations; a standalone command
cannot control what a subsequent uploader chooses to read. Only the representations
listed in the manifest were inspected. This does not imply arbitrary compression
or encoding was decoded.
