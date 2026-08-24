# Findings and occurrence identities

`changes --format json` and `artifacts --format json` emit schema version 2.
The envelope retains `mode`, `complete`, `scanner_version`, `coverage`,
`findings_count` and the original flat `findings` observations. It adds
`logical_findings`, `logical_findings_count`, `occurrences_count` and
`identity_schema: "redflag-occurrence-v1"`. Counts of detector observations,
logical findings and occurrences have different meanings.

A logical finding groups equal captured values across locations. Each group
contains its ID, title, maximum severity, rule IDs and severities, declared private
variable names, remediation and occurrences. Multipart credentials group only
when every required component value and role agrees. A shared access-key ID with
different required secret keys produces separate groups.

Each occurrence contains an ID, location, primary region and detector evidence.
Evidence retains the rule ID, description, severity and every required span.
Equal or nested primary regions for the same value at the same location combine
detector observations; the narrower region anchors the occurrence. Partially
overlapping repetitions stay separate. The primary region is a detector location,
not necessarily the exact secret capture: some rules include assignment context.
All original detector spans remain available in evidence and in flat findings.

Locations contain a relative `path` and a `version`. Source locations also have
`commit`, equal to the full commit ID in `version`. Artifact locations have a
zero-based `target` index into `coverage.targets`, with the whole-file SHA-256 in
`version`. A target that is a single file uses `path: "."`. Paths use `/` as the
component separator; a literal backslash in a Unix filename remains a backslash.
Non-UTF-8 or escaping paths fail instead of acquiring ambiguous identities.

Spans use one-based lines and byte columns, with inclusive ends. A multiline span
ending immediately after a newline has `end_column: 0` on the following line.
Columns refer to original bytes, including invalid UTF-8. Editor character columns
may differ. Source evidence points at the recorded commit, which may differ from
the final checkout when a credential was subsequently removed.

## Stability and privacy

IDs identify versioned evidence, not globally persistent credentials:

- `rf-evidence-v1:` hashes a canonical JSON array of mode, location, rule ID and
  sorted distinct evidence spans.
- `rf-occurrence-v1:` hashes the sorted distinct evidence IDs in an occurrence.
- `rf-group-v1:` hashes the sorted occurrence IDs in a logical finding.

The hash algorithm is SHA-256; IDs append its lowercase hexadecimal digest.
Canonical location fields are serialized in `target`, `path`, `version`, `commit`
order, omitting absent optional fields. Span fields are `start_line`, `end_line`,
`start_column`, `end_column`; spans sort in that field order. JSON is compact UTF-8.

Repeated scans of the same inputs retain IDs. Moving an artifact root while
retaining relative paths, file bytes and target order also retains IDs. Adding an
occurrence in another file gives it a new ID and changes group membership/ID;
the unchanged occurrence keeps its ID. Changing a file version, source commit,
rule or evidence changes the corresponding IDs. A source identity cannot serve
as an artifact identity. Descriptions and severity do not define evidence identity.
IDs are suitable for identifying an exact reviewed occurrence; they do not yet
authorize exceptions. The reviewed-exception workflow is separate modernization work.

Private SHA-256 capture digests are used only inside the engine adapter and private
temporary spools to group observations. They are never exported as credential
fingerprints or public IDs. Raw captures and snippets never enter the public report;
flat snippets are always `[REDACTED]`. Coverage still intentionally includes hashes
of whole inspected files. Reports also contain paths, rule names and declared
variable names, so treat them as workflow metadata with appropriate access controls.

## Completion and resource limits

Both modern text and JSON output wait for completed inspection and report
preparation. A scan or validation failure leaves stdout empty. Output-device or
temporary-file I/O failure during final rendering can still interrupt delivery;
always require exit 0 before publication. Exit 1 means findings and exit 2 means
an operational failure. Text escapes control characters in displayed paths and
rule names and includes occurrence IDs and remediation without source snippets.

Input records spool into a private anonymous file capped at 64 MiB; records are
bounded by `limits.max_findings` (100,000 by default). Grouping keeps location/ID
indexes in memory and reads each occurrence's evidence from the spool. It does not
load every complete finding into memory. Exceeding either budget fails explicitly.
No clean artifact manifest survives a failed requested rescan or report finalization.

Legacy `scan --format json` continues to emit its original array. `verify-artifacts`
and `show-config` retain their own version 1 envelopes; publication manifests retain
their independent version 2 contract. GitHub annotations and job summaries remain
separate implementation work.
