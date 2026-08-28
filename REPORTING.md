# Findings and occurrence identities

`changes --format json` and `artifacts --format json` emit schema version 3.
The envelope retains `mode`, `complete`, `scanner_version`, `coverage`,
`findings_count` and the original flat `findings` observations. It adds
`logical_findings`, `logical_findings_count`, `occurrences_count` and
`identity_schema: "redflag-occurrence-v1"`. Counts of detector observations,
logical findings and occurrences have different meanings.

Schema 3 adds occurrence dispositions and reviewed policy provenance. It retains
the schema 2 observation/group structure and the same identity algorithm. Use
`blocking_occurrences_count` for the gate; `accepted_occurrences_count` identifies
reviewed exceptions. `findings_count` remains the total detector observation count,
including accepted evidence. Every occurrence has `status` (`blocking` or
`accepted`) and, when matched, an `exception` with review status, kind, reason,
reviewer and expiry. Groups also include `blocking_occurrence_count`. See
[EXCEPTIONS.md](EXCEPTIONS.md) for trust selection and expiry behavior.

Matched review status is `accepted`, `expired` or `rejected_private_value`.
Declared private values cannot be accepted in artifact mode. Artifact false-positive
reviews require an explicit artifact policy; source policy never authorizes them.

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
IDs identify exact reviewed occurrences; the separately selected trusted exception
policy determines whether a review applies. New occurrences require their own
review records, and source policy does not authorize artifact publication.

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
always require exit 0 before publication. Exit 1 means blocking occurrences and exit 2 means
an operational failure. Text escapes control characters in displayed paths and
rule names and includes occurrence IDs and remediation without source snippets.

Input records spool into a private anonymous file capped at 64 MiB; records are
bounded by `limits.max_findings` (100,000 by default). Grouping keeps location/ID
indexes in memory and reads each occurrence's evidence from the spool. It does not
load every complete finding into memory. Exceeding either budget fails explicitly.
No approved artifact manifest survives a failed requested rescan or report finalization.

Legacy `scan --format json` continues to emit its original array. `verify-artifacts`
and `show-config` retain their own version 1 envelopes; publication manifests retain
their independent version 3 contract.

## GitHub annotations and job summaries

```sh
redflag changes . --github-event "$GITHUB_EVENT_PATH" --format github
redflag artifacts dist --private-env INTERNAL_API_KEY --format github
# Local rendering or an explicit summary destination:
redflag changes . --base BASE_SHA --head HEAD_SHA \
  --format github --github-summary summary.md
```

GitHub format writes workflow annotations to stdout and appends a Markdown summary
to `GITHUB_STEP_SUMMARY`, or to the explicit `--github-summary FILE`. The destination
is required. Other formats reject `--github-summary`. Existing summary content is
preserved. Parent directories must already exist. This uses GitHub's documented
[workflow commands and summary file](https://docs.github.com/en/actions/reference/workflows-and-actions/workflow-commands),
with [toolkit-compatible command escaping](https://github.com/actions/toolkit/blob/main/packages/core/src/command.ts).
No API calls, tokens or PR comments are involved. The scanner's ordinary exit codes
remain authoritative; every unaccepted occurrence blocks, regardless of severity.
Accepted reviews stay in the summary without error annotations.

The summary includes completion status, observation/group/occurrence counts,
selected source scope or artifact roots, detector information, occurrence IDs,
locations, rules and remediation. It emits at most 10 occurrence annotations and
shows at most 100 occurrence rows, also bounded to roughly 512 KiB of new content.
Long display fields are shortened. Every omission is identified with the total
occurrence count; inspection still includes the entire selected scope. Use
`--format json` when a complete machine-readable report is needed. Existing step
content plus the new summary must fit GitHub's 1 MiB limit; otherwise rendering
fails with exit 2 before annotations are emitted.

Source links use each occurrence's recorded commit with URL-encoded paths.
`GITHUB_REPOSITORY` supplies `owner/repo`; `GITHUB_SERVER_URL` defaults to
`https://github.com` and supports HTTPS enterprise hosts. Missing or invalid link
metadata produces plain locations. File annotations additionally require:

- `GITHUB_SHA` resolves to a locally available commit with the same blob at the
  reported path as the occurrence's recorded commit.
- The current regular file's bytes still match that blob, within the 64 MiB
  annotation verification bound.
- The repository root equals `GITHUB_WORKSPACE` (default: repository root), the
  file remains inside it, and its path contains no control characters. Nested
  checkouts retain general annotations because no repository-path mapping has
  been established.

These checks also allow an unchanged blob from an earlier introduced commit to
be annotated at the checked revision. Deleted exposures, changed files, dirty
checkouts and unavailable annotation context keep general annotations and their
original commit locations. Artifact occurrences use general annotations: generated
output has no established source-file mapping. File annotations specify lines;
byte columns remain in JSON to avoid confusing editor character offsets.

Summary text escapes Markdown/HTML metacharacters, workflow properties escape
command delimiters, and terminal error messages escape control characters.
No credential captures or private grouping digests enter annotations or summaries.
Summary destinations must be regular files outside publication inputs and distinct
from the requested manifest and active configuration/exception files. Symlinks and special files are rejected; Unix also
rejects shared hard links. Scan failures leave prior summary content unchanged.
Summary/output errors fail the step and invalidate a requested approved manifest.

The CLI formatter is covered by offline fixtures, including token-free source
events and historical locations. Verified prebuilt Action packaging and hosted
workflow acceptance remain separate modernization items.
