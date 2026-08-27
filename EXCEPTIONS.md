# Reviewed source exceptions

Source exceptions identify exact versioned occurrences. They require a recorded
reason, reviewer and expiry; they never exempt a value, rule, path pattern or
logical group globally. Accepted occurrences remain in reports and in the audit
backlog. A new copy or a new detector-evidence identity still blocks.

First inspect the complete intended source scope:

```sh
redflag changes . --base BASE_SHA --head HEAD_SHA --format json > source-report.json
# Initial history review, with complete local Git history:
redflag changes . --new-branch --head HEAD_SHA --format json > source-audit.json
```

After reviewing the redacted evidence, create `redflag-exceptions.json`. Copy the
exact `logical_findings[].occurrences[].id` for each accepted occurrence. This
illustrative ID must be replaced; the example is not a valid exception record:

```json
{
  "schema_version": 1,
  "mode": "changes",
  "exceptions": [
    {
      "occurrence_id": "rf-occurrence-v1:<64 lowercase hexadecimal characters>",
      "kind": "accepted_debt",
      "reason": "Tracked in security review 123; removal and rotation are assigned",
      "reviewed_by": "security-maintainers",
      "expires_at": "2026-10-01T00:00:00Z"
    }
  ]
}
```

`kind` is `accepted_debt` or `false_positive`. `reason` is 1–1024 UTF-8 bytes after
rejecting blank content, and `reviewed_by` is 1–256 bytes. `expires_at` is a complete
RFC 3339 timestamp with a timezone. Expiry is exclusive: at the expiry instant,
the occurrence blocks again if it is in the selected inspection scope. Expired
records remain visible; unmatched records never suppress anything and are counted
in the policy audit. The file is limited to 1 MiB and 10,000 entries; duplicate IDs,
unknown fields, broad selectors, unsupported versions and malformed fields fail.

Keep the redacted report with the policy review so reviewers can inspect each
location, commit and detector record. The `reviewed_by` label is attribution, not
authentication. Approval comes from the trusted revision/file selected by the
workflow and its normal review controls. Reasons and reviewer labels are public
report metadata; use nonsensitive descriptions rather than credential values.

## Trusted selection

By default, `changes` loads root `redflag-exceptions.json` from the selected base
commit. `--policy-ref REVISION` selects another explicitly trusted revision for
both root configuration and source exceptions. Proposed head/merge policy files
and working-tree files do not authorize the current range. Missing policy files
mean no exceptions; invalid or unreadable trusted policy fails the scan.

```sh
# Use independently reviewed history policy for a full initial audit:
redflag changes . --new-branch --head HEAD_SHA --policy-ref REVIEWED_POLICY_SHA
# An external file must come from a trusted workflow-controlled location:
redflag changes . --base BASE_SHA --head HEAD_SHA --exceptions /trusted/review.json
# Disable all occurrence exceptions for this source inspection:
redflag changes . --base BASE_SHA --head HEAD_SHA --no-exceptions
```

`--exceptions FILE` overrides repository exception selection. `--no-exceptions`
conflicts with that option. `--no-config` disables configuration loading separately;
it does not disable a trusted source exception file. Without a base or explicit
policy revision/file, new-branch inspection applies no exceptions. PR, push and
merge-queue event scopes use their resolved base under the same rules, without API
access or GitHub tokens. Do not point an explicit override at unreviewed PR content.

A reviewed baseline can contain several individual accepted-debt records, with
reasons and expiry for each. It does not replace source comparison: unchanged debt
in parent snapshots remains nonblocking in unrelated changes, as documented in
CHANGES.md. Expiry affects occurrences selected by the current scan; run a full
history audit when reviewing the historical backlog. Absence, acceptance or removal
does not establish revocation.

## Reporting and publication boundary

Modern JSON schema 3 retains all observations and logical occurrences. Gate on
`blocking_occurrences_count` or the exit code, never total `findings_count`:

- Exit 0: complete inspection with no blocking occurrences; reviewed occurrences
  can still be present.
- Exit 1: one or more blocking occurrences, including matches with expired reviews.
- Exit 2: invalid policy, incomplete inspection or another operational failure.

Each occurrence has `status: "blocking"` or `"accepted"`, plus its matched review
when present. The policy audit records origin, exact-file SHA-256, evaluation time,
entry/match/unmatched/expired counts and accepted occurrences. Evidence identities
are unchanged by acceptance. Text and GitHub summaries retain accepted evidence and
review metadata. GitHub error annotations cover blockers, displayed before accepted
rows; accepted-only results emit a completion notice.

Source baselines never load in `artifacts`, even when the working directory contains
`redflag-exceptions.json`. The same provider value or declared private value in
publication inputs still blocks and prevents a clean manifest. Artifact-scoped
false-positive review is separate implementation work; the current source policy
file does not authorize publication exceptions. Legacy `scan` does not apply this
exception workflow.
