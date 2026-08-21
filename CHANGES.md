# Inspecting introduced commits

`changes` inspects committed additions in every commit reachable from head but
not from base. A secret introduced and deleted within the range still fails.
The working tree is not an input. All findings are redacted. Exit codes are
0 for complete and clean, 1 for findings, and 2 for an incomplete scan or invalid
configuration; failed JSON scans leave stdout empty.

```sh
redflag changes . --base origin/main --head HEAD --format json
redflag changes . --base BEFORE_SHA --head AFTER_SHA
redflag changes . --base BASE_SHA --head PR_HEAD_SHA --merge-result PR_MERGE_SHA
redflag changes . --new-branch --head AFTER_SHA
```

Use exact event SHAs in CI, or read the event directly:

```sh
redflag changes . --github-event "$GITHUB_EVENT_PATH" --format json
```

The event type comes from `GITHUB_EVENT_NAME` or explicit `--event-name
pull_request|push|merge_group`. Manual base/head/new-branch/merge options cannot
be combined with an event. The event payload is bounded to 25 MiB, and its digest
and resolved scope are included in coverage. Only full commit SHAs are accepted;
ref names and the checkout's `HEAD`/`GITHUB_SHA` do not substitute for event scope.

- Open PRs use `pull_request.base.sha`, `head.sha`, and `merge_commit_sha`. The
  synthetic merge must be available and must have those exact parents. Null,
  missing or stale merge results fail. Fork PRs use the same local inspection;
  no GitHub token or private build values are required. Coverage identifies the
  PR number and whether the base/head repository IDs differ.
- Branch pushes use `before` and `after`. The payload's possibly truncated
  `commits` list is not used. A created branch requires an all-zero `before` and
  explicitly selects all reachable history. Deleted refs have no introduced
  range: skip the invocation for `push.deleted` events. Tag pushes require an
  explicit reviewed range instead of automatic source scope.
- Merge queues use `merge_group.base_sha` and `head_sha` on `checks_requested`.
  All introduced commits and the queue's merge resolution are inspected.

Fetch all required objects before scanning, including the PR head and synthetic
merge when applicable. Redflag does not fetch or substitute newer branch tips if
an event object is missing. Trigger required source checks for `pull_request` and
`merge_group: types: [checks_requested]`; use branch-filtered `push` triggers when
also checking pushes. The parser deliberately rejects `pull_request_target` and
unrelated events; they require an explicitly reviewed range and workflow design.
See GitHub's [event definitions](https://docs.github.com/en/webhooks/webhook-events-and-payloads)
and [workflow trigger documentation](https://docs.github.com/en/actions/reference/workflows-and-actions/events-that-trigger-workflows).

`--new-branch` explicitly inspects all reachable history, including
existing debt; choose a reviewed base explicitly when a different scope is intended.
Base need not be an ancestor of head: reachability subtraction also handles a
diverged branch or force push. Date filters and branch lists from legacy `[git]`
configuration do not narrow this required range.

The optional merge result must have the exact base and head among its parents.
It is inspected in addition to the introduced branch commits. Each ordinary merge
is compared with every parent. Required evidence must include an addition relative
to every parent to count as a new finding in that merge. This prevents imported
base debt from being reported again while retaining a multipart credential
assembled from different parents. The detector records required component spans
and keeps the same path/location in different commits distinct.

## Trusted policy

The default policy is root `redflag.toml` from the base commit, merged with built-in
defaults. A proposed policy in head or the checkout cannot exclude its own changes.
If that file is absent, built-in defaults apply. A new branch without a base also
uses defaults. `--policy-ref REVISION` explicitly chooses a trusted policy commit;
`--config PATH` explicitly chooses an external trusted file; `--no-config` uses
defaults. The workflow calling these options is responsible for selecting trusted
revisions and files. Do not point these overrides at unreviewed PR content.

Trusted `Ignore` exclusions prune files before blob/patch inspection. Every other
selected regular blob is eligible, regardless of extension, hidden filename, or
Git's binary classification. `ScanButWarn` findings block in this mode. Source
comment directives and Betterleaks allow comments cannot authorize exceptions.
Selected symlinks, submodules and unsupported Git entries fail explicitly; no
filesystem target is followed. Deleted paths and trusted exclusions appear in
coverage. Selected binary bytes are inspected by the pinned engine.

## Limits and reporting

The default detector is pinned offline Betterleaks; install it as described in
[engines/README.md](engines/README.md). `--engine native` selects the compatibility
detector. Custom TOML patterns remain native. Legacy `scan` retains its original
source policy and JSON array format.

Version 1 `changes` JSON contains completion status, findings and coverage: exact
base/head/merge IDs, every introduced commit, policy origin and digest, engine
provenance, inspected file revisions and blob IDs, added-line intervals for each
parent, skipped paths/reasons and applied limits. Finding evidence uses 1-based
line numbers and inclusive byte columns; an end column of zero denotes the
preceding newline. Reports never contain matched values or source snippets.

Shallow repositories, missing required commits/trees/blobs and unresolved revisions
fail. `--max-commits` defaults to `[git].max_depth` and limits the complete introduced
range, including an extra merge result. Exact limits pass; exceeding one fails
instead of truncating. `limits.max_files` counts considered file revisions, including
skips. File/line size limits apply; `limits.max_total_bytes` bounds the sum of
inspected new snapshots and parent bytes read for comparisons. Detector time and
output limits also apply. Raise limits explicitly for larger reviewed scopes.
