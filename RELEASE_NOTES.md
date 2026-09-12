# Redflag 0.2.0

Redflag now checks the exact files selected for publication, including declared
private build values, bounded JSON/URL/Base64 representations and supported
gzip/ZIP/tar payloads. Clean artifact scans can produce an approval manifest that
verifies the same bytes immediately before upload or deployment.

Introduced-change scans use exact PR, push and merge-queue event ranges, including
credentials introduced and deleted before the final tree. Reports group versioned
occurrences, redact captures and support GitHub annotations/job summaries. Reviewed
exceptions bind exact occurrences, trusted policy and expiry; source debt cannot
authorize a new public-output leak.

The Action installs a verified native bundle instead of compiling Rust during each
invocation. Bundles include pinned offline Betterleaks 1.8.1, required license
notices and manifests, with GitHub build attestations tied to the release source
commit. Native targets include Apple Silicon, macOS Intel, Linux x86-64 and Windows
x86-64. Locally supplied bundles require a separately trusted SHA-256.

The Action defaults to legacy `scan` for compatibility. Select `mode: changes` for
event-aware source checks, `mode: artifacts` with explicit `paths` for publication,
and `mode: verify-artifacts` with `manifest` before publishing copied inputs.
Private-value checks run only in a trusted build that already has those values.

Legacy `scan --format json` remains an array. Modern source/artifact reports use
schema 3; publication manifests use schema 5 and require a fresh scan of older
manifests. Incomplete inspection exits 2, blocking occurrences exit 1, and complete
inspection without blockers exits 0. No online provider validation runs.

See ACTION.md, ARTIFACTS.md, CHANGES.md, DECODING.md, ARCHIVES.md, EXCEPTIONS.md,
REPORTING.md and RELEASES.md for exact scope, configuration and limits. Detection has the scope and limitations documented in those guides.
