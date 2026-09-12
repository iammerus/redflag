# Encoded private values in publication inputs

`artifacts --private-env NAME` matches each declared private value in original
file bytes and supported decoded candidates. This applies with both general
engines. It finds a value encoded together with a username, binary prefix or
suffix; it does not depend on the encoding of the value alone.

Only declared private values use this decoder. Betterleaks and native custom
rules inspect the original file representations described in [ARTIFACTS.md](ARTIFACTS.md).
Source `changes` and legacy `scan` do not use candidate decoding. Supported archive
members also receive this matching; see [ARCHIVES.md](ARCHIVES.md). A complete scan certifies this stated scope;
it does not certify arbitrary transformations, encryption or fragmented values.

## Candidate grammar

Each representation is searched independently for all four candidate kinds:

| Kind | Inspected candidates |
| --- | --- |
| `json_string` | Complete double-quoted strings containing a backslash and valid JSON string syntax, including Unicode escapes and surrogate pairs. The surrounding file need not be valid JSON. |
| `url_percent` | Segments separated by ASCII whitespace, NUL, quotes, backticks or angle brackets. Valid `%HH` pairs decode case-insensitively; invalid pairs remain literal. Punctuation such as `:`, `/`, `?`, `&` and `=` stays within a segment. |
| `url_form` | The same segments with `+` decoded as a space as well as percent pairs. Only segments containing `+` receive this additional interpretation. |
| `base64` | Maximal contiguous standard or URL-safe alphabet runs, including their trailing padding. Padded and unpadded canonical encodings are supported. Mixed alphabets, invalid padding and nonzero trailing bits are rejected. |

Decoded bytes are searched and recursively considered as new candidates. Separate
segments are never concatenated. Malformed JSON and Base64 candidates are not
interpreted; they still receive the original raw scan. URL candidates that produce
no change receive no derived scan. Candidate boundaries are syntactic: a Base64
substring embedded in a larger alphabet run is not separately guessed. MIME
line-wrapped Base64 and JavaScript-specific string escapes are outside this grammar.

Candidates too short to contain the shortest declared private value are pruned.
Every supported transform preserves or reduces byte length, so further decoding
cannot make those candidates contain a value. The explicit short-value override
also lowers this eligibility threshold; overlaps remain visible.

## Provenance and privacy

Flat findings and logical occurrence locations add `representation` only for
derived matches. It is a root-first array of steps with `kind`, `encoded` and
`decoded` spans. `encoded` identifies the complete candidate in that step's input;
`decoded` identifies the supporting region in that candidate's output. A nested
step's input coordinates refer to the preceding candidate's decoded bytes.
Spans use one-based lines and byte columns, as in [REPORTING.md](REPORTING.md).

The finding's primary/evidence region maps back to the original file. Base64
mapping includes the four-character quanta necessary to reconstruct a match;
the innermost decoded span distinguishes different matches within the same
quantum. A private value in an unchanged part of a decoded candidate is reported
once by the original raw scan. Text and GitHub summaries show the transform chain
and innermost location. Decoded contents and private capture digests are never
included in public output or passed to the general engine. Decoded bytes stay in
memory; temporary reports contain only redacted findings and private grouping data.
Reviewed exceptions cannot accept a decoded private-value occurrence.

## Limits and coverage

All limits are configurable under `[limits]` and must be positive:

| Setting | Default | Scope |
| --- | ---: | --- |
| `max_decode_depth` | 4 | Transformations along one chain; allowed range 1–16. |
| `max_decode_candidates` | 1,000,000 | Eligible decode attempts across every selected file and layer, including malformed candidates. |
| `max_decoded_bytes` | 1 GiB | Total bytes produced across every successful candidate, including pruned results. |
| `max_decode_work_bytes` | 8 GiB | Each representation's length charged once per candidate kind, plus each eligible candidate's input length. This is work accounting, not a count of physical reads. |
| `max_decode_map_runs` | 262,144 | Mapping runs within one candidate; adjacent runs with the same byte ratio coalesce. |

Input file and report limits also apply. Candidates are processed sequentially;
only the current nested chain retains decoded buffers and coordinate maps. If a
limit prevents inspection, the scan exits 2 before report delivery and invalidates
a requested approval manifest. A valid deeper candidate that could contain a
private value fails the depth limit even if it would ultimately be clean.

Artifact coverage and schema 5 manifests include a `private_decoding` receipt with
its own `schema_version: 1`, `enabled`, ordered `formats`, `candidates`,
`decoded_bytes`, `work_bytes` and `max_depth_reached`. Decoding is enabled whenever
private variables are declared. With none, counters stay zero. A short decoded
result can increase `decoded_bytes` while depth remains zero because it was
pruned before inspection. Existing raw representation fields remain present;
this receipt records the additional private-value scope.

Manifest verification checks the receipt's format, consistency and limits along
with the original inventory. It does not repeat decoding or require the private
values. As with the rest of the unsigned manifest, this is a record from a trusted
scan, not proof against deliberate editing. Earlier manifests require a new scan.

Run `python3 scripts/benchmark_decoding.py --binary target/release/redflag --check`
after a release build to measure dense Base64/JSON reports and clean-file overhead.
The synthetic probes verify counts, redaction and doubling ratios; they do not
estimate real-project detection accuracy.
