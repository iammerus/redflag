# Publication archive inspection

Artifact scans inspect original container bytes and recursively inspect supported
archive payloads. Every payload receives general credential detection, native
custom/format rules, and raw plus decoded matching for any declared private values.
Inspection happens in memory; archive paths are never extracted to the filesystem.
Source `changes` and legacy `scan` retain their existing scope.

## Supported formats

| Format | Contract |
| --- | --- |
| gzip | All concatenated gzip members form one logical output stream, including matches crossing their boundaries. Checksums, complete trailers and absence of trailing non-gzip data are required. |
| ZIP | Classic, single-disk ZIP with stored or deflate compression. Every central-directory entry is inspected. Central counts, local names/flags, payload extents, sizes and content checksums are checked. |
| tar | Regular files and directories in basic/ustar archives. Entry checksums and sizes are checked. Two zero terminator blocks are required, with only zero block padding afterwards. |

ZIP64 size/offset sentinels, split archives, encrypted ZIP entries, unsupported ZIP
compression, tar extended headers (including PAX/GNU extensions), sparse entries,
links and special files fail with exit 2. ZIP names must be unique after path
normalization; tar names must also be unique. ZIP's declared directory is the
member selection boundary; unreferenced container bytes receive the raw scan.
Self-extracting/prepended ZIP payloads are outside this scope.

Names must be UTF-8, at most 4,096 bytes, without control characters, backslashes,
colons, absolute prefixes or parent traversal. Leading `./`, repeated separators
and directory trailing separators normalize to a relative path. No member path is
used as an extraction destination. Member filenames retain code/configuration
classification and `.netrc` rules; source exclusions and inline suppressions still
do not apply.

gzip, ZIP and ustar magic is recognized without relying on filename extensions.
`.tar` also selects the tar parser, including empty archives and basic tar without
ustar magic. Files named `.gz`, `.tgz`, `.zip`, `.jar` or `.whl` with incompatible
headers fail. Known 7z, RAR, bzip2, xz and zstd signatures, and their listed suffixes
plus `.br`, `.tbz`, `.tbz2` and `.txz`, fail as unsupported. Other compression or
embedded archives at arbitrary offsets are not guessed. Supply unpacked publication
inputs for unsupported formats. A structurally valid empty archive is inspected;
it differs from a missing or zero-byte publication target.

## Member locations

Flat findings and logical locations add a root-first `archive` array, omitted for
raw observations. Each step contains `format`, zero-based member `index`, normalized
`path`, uncompressed `bytes` and whole-member `sha256`. ZIP/tar indices include
directory entries. gzip uses one logical stream at index 0; the name is derived
from the containing filename (`.gz` removed, `.tgz` changed to `.tar`), falling back
to `content` for a container recognized only by magic. Header filename metadata
does not choose an extraction path or override this name.

The finding's file and artifact version still identify the outer publication file.
Its line/primary/evidence spans refer to the innermost member bytes. A simultaneous
`representation` chain maps decoded private matches back to those member bytes,
not to a guessed compressed-file line. Text and GitHub summaries label archive
members explicitly; archive findings use general GitHub annotations.

Member contents and private captures stay out of reports. Paths and whole-member
hashes are intentional metadata. A member path containing a declared private value
is replaced entirely by `[REDACTED PRIVATE VALUE]` before report spooling or public
identity construction; original names still select detector filename context.
Member indices and outer/member hashes preserve distinct occurrences even when
their labels are masked. Member chains participate in occurrence identity,
so equal values in different members remain separate occurrences. Moving an outer
root preserves IDs when bytes, target order and derived member names stay the same.
Renaming a gzip file can change its derived name and code classification. Raw IDs
remain unchanged. Exact artifact false-positive reviews bind these identities and
the outer file's digest; declared private values always block.

## Resource limits and manifests

Configure positive limits under `[limits]`:

| Setting | Default | Scope |
| --- | ---: | --- |
| `max_archive_depth` | 4 | Nested archive layers, allowed range 1–16. A gzip-compressed tar uses two layers. |
| `max_archive_members` | 10,000 | ZIP/tar entries including directories, plus logical gzip output streams, across all selected files/layers. |
| `max_archive_member_bytes` | 64 MiB | One expanded file or logical gzip stream. |
| `max_expanded_bytes` | 1 GiB | Every expanded payload across files and layers, including intermediate nested containers. |
| `max_archive_ratio` | 1,000 | Expanded bytes divided by compressed entry bytes (whole input for gzip, stored size for tar), using a denominator of at least one. |

The reader stops after the smallest applicable byte limit plus one byte. Original
file/total limits still bound container inputs; line, private-decoding and report
budgets also apply to members. Only the current nested chain retains member data;
the general engine stages bounded snapshots of those bytes in its private workspace.
An incomplete or unsupported archive fails before output and invalidates any
requested previous approval manifest.

Coverage adds `archive_inspection` with `schema_version: 1`, ordered `formats`,
`archives`, `members`, `expanded_bytes` and `max_depth_reached`. A gzip stream counts
as one logical member even when its encoding contains multiple gzip members. Clean
scans record this receipt in schema 5 manifests. Verification validates the receipt
and rechecks the exact original container inventory/digests; it does not re-extract
or rerun detectors. The manifest remains an unsigned trusted workflow record.
Earlier manifests require a new scan.

The pinned parsers are [flate2 1.1.9](https://docs.rs/flate2/1.1.9/flate2/),
[zip 8.6.0](https://docs.rs/zip/8.6.0/zip/) with only deflate enabled, and
[tar 0.4.46](https://docs.rs/tar/0.4.46/tar/). Decompression uses the Rust backend;
no archive extraction commands or external services run.

Run `python3 scripts/benchmark_archives.py --binary target/release/redflag --check`
after a release build for synthetic gzip-size and ZIP-member scaling checks. These
probes validate coverage and doubling ratios, not real-project accuracy or p95 CI
latency.
