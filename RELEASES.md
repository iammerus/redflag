# Native release bundles

This guide describes the native bundle format and release commands.

The release platform inventory is [release/platforms.json](release/platforms.json):

| Platform | Rust target | Native build runner |
| --- | --- | --- |
| Apple Silicon | `aarch64-apple-darwin` | `macos-15` |
| macOS Intel | `x86_64-apple-darwin` | `macos-15-intel` |
| Linux x86-64 | `x86_64-unknown-linux-gnu` | `ubuntu-24.04` |
| Windows x86-64 | `x86_64-pc-windows-msvc` | `windows-2025` |

Only Apple Silicon execution has been validated locally so far. The inventory is
not evidence that the other platform builds have run. Linux/Windows arm64 currently
fail platform selection explicitly; there is no silent architecture fallback.

## Build a bundle

Build with the locked dependency graph and install the pinned engine. Keep generated
metadata and bundles outside the checkout so they do not make the source tree dirty.
For an Apple Silicon build:

```sh
cargo build --locked --release
python3 scripts/install_engine.py --directory target/release/engines
release_work="$(mktemp -d)"
cargo metadata --locked --format-version 1 --filter-platform aarch64-apple-darwin \
  > "$release_work/metadata.json"
python3 scripts/release_bundle.py build \
  --binary target/release/redflag --engine target/release/engines/betterleaks \
  --platform darwin_arm64 --source-commit "$(git rev-parse HEAD)" \
  --metadata "$release_work/metadata.json" \
  --output "$release_work/redflag-0.2.0-darwin_arm64.tar.gz"
```

The command prints the archive SHA-256 and filename. The source commit must equal
the current checkout. Native builds must report the package version. Executable
headers must match the selected architecture, and the engine must match the exact
reviewed platform pin. The bundle records whether tracked or untracked source
changes are present; development bundles cannot pass verification that requires
an exact clean release commit.

Bundles contain Redflag, `engines/betterleaks` (both with `.exe` on Windows), the
Redflag and Betterleaks license notices, a dependency notice inventory, and license
files from resolved Rust packages and their bundled native dependencies. Native
notices include libgit2, libssh2, zlib and OpenSSL. Cargo metadata is build input;
the resulting archive contains no local dependency paths or source trees.

`manifest.json` version 1 records the version, platform, target, source commit and
dirty flag, engine version/pin identity, and every payload's size, SHA-256 and
executable status. Archive ordering and gzip/tar timestamps are deterministic for
identical inputs. The builder verifies its finished archive before moving it to
the requested destination. Existing destinations are not replaced.

## Verify and install a supplied bundle

```sh
python3 scripts/release_bundle.py install \
  --archive /trusted/redflag-0.2.0-darwin_arm64.tar.gz \
  --sha256 "$TRUSTED_BUNDLE_SHA256" --directory /new/redflag-installation
```

Obtain the expected digest through a trusted channel. A digest supplied beside an
untrusted download establishes consistency, not publisher identity. This local
path permits deliberately authorized development bundles; release downloads will
also require verified build provenance before this installer runs.

Verification checks the archive digest before decompression, then enforces bounded
gzip expansion and a strict regular-file tar inventory. It rejects links, traversal,
duplicate entries, extended headers, truncated/checksum-invalid archives, unexpected
payloads, incorrect license notices, manifest mismatches and modified engines. Only
the two expected binaries become executable. Installation stages files in a private
directory and moves the complete directory into place; validation failures create
no destination. Existing installations remain untouched.

Limits are 128 MiB compressed, 256 MiB payload bytes plus bounded tar overhead,
64 MiB per member and 4,096 members. `python3 scripts/test_release_bundle.py` exercises
these boundaries and rejection paths without executing synthetic fixture binaries.
No test or source-tree hash alone proves that a hosted release was published or
that its build provenance was verified.
