# Pinned offline engine inputs

`pins.json` fixes Betterleaks 1.8.1 at source commit
`5eab48332cc48565864514e3bc6de89df091a7c4`. Each release archive was downloaded
from the upstream release, checked against its published `checksums.txt`, and
the extracted executable was hashed separately. Runtime checks use the executable
digest before execution; installation checks both archive and executable digests.
The six pins cover Linux, macOS and Windows on x64 and arm64. Local execution
validation currently uses macOS arm64; downloaded bytes alone do not prove the
other platforms execute correctly.

```sh
python3 scripts/install_engine.py --directory target/debug/engines
```

Use `--archive PATH` for offline installation from a downloaded archive. The
installer reads only the expected executable member and replaces it atomically.
It does not extract arbitrary paths. Scanning never installs or updates engines.
Redistributions must include `LICENSE.betterleaks`.

`betterleaks.toml` inherits the pinned engine's rules while disabling its global
path prefilter: Redflag owns selection and completeness. `report.tmpl` emits only
rule and location fields, so source snippets, secret captures and validation
metadata cannot enter the normalized report.
Required multipart component locations are retained as separate evidence sets.
Input identity includes the snapshot, so overlap deduplication cannot collapse
the same location in different commits. Reaching the upstream combination limit
or an ambiguous multipart window boundary fails explicitly.

Two narrow GitHub rule overrides preserve complete-token boundaries instead of
accepting a fixed-length prefix of a longer identifier. Custom Redflag TOML rules
remain native, and the existing native `.netrc` check is retained because Betterleaks
1.8.1 misses that format in the preserved research corpus. Native entropy and the
remaining built-in provider catalogue do not run alongside Betterleaks.

Engine upgrades require reviewed checksum pins and the coverage, completeness
and redaction regression tests. Do not change pins to accept an arbitrary binary.

Real-engine integration tests cover hidden/unknown/binary inputs, untrusted
environment/config isolation, overlap and Unicode locations, provider boundaries,
redaction, native custom rules and version 2 manifests. Run them with:

```sh
python3 scripts/install_engine.py --directory target/debug/engines
cargo test --locked --all-targets -- --include-ignored
```

CI installs the pinned engine and includes these tests. Ordinary offline unit-test
runs can omit the explicitly marked external-engine tests.
