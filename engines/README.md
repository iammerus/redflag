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
path prefilter: Redflag owns selection and completeness. `report.tmpl` emits rule
and location fields plus private SHA-256 digests of captured values. The child
retains captures in memory (`--redact=0`) so the template hashes actual captures;
hashing an already redacted placeholder would merge unrelated credentials.
The template never emits raw captures, snippets or validation metadata. Private
digests remain in temporary processing files and are removed from public reports.
Public IDs derive from versioned locations and detector evidence; see REPORTING.md.
Required multipart component locations are retained as separate evidence sets.
Input identity includes the snapshot, so overlap deduplication cannot collapse
the same location in different commits. Reaching the upstream combination limit
or an ambiguous multipart window boundary fails explicitly.

Two narrow GitHub rule overrides preserve complete-token boundaries instead of
accepting a fixed-length prefix of a longer identifier. Custom Redflag TOML rules
remain native, and the existing native `.netrc` check is retained because Betterleaks
1.8.1 misses that format in the preserved research corpus. Native entropy and the
remaining built-in provider catalogue do not run alongside Betterleaks.

`normalization.json` preserves the code-file class used by the pinned engine's
password and username filters. Recognized code extensions (including one
`.example`, `.sample` or `.template` suffix) stage under neutral `.js` names;
other inputs stage under neutral `.txt` names. Original names still appear in
reports. This retains source-expression filtering without restoring upstream
file-selection skips. Unquoted configuration scalars and quoted source passwords
remain candidates. The extension list mirrors the [pinned upstream code-file
filter](https://github.com/betterleaks/betterleaks/blob/5eab48332cc48565864514e3bc6de89df091a7c4/config/betterleaks.toml).

The generic-password filter also requires a credential-key delimiter or a
lower-to-upper camel-case edge. `notpassword` is excluded while `DATABASE_PASSWORD`
and `databasePassword` retain detection. Upstream filter overrides replace
inheritance, so `betterleaks.toml` carries the pinned upstream password filter plus
two final conditions; updates must review that copy with the engine pin. One
condition recognizes an unquoted identifier inside a complete function-call object
argument, including examples in `.txt` files. Both enclosing call/object delimiters
are required. A YAML password field containing an unquoted word, or a quoted
password in that call, still reports a candidate.

Only the exact generic-password captures `YOUR_PASSWORD_HERE` and
`your_password_here` are classified as instructional placeholders by Redflag's
adapter. Prefixes, suffixes and other case variants remain candidates. Provider
rules and declared-private-value matching are independent; declaring either marker
as private still blocks its publication. This does not establish that a marker
used as an actual password is safe.

Reports and manifests include `adapter_sha256`: SHA-256 of the exact `report.tmpl`
bytes, one NUL byte, and the exact `normalization.json` bytes. The detector's
`config_sha256` separately identifies its TOML policy. Verification requires both
current identities; earlier Betterleaks manifests without the adapter identity
require a rescan. Native engine metadata uses a null adapter digest.

Engine upgrades require reviewed checksum pins and the coverage, completeness
and redaction regression tests. Do not change pins to accept an arbitrary binary.

Real-engine integration tests cover hidden/unknown/binary inputs, untrusted
environment/config isolation, overlap and Unicode locations, provider boundaries,
redaction, native custom rules, source references, literal/password key boundaries,
private placeholder values and version 3 manifests. Run them with:

```sh
python3 scripts/install_engine.py --directory target/debug/engines
cargo test --locked --all-targets -- --include-ignored
```

CI installs the pinned engine and includes these tests. Ordinary offline unit-test
runs can omit the explicitly marked external-engine tests.
