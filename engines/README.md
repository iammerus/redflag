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

Engine upgrades require reviewed checksum pins and the coverage, completeness
and redaction regression tests. Do not change pins to accept an arbitrary binary.
