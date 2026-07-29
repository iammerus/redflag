# Redflag 🚩

Redflag is a small, cross-platform CLI for finding secrets in source files and
Git history. It combines regular-expression rules for known credential formats
with heuristic Shannon entropy checks.

[![CI](https://github.com/iammerus/redflag/actions/workflows/ci.yml/badge.svg)](https://github.com/iammerus/redflag/actions/workflows/ci.yml)
[![Release](https://img.shields.io/github/v/release/iammerus/redflag)](https://github.com/iammerus/redflag/releases/latest)
![License: MIT](https://img.shields.io/badge/license-MIT-blue.svg)

## Install

Install from source with a current Rust toolchain:

```bash
cargo install --git https://github.com/iammerus/redflag
```

Release tags use the `v<version>` form. Package version `0.1.1` therefore uses
tag `v0.1.1`. Release builds provide Linux, Windows, and macOS x86-64 binaries.

## Quick start

```bash
# Scan the current directory
redflag scan .

# Scan the current checkout and history reachable from HEAD
redflag scan . --git-history

# Create and use a configuration file
redflag generate-config redflag.toml
redflag scan . --config redflag.toml
```

## GitHub Action

Add Redflag to a workflow:

```yaml
name: Secret scan

on: [push, pull_request]

jobs:
  redflag:
    runs-on: ubuntu-latest
    steps:
      - uses: actions/checkout@v4
        with:
          fetch-depth: 0
      - uses: iammerus/redflag@v0.1.1
        with:
          git-history: "true"
```

The action accepts optional `path` and `config` inputs. It builds the selected
Redflag revision with stable Rust, redacts secrets by default, and fails when
findings are present.

Run the action after the build step to include generated assets. Directory scans
now include `dist`, `build`, `out`, `.next`, `.nuxt`, minified JavaScript, and source
maps. Dependency folders and caches remain excluded. Review existing custom
exclusions if these files were previously ignored in your configuration.

## Detection coverage

Known GitHub, AWS access ID, Stripe secret/restricted, and npm token formats are
recognized anywhere on a line, including unnamed values in compiled JavaScript.
GitHub classic and fine-grained tokens are supported. Provider rules run even
when entropy checks are disabled; they do not verify whether a credential is live.

Credential assignments support JSON, YAML, shell, TOML, and common source syntax,
including single quotes, double quotes, backticks, and unquoted values. API-key
assignments recognize hexadecimal and base64 values without lowering the global
entropy threshold. Password rules recognize literal fallbacks, including shell
defaults and JavaScript `||`/`??` expressions.

Built-in validation excludes plain environment references, explicit template
placeholders, and Stripe publishable keys. Database URL findings require a
password. Entropy checks skip labeled checksums; provider rules still run on
those values. Overlapping built-in rules for the same literal produce one finding.

## Process contract

| Exit code | Meaning |
| ---: | --- |
| `0` | The scan completed and found nothing |
| `1` | The scan completed and found at least one item |
| `2` | Arguments, configuration, input, output, or Git caused an operational failure |

stdout contains only the selected report format. Errors, warnings, and progress
belong on stderr. JSON output is one valid array for clean and finding-producing
scans.

Interactive scans show a single-line progress bar on stderr. Redirected output
and CI stay quiet automatically. Use `--no-progress` to disable progress in a
terminal.

Matched values are replaced with `[REDACTED]` by default. Use `--show-secrets`
only when raw values are genuinely required, and treat that output as sensitive.

## Scan command

```bash
redflag scan [PATH]
```

`PATH` defaults to the current directory.

| Option | Purpose |
| --- | --- |
| `-c, --config <FILE>` | Load a TOML configuration |
| `-f, --format <text\|json>` | Select text or JSON output |
| `--show-secrets` | Include raw matched values |
| `--no-progress` | Disable interactive progress output |
| `--git-history` | Also scan reachable Git history |
| `--git-branches <REVISIONS>` | Scan comma-separated branches, tags, or revisions |
| `--git-max-depth <COUNT>` | Limit reachable commits inspected |
| `--git-since <YYYY-MM-DD>` | Ignore older commits |
| `--git-until <YYYY-MM-DD>` | Ignore newer commits |

When no Git revision is configured, history scanning starts from `HEAD`. Every
explicit revision must resolve or the scan exits with code `2`.

An explicitly named regular file is scanned regardless of its extension.
Directory scans use the configured extensions and recognise `.env` and names
such as `.env.local`. Common extensionless configuration files including
`.npmrc`, `.netrc`, `credentials`, SSH private key names such as `id_ed25519`,
`Dockerfile`, `Makefile`, and `Jenkinsfile` are also
recognised. Test, example, fixture, and documentation files are not implicitly
skipped.

The former `install-hook` command has been removed. Its hook was not executable
and read working-tree files rather than staged blobs.

## Configuration

Generate a complete starting file:

```bash
redflag generate-config redflag.toml
```

Configuration is merged with built-in defaults as follows:

- a user pattern replaces a built-in pattern with the same name, otherwise it
  is appended;
- extensions extend the defaults and are deduplicated without regard to case;
- exclusions extend the defaults, with exact duplicates removed;
- a present `[entropy]` or `[git]` section replaces that section after omitted
  fields receive documented defaults;
- invalid regular expressions, globs, dates, date ranges, entropy values, and
  Git limits are fatal.

Example:

```toml
extensions = ["kt"]

[entropy]
enabled = false
threshold = 4.8
min_length = 30

[git]
max_depth = 1000
branches = []

[[patterns]]
name = "internal-service-token"
pattern = '''service_token\s*=\s*"(?P<secret>[A-Za-z0-9_-]{32,})"'''
description = "Internal service token"
severity = "High"

[[exclusions]]
pattern = "**/generated/**"
policy = "Ignore"
```

Exclusion policies are:

| Policy | Behaviour |
| --- | --- |
| `Ignore` | Do not scan the matching path |
| `ScanButWarn` | Warn on stderr but do not add findings |
| `ScanButAllow` | Report findings normally |

The last matching exclusion rule wins. See
[PATTERN_GUIDE.md](PATTERN_GUIDE.md) and
[redflag.example.toml](redflag.example.toml) for more examples.

## Output

Default text output redacts the matched range:

```text
[CRITICAL] config.rs:42 - AWS Access Key - AWS Access Key ID detected
Snippet: [REDACTED]
Commit: a1b2c3d (Developer, 2025-02-24T00:00:00+00:00)

Scan Summary:
-------------
Working tree: 14 files, 0 findings
Git history: 1000 commits, 321 changed files, 1 finding
Total findings: 1
  Critical: 1
  High:     0
  Medium:   0
  Low:      0
```

JSON output can be redirected safely:

```bash
redflag scan . --git-history --format json > redflag-results.json
```

## Files scanned by default

| Group | Extensions |
| --- | --- |
| Languages | `php`, `js`, `ts`, `jsx`, `tsx`, `py`, `rb`, `java`, `go`, `rs`, `cs`, `cpp`, `c`, `h`, `hpp` |
| Data and configuration | `xml`, `yaml`, `yml`, `json`, `config`, `conf`, `ini`, `env`, `properties`, `toml`, `sql`, `md`, `txt` |
| Shell and infrastructure | `sh`, `bash`, `zsh`, `tf`, `tfvars`, `hcl` |
| Credentials and build artifacts | `pem`, `key`, `mjs`, `cjs`, `map` |

## Limits

- Entropy detection is heuristic. It can miss secrets and report harmless
  strings.
- Scanning is line based. Encoded, split, or dynamically constructed credentials
  may be missed. Unknown opaque values still depend on heuristics or custom rules.
- A clean scan is not a security guarantee.
- Finding a committed secret does not make it safe again. Revoke or rotate it
  first.
- Redflag reports history but does not rewrite it.

## Development

```bash
cargo fmt -- --check
cargo clippy --all-targets -- -D warnings
cargo test --all-targets
cargo build --release
```

`tests/detection_tests.rs` generates offline fixtures for provider formats,
assignment syntax, file selection, history, redaction, and benign lookalikes.
These tests run with the normal CI suite. They measure regression coverage,
not the probability of finding every secret in a real repository.

Redflag is available under the MIT licence.
