# Redflag 🚩

Redflag is a small, cross-platform CLI for finding secrets in source code and Git history. It combines regular-expression rules for known credential formats with Shannon entropy checks for strings that look suspicious but do not match a built-in pattern.

Removing a secret in a later commit does not remove it from Git history. Redflag can scan both the files in your current checkout and the commits behind them.

[![CI](https://github.com/iammerus/redflag/actions/workflows/ci.yml/badge.svg)](https://github.com/iammerus/redflag/actions/workflows/ci.yml)
[![Release](https://img.shields.io/github/v/release/iammerus/redflag)](https://github.com/iammerus/redflag/releases/latest)
![License: MIT](https://img.shields.io/badge/license-MIT-blue.svg)

## Install

### From source

You need a current Rust toolchain and Cargo.

```bash
cargo install --git https://github.com/iammerus/redflag
```

### Pre-built binaries

[Release 0.0.9](https://github.com/iammerus/redflag/releases/tag/0.0.9) includes binaries for:

- Linux x86_64
- Windows x86_64
- macOS x86_64

Download the binary for your platform, place it somewhere on your `PATH`, and make it executable where required.

## Quick start

```bash
# Scan the current directory
redflag scan .

# Scan the current checkout and its Git history
redflag scan . --git-history

# Create a configuration file you can edit
redflag generate-config redflag.toml

# Scan with that configuration
redflag scan . --config redflag.toml
```

Redflag exits with a non-zero status when it finds a possible secret or cannot complete the scan, and `0` when the scan is clean. Findings include the matched text, so treat terminal logs and JSON reports as sensitive data.

## Commands

### Scan files

```bash
redflag scan [PATH]
```

`PATH` defaults to the current directory.

Useful options:

| Option | What it does |
| --- | --- |
| `-c, --config <FILE>` | Load rules from a TOML configuration file |
| `-f, --format <text\|json>` | Choose human-readable or JSON output |
| `--git-history` | Scan Git history in addition to the current checkout |
| `--git-branches <BRANCHES>` | Scan a comma-separated list of branches |
| `--git-max-depth <COUNT>` | Limit the number of commits inspected |
| `--git-since <YYYY-MM-DD>` | Ignore commits before this date |
| `--git-until <YYYY-MM-DD>` | Ignore commits after this date |

For example:

```bash
redflag scan . \
  --git-history \
  --git-branches main,develop \
  --git-since 2025-01-01 \
  --git-max-depth 500
```

Historical findings include the commit hash, author, and date.

### Install a pre-commit hook

Run this from the root of a Git repository:

```bash
redflag install-hook
```

The installed hook runs Redflag against staged files before Git creates the commit. The `redflag` binary must remain available on your `PATH` for the hook to work.

### Generate a configuration

```bash
redflag generate-config redflag.toml
```

If no output path is supplied, Redflag writes `redflag.toml` in the current directory.

## Configuration

Redflag ships with rules for common secrets such as AWS credentials, GitHub tokens, private keys, database URLs, JWTs, and hardcoded passwords. A TOML file can adjust entropy detection, choose Git history limits, add patterns, and control exclusions.

```toml
[entropy]
enabled = true
threshold = 3.8
min_length = 24

[git]
max_depth = 1000
branches = ["main", "develop"]
since_date = "2025-01-01"

[[patterns]]
name = "stripe-key"
pattern = '''(?i)sk_(test|live)_[a-z0-9]{24}'''
description = "Stripe API key"
severity = "Critical"

[[exclusions]]
pattern = "**/node_modules/**"
policy = "Ignore"

[[exclusions]]
pattern = "**/test-fixtures/**"
policy = "ScanButAllow"

[[exclusions]]
pattern = "docs/examples/**"
policy = "ScanButWarn"
```

### Exclusion policies

| Policy | Behaviour |
| --- | --- |
| `Ignore` | Skip matching files completely |
| `ScanButWarn` | Print warnings for matching files without adding them to the final findings |
| `ScanButAllow` | Scan matching files normally and include matches in the final findings |

See the [pattern guide](PATTERN_GUIDE.md) for advice on writing and testing custom rules.

## Output

Text output is intended for local use. The secret in this example has been manually redacted:

```text
[CRITICAL] config.rs:42 - AWS Access Key - AWS Access Key ID detected
Snippet: AKIA****************
Commit: a1b2c3d (Developer, 2025-02-24)

Scan Summary:
-------------
Total findings: 1
  Critical: 1
  High:     0
  Medium:   0
  Low:      0
```

Use JSON when another tool needs to read the findings:

```bash
redflag scan . --git-history --format json > redflag-results.json
```

The report contains matched snippets. Do not publish it as a public CI artifact without reviewing or redacting it first.

## GitHub Actions

This example installs Redflag and fails the job when a scan finds something:

```yaml
- name: Install Redflag
  run: cargo install --git https://github.com/iammerus/redflag

- name: Scan repository
  run: redflag scan . --git-history --format json > redflag-results.json
```

The report can contain the values Redflag matched. Do not print it into a public Actions log or upload it as a public artifact.

## Files scanned by default

| Group | Extensions |
| --- | --- |
| Languages | `php`, `js`, `ts`, `jsx`, `tsx`, `py`, `rb`, `java`, `go`, `rs`, `cs`, `cpp`, `c`, `h`, `hpp` |
| Data and configuration | `xml`, `yaml`, `yml`, `json`, `config`, `conf`, `ini`, `env`, `properties`, `toml`, `sql`, `md`, `txt` |

You can add more extensions with the `extensions` field in `redflag.toml`.

## Limits

- Redflag uses heuristic checks. It can miss secrets and report harmless strings.
- A clean scan is not a security guarantee.
- Finding a committed secret does not make it safe again. Revoke or rotate the credential first.
- Redflag reports where a historical secret appears, but it does not rewrite Git history.
- Git hooks are local and can be skipped. Run Redflag in CI or on a schedule as a second check.

## Development

```bash
cargo test
cargo build --release
```

Pattern contributions are welcome. Add the rule to `redflag.example.toml`, include positive and negative tests, and open a pull request with the format it is intended to catch.

Redflag is available under the MIT licence.
