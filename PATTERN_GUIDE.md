# Pattern guide

Redflag combines provider formats, credential assignment rules, and optional
entropy checks. File and Git-history scans use the same detector.

## Built-in detection

Provider rules recognize GitHub classic and fine-grained tokens, AWS access IDs,
Stripe secret/restricted keys, and npm access tokens independently of variable
names. They enforce token boundaries so a fixed-length match cannot silently
accept the beginning of a longer string. Private key headers are also recognized.

Assignment rules extract the complete literal before validating it. They support
quoted keys, single/double/backtick strings, unquoted values, and `=`, `:`, `=>`,
and `:=` syntax. AWS secret values require credential context and the expected
alphabet/length. Generic API keys accept hexadecimal and base64 values of at
least 32 characters. Password assignments require at least eight bytes;
`.netrc` passwords use the file's explicit credential syntax.

Credential names can use underscore/hyphen separators or camel-case suffixes,
such as `DATABASE_PASSWORD` or `databasePassword`. Arbitrary substrings such as
`notpassword` do not qualify. In programming-language source, assignment rules
require quoted string values; unquoted names and expressions are references.
Environment, shell, and configuration files retain unquoted literal support.
Provider token formats are still recognized anywhere on a line.

Plain references such as `${DATABASE_PASSWORD}` are excluded. Literal JavaScript
fallbacks and shell defaults are inspected, including when the default is inside
quotes. Known placeholders and Stripe publishable keys are excluded from generic
rules. Database URLs require a nonempty password. These are detection heuristics,
not a parser for every programming language or proof that a credential is valid.

Entropy checks retain the default threshold of 4.8 and minimum length of 30.
Lowering the threshold globally increases noise; hexadecimal credentials should
be found through their credential context. Labeled checksums are excluded only
from entropy checks, so a provider token under a checksum label still produces a
finding. Entropy also skips lockfiles but provider rules continue to inspect them
when the path is selected for scanning.

## Custom rules

Source suppressions use `// redflag-ignore` on the current line or
`// redflag-ignore-next` on the preceding line in supported C-style source
languages. The directive must be a line comment outside strings, template
literals, raw strings, and block comments. JSON and other data files do not
interpret these phrases as directives. A reason can follow the directive.

```toml
[[patterns]]
name = "internal-service-token"
pattern = '''service_token\s*=\s*"(?P<secret>[A-Za-z0-9_-]{32,})"'''
description = "Internal service token"
severity = "High"
```

The fields are `name`, `pattern`, `description`, and `severity` (`Critical`, `High`,
`Medium`, or `Low`). Severity expresses a policy choice, not confidence or
verification status.

A named `secret` capture selects the value to report and redact. Without that
capture, the entire regex match is used. All detected ranges on a line are
redacted in every snippet, including adjacent credentials.

A rule with an existing name replaces that rule. Built-in validation applies
only when both its name and regex match the current built-in definition. A
custom regex keeps its own matching semantics, even if it replaces a built-in
rule. Generated configurations preserve the built-in validation. An older
configuration that supplies old pattern definitions still overrides new defaults;
review those overrides when upgrading.

Use Rust's `regex` syntax. Lookaround and backreferences are unsupported. Keep
provider-specific prefixes case sensitive when their format requires it. Capture
complete values and test token boundaries; matching an arbitrary 32-character
prefix can both misclassify a value and leave its remaining characters exposed.

## Regression tests

Add generated fixtures to `tests/detection_tests.rs` or focused scanner tests:

- Positive cases across supported quoting and assignment styles, including bare
  provider tokens, build outputs, and relevant credential file names.
- Negative cases for references, checksums, public identifiers, and malformed
  token boundaries.
- Multiple credentials on one line, with assertions that each is found and all
  values are redacted from every report snippet.
- File/history parity and custom-rule behavior when either is affected.

Construct synthetic values from short pieces at runtime. Do not commit complete
credentials or exempt the test directory from scanning. Assert the expected file
and rule, since a duplicate finding elsewhere must not hide a missed case.

Run `cargo test --all-targets`, `cargo clippy --all-targets -- -D warnings`, and
`cargo fmt -- --check`. A small synthetic fixture set is regression evidence, not
a real-world recall estimate. Keep additional reported misses as new fixtures.
