# Pattern Guide for Redflag

This guide explains how to contribute new patterns to Redflag and outlines best practices for pattern development.

## Pattern Structure

Each pattern in Redflag is defined by four components:

```toml
[[patterns]]
name = "pattern-name"
pattern = "regex-pattern"
description = "Human-readable description"
severity = "Critical"  # Options: Critical, High, Medium, Low
```

- `name`: A unique identifier for the pattern (kebab-case recommended)
- `pattern`: A regular expression that matches the secret
- `description`: A clear description of what the pattern detects
- `severity`: The risk level of the detected secret

## Severity Levels

### Critical
- Credentials that provide direct access to sensitive systems
- Examples: AWS keys, database passwords, private keys
- Immediate action required

### High
- Sensitive information that could be part of a larger attack
- Examples: API keys, OAuth tokens, encryption keys
- Action required soon

### Medium
- Potentially sensitive information requiring review
- Examples: Internal URLs, non-production credentials
- Should be reviewed

### Low
- Items that should be checked but may be acceptable
- Examples: Test credentials, documentation tokens
- Review when convenient

## Pattern Best Practices

### 1. Make Patterns Specific

❌ Bad:
```toml
pattern = "password=.*"  # Too broad, many false positives
```

✅ Good:
```toml
pattern = '''(?i)password\s*=\s*['""][^'""]{8,}['""]'''  # Specific format
```

### 2. Use Case-Insensitive Matching

- Use `(?i)` prefix for case-insensitive matching where appropriate
- Consider variations in naming (e.g., `api_key`, `apikey`, `api-key`)

```toml
pattern = '''(?i)api[_-]?key\s*=\s*['""][a-zA-Z0-9]{32,}['""]'''
```

### 3. Account for Common Formats

- Consider different assignment operators (`=`, `:`, `=>`)
- Account for various quote types (`'`, `"`, `"""`)
- Allow for flexible whitespace with `\s*`

```toml
pattern = '''(?i)(api[_-]?key|access[_-]?token)\s*[:=]>\s*['""][a-zA-Z0-9-_]{32,}['""]'''
```

### 4. Validate Pattern Length

- Include minimum length requirements for secrets
- Use quantifiers to prevent short matches
- Consider maximum lengths for specific formats

```toml
pattern = '''(?i)github[_-]?token\s*=\s*gh[pousr]_[a-zA-Z0-9]{36}'''  # Exact GitHub token length
```

## Common Pattern Types

### 1. API Keys

```toml
[[patterns]]
name = "generic-api-key"
pattern = '''(?i)api[_-]?key\s*=\s*['""][a-zA-Z0-9-_]{32,}['""]'''
description = "Generic API key with minimum length of 32 characters"
```

### 2. Access Tokens

```toml
[[patterns]]
name = "oauth-token"
pattern = '''(?i)(oauth|access)[_-]?token\s*=\s*['""][a-zA-Z0-9-_]{32,}['""]'''
description = "OAuth or Access Token"
```

### 3. Credentials

```toml
[[patterns]]
name = "database-url"
pattern = '''(?i)(mongodb|postgresql|mysql)://([\w-]+:[\w-]+@)?[\w.-]+[:]\d+/[\w-]+'''
description = "Database connection string with potential credentials"
```

### 4. Private Keys

```toml
[[patterns]]
name = "private-key"
pattern = '''-----BEGIN\s+(RSA|DSA|EC|OPENSSH)\s+PRIVATE\s+KEY(\s+ENCRYPTED)?-----'''
description = "Private key file header"
```

## Testing Your Pattern

1. Create a test file with both positive and negative examples
2. Test the pattern against real-world examples
3. Verify minimal false positives
4. Check performance impact

Build a test file without storing complete synthetic secrets in the repository:
```bash
api_key_first="abcd1234efgh5678"
api_key_second="ijkl9012mnop3456"
token_first="zyxw9876vutsrqpon"
token_second="mlkjihgfedcba"

printf 'API_KEY="%s%s"\n' "$api_key_first" "$api_key_second" > pattern-fixture.env
printf "access_token='%s%s'\n" "$token_first" "$token_second" >> pattern-fixture.env
printf 'api_prefix="test"\nnot_an_api_key="short"\n' >> pattern-fixture.env
```

## Pattern Validation

Before submitting a pattern:

1. **Uniqueness**: Ensure it doesn't duplicate existing patterns
2. **Performance**: Test with large codebases to verify performance
3. **False Positives**: Minimise false positives with specific matches
4. **Documentation**: Include clear description and examples

## Common Pitfalls

1. **Over-matching**: Patterns that are too broad
2. **Under-matching**: Missing common variations
3. **Performance Issues**: Complex regex with excessive backtracking
4. **False Positives**: Not accounting for common code patterns

## Contributing

1. Fork the repository
2. Add your pattern to `redflag.example.toml`
3. Add tests for your pattern
4. Submit a pull request with:
   - Pattern description
   - Example matches
   - Test cases
   - Use case explanation

## Pattern Testing Tools

Use these tools to test your patterns:

1. [regex101.com](https://regex101.com) - Interactive regex testing
2. [regexr.com](https://regexr.com) - Visual regex explanation
3. Local testing:
   ```bash
   # Test your pattern
   redflag scan --config your-pattern.toml ./test-dir
   ```

## Need Help?

- Open an issue for pattern discussion
- Join our community discussions
- Check existing patterns for examples

Remember: Security tools are only as good as their patterns. Help us improve Redflag by contributing high-quality, well-tested patterns!
