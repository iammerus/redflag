use std::path::Path;

/// Tracks only the lexical context needed to recognize supported line comments.
/// Detection still examines every byte of a line that is not explicitly ignored.
#[derive(Default)]
pub(crate) struct SuppressionState {
    ignore_next_line: bool,
    quote: Option<Quote>,
    block_depth: usize,
}

struct Quote {
    delimiter: u8,
    raw_hashes: Option<usize>,
}

impl SuppressionState {
    pub(crate) fn consume(&mut self, path: &Path, line: &str) -> bool {
        let ignored = std::mem::take(&mut self.ignore_next_line);
        let extension = path.extension().and_then(|ext| ext.to_str()).unwrap_or("");
        if !matches!(
            extension,
            "js" | "mjs"
                | "cjs"
                | "ts"
                | "jsx"
                | "tsx"
                | "rs"
                | "java"
                | "go"
                | "cs"
                | "c"
                | "cpp"
                | "h"
                | "hpp"
                | "php"
                | "kt"
                | "swift"
        ) {
            return ignored;
        }
        let rust = extension == "rs";
        let bytes = line.as_bytes();
        let mut index = 0;
        while index < bytes.len() {
            if let Some(quote) = &self.quote {
                if bytes[index] == quote.delimiter {
                    let hashes = quote.raw_hashes.unwrap_or(0);
                    if bytes
                        .get(index + 1..index + 1 + hashes)
                        .is_some_and(|suffix| suffix.iter().all(|&byte| byte == b'#'))
                    {
                        index += hashes + 1;
                        self.quote = None;
                        continue;
                    }
                }
                if quote.raw_hashes.is_none() && bytes[index] == b'\\' {
                    index += 1;
                }
                index += 1;
                continue;
            }
            if bytes[index..].starts_with(b"/*") {
                self.block_depth += 1;
                index += 2;
            } else if self.block_depth > 0 {
                if bytes[index..].starts_with(b"*/") {
                    self.block_depth -= 1;
                    index += 2;
                } else {
                    index += 1;
                }
            } else if bytes[index..].starts_with(b"//") {
                let directive = line[index + 2..].split_whitespace().next().unwrap_or("");
                if directive.eq_ignore_ascii_case("redflag-ignore-next") {
                    self.ignore_next_line = true;
                    return true;
                }
                return ignored || directive.eq_ignore_ascii_case("redflag-ignore");
            } else if rust && bytes[index] == b'r' {
                let hashes = bytes[index + 1..]
                    .iter()
                    .take_while(|&&b| b == b'#')
                    .count();
                if bytes.get(index + hashes + 1) == Some(&b'"') {
                    self.quote = Some(Quote {
                        delimiter: b'"',
                        raw_hashes: Some(hashes),
                    });
                    index += hashes + 2;
                } else {
                    index += 1;
                }
            } else if matches!(bytes[index], b'"' | b'\'' | b'`') {
                // A Rust lifetime is not the beginning of a character literal.
                let lifetime = rust && bytes[index] == b'\'' && {
                    let length = bytes[index + 1..]
                        .iter()
                        .take_while(|&&b| b.is_ascii_alphanumeric() || b == b'_')
                        .count();
                    length > 0 && bytes.get(index + 1 + length) != Some(&b'\'')
                };
                if !lifetime {
                    self.quote = Some(Quote {
                        delimiter: bytes[index],
                        raw_hashes: None,
                    });
                }
                index += 1;
            } else {
                index += 1;
            }
        }
        ignored
    }
}
