use crate::{
    config::Severity,
    error::RedflagError,
    scanner::{Finding, FindingHandler, FindingSpan},
};
use aho_corasick::AhoCorasick;
use std::{
    collections::{BTreeSet, VecDeque},
    path::Path,
};

/// Only explicitly declared environment variables enter this matcher.
/// Its contents are intentionally neither Debug nor Serialize.
pub(crate) struct ProtectedValues {
    names: Vec<String>,
    matcher: Option<AhoCorasick>,
    max_value_len: usize,
}

impl ProtectedValues {
    pub fn load(names: &[String], allow_short: &[String]) -> Result<Self, RedflagError> {
        let names: BTreeSet<_> = names.iter().cloned().collect();
        if names.len() > 256 {
            return Err(RedflagError::Config(
                "Declare at most 256 private environment variables".into(),
            ));
        }
        for name in allow_short {
            if !names.contains(name) {
                return Err(RedflagError::Config(format!(
                    "Short-value override {name} must also be declared with --private-env"
                )));
            }
        }
        let mut values = Vec::new();
        for name in names {
            if !valid_name(&name) {
                return Err(RedflagError::Config("Private environment names must contain ASCII letters, digits or underscores and cannot start with a digit".into()));
            }
            let value = std::env::var(&name).map_err(|_| RedflagError::Config(format!(
                "Private environment variable {name} is missing or is not Unicode. Set it in this trusted build before scanning."
            )))?;
            if value.is_empty() {
                return Err(RedflagError::Config(format!("Private environment variable {name} is empty. Set a nonempty value before scanning.")));
            }
            if value.len() < 8 && !allow_short.contains(&name) {
                return Err(RedflagError::Config(format!("Private environment variable {name} is shorter than 8 bytes. Use --allow-short-private-value {name} to accept exact matches of this value.")));
            }
            if value.len() > 64 * 1024 {
                return Err(RedflagError::Config(format!(
                    "Private environment variable {name} exceeds the 65536-byte value limit"
                )));
            }
            values.push((name, value));
        }
        Self::from_values(values)
    }

    fn from_values(values: Vec<(String, String)>) -> Result<Self, RedflagError> {
        let max_value_len = values
            .iter()
            .map(|(_, value)| value.len())
            .max()
            .unwrap_or(0);
        let matcher = if values.is_empty() {
            None
        } else {
            Some(
                AhoCorasick::new(values.iter().map(|(_, value)| value.as_bytes())).map_err(
                    |_| RedflagError::Config("Could not compile private-value matcher".into()),
                )?,
            )
        };
        Ok(Self {
            names: values.into_iter().map(|(name, _)| name).collect(),
            matcher,
            max_value_len,
        })
    }

    pub fn names(&self) -> &[String] {
        &self.names
    }

    pub fn scan<H: FindingHandler>(
        &self,
        path: &Path,
        bytes: &[u8],
        handler: &mut H,
    ) -> Result<usize, RedflagError> {
        let Some(matcher) = &self.matcher else {
            return Ok(0);
        };
        let mut count = 0;
        let mut end = 0;
        let mut end_line = 1;
        let mut line_start = 0;
        let mut newlines = VecDeque::new();
        let mut preceding = None;
        // Keep only the newline window needed by the longest declared value.
        // Match ends are monotonic; overlapping starts may move backwards.
        for found in matcher.find_overlapping_iter(bytes) {
            let earliest = found.end().saturating_sub(self.max_value_len + 1);
            while newlines
                .front()
                .is_some_and(|&(offset, _)| offset < earliest)
            {
                preceding = newlines.pop_front();
            }
            for (offset, &byte) in bytes[end..found.end()].iter().enumerate() {
                if byte == b'\n' {
                    end_line += 1;
                    line_start = end + offset + 1;
                    let newline = (line_start - 1, end_line);
                    if newline.0 < earliest {
                        preceding = Some(newline);
                    } else {
                        newlines.push_back(newline);
                    }
                }
            }
            end = found.end();
            let index = newlines.partition_point(|&(offset, _)| offset < found.start());
            let previous = index.checked_sub(1).map(|i| newlines[i]).or(preceding);
            let (line, column) = previous.map_or((1, found.start() + 1), |(offset, line)| {
                (line, found.start() - offset)
            });
            handler.handle(Finding {
                file: path.to_path_buf(), line,
                pattern_name: format!("private-env:{}", self.names[found.pattern().as_usize()]),
                description: "Declared private value is present in published bytes. Remove it from the build output and rotate it if it was published.".into(),
                snippet: "[REDACTED]".into(), severity: Severity::Critical,
                commit_hash: None, commit_author: None, commit_date: None,
                evidence: vec![FindingSpan { start_line: line, end_line, start_column: column, end_column: end - line_start }],
                primary: Some(FindingSpan { start_line: line, end_line, start_column: column, end_column: end - line_start }),
                grouping_key: Some(crate::artifacts::digest(&bytes[found.start()..found.end()])),
            })?;
            count += 1;
        }
        Ok(count)
    }
}

fn valid_name(name: &str) -> bool {
    let mut bytes = name.bytes();
    bytes
        .next()
        .is_some_and(|first| first.is_ascii_alphabetic() || first == b'_')
        && bytes.all(|byte| byte.is_ascii_alphanumeric() || byte == b'_')
}
