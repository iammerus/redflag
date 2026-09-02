//! Bounded candidate decoding for explicitly declared private values. Decoded
//! bytes stay in memory; evidence maps back through every transform to the input.
use crate::{
    artifacts::digest,
    config::{ScanLimits, Severity},
    error::RedflagError,
    protected_values::ProtectedValues,
    scanner::{Finding, FindingHandler, FindingSpan},
};
use base64::{engine::general_purpose, Engine};
use serde::{Deserialize, Serialize};
use std::{ops::Range, path::Path};

#[derive(Debug, Clone, Copy, Serialize, Deserialize, PartialEq, Eq, PartialOrd, Ord)]
#[serde(rename_all = "snake_case")]
pub enum Kind {
    JsonString,
    UrlPercent,
    UrlForm,
    Base64,
}
const FORMATS: [Kind; 4] = [
    Kind::JsonString,
    Kind::UrlPercent,
    Kind::UrlForm,
    Kind::Base64,
];

impl Kind {
    fn name(self) -> &'static str {
        match self {
            Self::JsonString => "json_string",
            Self::UrlPercent => "url_percent",
            Self::UrlForm => "url_form",
            Self::Base64 => "base64",
        }
    }
}

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq, PartialOrd, Ord)]
#[serde(deny_unknown_fields)]
pub struct Step {
    pub kind: Kind,
    /// Complete candidate span in this transform's input representation.
    pub encoded: FindingSpan,
    /// Supporting match span in the resulting candidate's decoded bytes.
    pub decoded: FindingSpan,
}

pub fn label(steps: &[Step]) -> String {
    let Some(last) = steps.last() else {
        return String::new();
    };
    format!(
        "{}; decoded {}:{}",
        steps
            .iter()
            .map(|step| step.kind.name())
            .collect::<Vec<_>>()
            .join(" -> "),
        last.decoded.start_line,
        last.decoded.start_column
    )
}

#[derive(Clone, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub(crate) struct Coverage {
    pub schema_version: u32,
    pub enabled: bool,
    pub formats: Vec<Kind>,
    pub candidates: usize,
    pub decoded_bytes: u64,
    pub work_bytes: u64,
    pub max_depth_reached: usize,
}

impl Coverage {
    pub fn new(enabled: bool) -> Self {
        Self {
            schema_version: 1,
            enabled,
            formats: FORMATS.to_vec(),
            candidates: 0,
            decoded_bytes: 0,
            work_bytes: 0,
            max_depth_reached: 0,
        }
    }

    pub fn validate(&self, enabled: bool, limits: &ScanLimits) -> Result<(), RedflagError> {
        if self.schema_version != 1
            || self.enabled != enabled
            || self.formats != FORMATS
            || self.candidates > limits.max_decode_candidates
            || self.decoded_bytes > limits.max_decoded_bytes
            || self.work_bytes > limits.max_decode_work_bytes
            || self.max_depth_reached > limits.max_decode_depth
            || (self.decoded_bytes == 0 && self.max_depth_reached != 0)
            || (self.decoded_bytes > 0 && self.candidates == 0)
            || (!enabled
                && (self.candidates != 0 || self.decoded_bytes != 0 || self.work_bytes != 0))
        {
            return Err(RedflagError::Config(
                "Invalid private-value decoding coverage; scan publication inputs again".into(),
            ));
        }
        Ok(())
    }

    fn work(&mut self, bytes: usize, limits: &ScanLimits) -> Result<(), RedflagError> {
        self.work_bytes = self
            .work_bytes
            .checked_add(bytes as u64)
            .filter(|&total| total <= limits.max_decode_work_bytes)
            .ok_or_else(|| incomplete("max_decode_work_bytes"))?;
        Ok(())
    }
}

pub(crate) fn scan<H: FindingHandler>(
    path: &Path,
    bytes: &[u8],
    private: &ProtectedValues,
    limits: &ScanLimits,
    coverage: &mut Coverage,
    handler: &mut H,
) -> Result<(), RedflagError> {
    if !coverage.enabled || bytes.len() < private.minimum_length() {
        return Ok(());
    }
    let lines = Lines::new(bytes);
    let mut inspection = Inspection {
        path,
        root: bytes,
        private,
        limits,
        coverage,
        handler,
    };
    inspection.visit(bytes, &lines, None, 0)
}

struct Inspection<'a, H> {
    path: &'a Path,
    root: &'a [u8],
    private: &'a ProtectedValues,
    limits: &'a ScanLimits,
    coverage: &'a mut Coverage,
    handler: &'a mut H,
}

struct Frame<'a> {
    parent: Option<&'a Frame<'a>>,
    input: &'a [u8],
    input_lines: &'a Lines,
    output_lines: Lines,
    decoded: &'a Decoded,
}

impl<H: FindingHandler> Inspection<'_, H> {
    fn visit<'a>(
        &mut self,
        bytes: &'a [u8],
        lines: &'a Lines,
        parent: Option<&'a Frame<'a>>,
        depth: usize,
    ) -> Result<(), RedflagError> {
        for kind in FORMATS {
            self.coverage.work(bytes.len(), self.limits)?;
            let mut cursor = 0;
            while let Some(range) =
                candidate(kind, bytes, &mut cursor, self.private.minimum_length())
            {
                self.coverage.candidates = self
                    .coverage
                    .candidates
                    .checked_add(1)
                    .filter(|&total| total <= self.limits.max_decode_candidates)
                    .ok_or_else(|| incomplete("max_decode_candidates"))?;
                self.coverage.work(range.len(), self.limits)?;
                let Some(decoded) = decode(kind, bytes, range, self.limits.max_decode_map_runs)?
                else {
                    continue;
                };
                self.coverage.decoded_bytes = self
                    .coverage
                    .decoded_bytes
                    .checked_add(decoded.bytes.len() as u64)
                    .filter(|&total| total <= self.limits.max_decoded_bytes)
                    .ok_or_else(|| incomplete("max_decoded_bytes"))?;
                // Every supported transform shrinks or preserves length. Shorter
                // candidates cannot contain a private value at any deeper level.
                if decoded.bytes.len() < self.private.minimum_length() {
                    continue;
                }
                if depth >= self.limits.max_decode_depth {
                    return Err(incomplete("max_decode_depth"));
                }
                self.coverage.max_depth_reached = self.coverage.max_depth_reached.max(depth + 1);
                let frame = Frame {
                    parent,
                    input: bytes,
                    input_lines: lines,
                    output_lines: Lines::new(&decoded.bytes),
                    decoded: &decoded,
                };
                self.emit(&frame)?;
                self.visit(&decoded.bytes, &frame.output_lines, Some(&frame), depth + 1)?;
            }
        }
        Ok(())
    }

    fn emit(&mut self, frame: &Frame<'_>) -> Result<(), RedflagError> {
        for (name, range) in self.private.matches(&frame.decoded.bytes) {
            let value = &frame.decoded.bytes[range.clone()];
            let mut supporting = range;
            let mut current = Some(frame);
            let mut steps = Vec::new();
            let mut original = None;
            while let Some(at) = current {
                steps.push(Step {
                    kind: at.decoded.kind,
                    encoded: at.input_lines.span(at.input, at.decoded.input.clone()),
                    decoded: at.output_lines.span(&at.decoded.bytes, supporting.clone()),
                });
                supporting = at.decoded.map(supporting);
                original = Some(at.input_lines.span(at.input, supporting.clone()));
                current = at.parent;
            }
            // An unchanged part of a JSON/URL candidate was already matched in
            // raw bytes. Do not create another occurrence for that same evidence.
            if self.root[supporting] == *value {
                continue;
            }
            steps.reverse();
            let primary = original.expect("at least one decoding frame");
            self.handler.handle(Finding {
                file: self.path.to_path_buf(), line: primary.start_line,
                pattern_name: format!("private-env:{name}"),
                description: "Declared private value is present in decoded publication bytes. Remove it from the build output and rotate it if published.".into(),
                snippet: "[REDACTED]".into(), severity: Severity::Critical,
                commit_hash: None, commit_author: None, commit_date: None,
                evidence: vec![primary.clone()], primary: Some(primary), representation: steps,
                grouping_key: Some(digest(value)),
            })?;
        }
        Ok(())
    }
}

fn incomplete(limit: &str) -> RedflagError {
    RedflagError::Incomplete(format!(
        "Private-value decoding exceeds limits.{limit}; inspection is incomplete"
    ))
}

fn candidate(kind: Kind, bytes: &[u8], cursor: &mut usize, minimum: usize) -> Option<Range<usize>> {
    while *cursor < bytes.len() {
        let start;
        match kind {
            Kind::JsonString => {
                while *cursor < bytes.len() && bytes[*cursor] != b'"' {
                    *cursor += 1;
                }
                start = *cursor;
                if start == bytes.len() {
                    return None;
                }
                *cursor += 1;
                let mut escaped = false;
                let mut closed = false;
                while *cursor < bytes.len() {
                    let byte = bytes[*cursor];
                    *cursor += 1;
                    if byte == b'\\' {
                        escaped = true;
                        *cursor = (*cursor + 1).min(bytes.len());
                    } else if byte == b'"' {
                        closed = true;
                        break;
                    }
                }
                if !closed {
                    return None;
                }
                if !escaped {
                    continue;
                }
            }
            Kind::UrlPercent | Kind::UrlForm => {
                while *cursor < bytes.len() && url_delimiter(bytes[*cursor]) {
                    *cursor += 1;
                }
                start = *cursor;
                while *cursor < bytes.len() && !url_delimiter(bytes[*cursor]) {
                    *cursor += 1;
                }
                let segment = &bytes[start..*cursor];
                if !segment.contains(&b'%') && !(kind == Kind::UrlForm && segment.contains(&b'+')) {
                    continue;
                }
                // Percent-only and form decoding are identical in this case.
                if kind == Kind::UrlForm && !segment.contains(&b'+') {
                    continue;
                }
            }
            Kind::Base64 => {
                while *cursor < bytes.len() && !base64_byte(bytes[*cursor]) {
                    *cursor += 1;
                }
                start = *cursor;
                while *cursor < bytes.len() && base64_byte(bytes[*cursor]) {
                    *cursor += 1;
                }
                // Consume all padding so malformed excess padding cannot be
                // accepted by decoding a valid prefix of the same segment.
                while bytes.get(*cursor) == Some(&b'=') {
                    *cursor += 1;
                }
                if (*cursor - start).saturating_mul(3) / 4 < minimum {
                    continue;
                }
            }
        }
        if *cursor - start >= minimum {
            return Some(start..*cursor);
        }
    }
    None
}

fn url_delimiter(byte: u8) -> bool {
    byte.is_ascii_whitespace() || matches!(byte, 0 | b'"' | b'\'' | b'`' | b'<' | b'>')
}
fn base64_byte(byte: u8) -> bool {
    byte.is_ascii_alphanumeric() || matches!(byte, b'+' | b'/' | b'-' | b'_')
}

struct Run {
    input: usize,
    output: usize,
    len: usize,
    input_unit: usize,
    output_unit: usize,
}
struct Decoded {
    kind: Kind,
    input: Range<usize>,
    bytes: Vec<u8>,
    runs: Vec<Run>,
}

impl Decoded {
    fn push_run(
        &mut self,
        input: usize,
        output: usize,
        len: usize,
        input_unit: usize,
        output_unit: usize,
        max_runs: usize,
    ) -> Result<(), RedflagError> {
        if len == 0 {
            return Ok(());
        }
        if let Some(previous) = self.runs.last_mut().filter(|r| {
            r.output + r.len == output
                && r.input + r.len / r.output_unit * r.input_unit == input
                && r.input_unit == input_unit
                && r.output_unit == output_unit
        }) {
            previous.len += len;
            return Ok(());
        }
        if self.runs.len() >= max_runs {
            return Err(incomplete("max_decode_map_runs"));
        }
        self.runs.push(Run {
            input,
            output,
            len,
            input_unit,
            output_unit,
        });
        Ok(())
    }

    fn map(&self, range: Range<usize>) -> Range<usize> {
        if self.kind == Kind::Base64 {
            return self.input.start + range.start / 3 * 4
                ..(self.input.start + range.end.div_ceil(3) * 4).min(self.input.end);
        }
        let first = &self.runs[self
            .runs
            .partition_point(|run| run.output + run.len <= range.start)];
        let last = &self.runs[self
            .runs
            .partition_point(|run| run.output + run.len < range.end)];
        first.input + (range.start - first.output) / first.output_unit * first.input_unit
            ..last.input + (range.end - last.output).div_ceil(last.output_unit) * last.input_unit
    }
}

fn decode(
    kind: Kind,
    source: &[u8],
    input: Range<usize>,
    max_runs: usize,
) -> Result<Option<Decoded>, RedflagError> {
    let bytes = &source[input.clone()];
    let mut decoded = Decoded {
        kind,
        input: input.clone(),
        bytes: Vec::new(),
        runs: Vec::new(),
    };
    match kind {
        Kind::Base64 => {
            let url = bytes.iter().any(|byte| matches!(byte, b'-' | b'_'));
            let padded = bytes.ends_with(b"=");
            let engine = match (url, padded) {
                (false, true) => &general_purpose::STANDARD,
                (false, false) => &general_purpose::STANDARD_NO_PAD,
                (true, true) => &general_purpose::URL_SAFE,
                (true, false) => &general_purpose::URL_SAFE_NO_PAD,
            };
            let Ok(result) = engine.decode(bytes) else {
                return Ok(None);
            };
            decoded.bytes = result;
        }
        Kind::JsonString => {
            let Ok(result) = serde_json::from_slice::<String>(bytes) else {
                return Ok(None);
            };
            let mut at = 1;
            let mut output = 0;
            while at + 1 < bytes.len() {
                let (consumed, produced) = if bytes[at] == b'\\' {
                    if bytes[at + 1] == b'u' {
                        let code = u16::from_str_radix(
                            std::str::from_utf8(&bytes[at + 2..at + 6]).expect("validated JSON"),
                            16,
                        )
                        .expect("validated escape");
                        (
                            if (0xd800..=0xdbff).contains(&code) {
                                12
                            } else {
                                6
                            },
                            result[output..]
                                .chars()
                                .next()
                                .expect("decoded character")
                                .len_utf8(),
                        )
                    } else {
                        (2, 1)
                    }
                } else {
                    let count = bytes[at..bytes.len() - 1]
                        .iter()
                        .take_while(|&&byte| byte != b'\\')
                        .count();
                    (count, count)
                };
                let (input_unit, output_unit) = if consumed == produced {
                    (1, 1)
                } else {
                    (consumed, produced)
                };
                decoded.push_run(
                    input.start + at,
                    output,
                    produced,
                    input_unit,
                    output_unit,
                    max_runs,
                )?;
                at += consumed;
                output += produced;
            }
            decoded.bytes = result.into_bytes();
        }
        Kind::UrlPercent | Kind::UrlForm => {
            let mut at = 0;
            let mut changed = false;
            while at < bytes.len() {
                let replacement = (bytes[at] == b'%' && at + 2 < bytes.len())
                    .then(|| hex(bytes[at + 1]).zip(hex(bytes[at + 2])))
                    .flatten()
                    .map(|(high, low)| (high * 16 + low, 3))
                    .or_else(|| (kind == Kind::UrlForm && bytes[at] == b'+').then_some((b' ', 1)));
                let (byte, consumed) = replacement.unwrap_or((bytes[at], 1));
                changed |= replacement.is_some();
                decoded.push_run(
                    input.start + at,
                    decoded.bytes.len(),
                    1,
                    consumed,
                    1,
                    max_runs,
                )?;
                decoded.bytes.push(byte);
                at += consumed;
            }
            if !changed {
                return Ok(None);
            }
        }
    }
    Ok(Some(decoded))
}

fn hex(byte: u8) -> Option<u8> {
    match byte {
        b'0'..=b'9' => Some(byte - b'0'),
        b'a'..=b'f' => Some(byte - b'a' + 10),
        b'A'..=b'F' => Some(byte - b'A' + 10),
        _ => None,
    }
}

/// A checkpoint every 4 KiB bounds lookup work without a dense newline index.
struct Lines {
    checkpoints: Vec<(usize, usize)>,
}
impl Lines {
    fn new(bytes: &[u8]) -> Self {
        let mut checkpoints = vec![(1, 0)];
        let (mut line, mut start) = (1, 0);
        for (offset, &byte) in bytes.iter().enumerate() {
            if offset != 0 && offset % 4096 == 0 {
                checkpoints.push((line, start));
            }
            if byte == b'\n' {
                line += 1;
                start = offset + 1;
            }
        }
        Self { checkpoints }
    }
    fn point(&self, bytes: &[u8], offset: usize) -> (usize, usize) {
        let index = (offset / 4096).min(self.checkpoints.len() - 1);
        let (mut line, mut start) = self.checkpoints[index];
        for (position, &byte) in bytes[index * 4096..offset].iter().enumerate() {
            if byte == b'\n' {
                line += 1;
                start = index * 4096 + position + 1;
            }
        }
        (line, offset - start)
    }
    fn span(&self, bytes: &[u8], range: Range<usize>) -> FindingSpan {
        let (start_line, start_column) = self.point(bytes, range.start);
        let (end_line, end_column) = self.point(bytes, range.end);
        FindingSpan {
            start_line,
            start_column: start_column + 1,
            end_line,
            end_column,
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn json_surrogates_and_multibyte_ranges_map_to_original_escapes() {
        let input = br#"prefix
"a\u00e9\uD83D\uDE00z\n""#;
        let decoded = decode(Kind::JsonString, input, 7..input.len(), 100)
            .unwrap()
            .unwrap();
        assert_eq!(decoded.bytes, "aé😀z\n".as_bytes());
        assert_eq!(decoded.map(1..7), 9..27);
        let span = Lines::new(input).span(input, decoded.map(1..7));
        assert_eq!(
            (
                span.start_line,
                span.end_line,
                span.start_column,
                span.end_column
            ),
            (2, 2, 3, 20)
        );
        let span = Lines::new(&decoded.bytes).span(&decoded.bytes, 1..9);
        assert_eq!(
            (
                span.start_line,
                span.end_line,
                span.start_column,
                span.end_column
            ),
            (1, 2, 2, 0)
        );
    }

    #[test]
    fn base64_mapped_quanta_reconstruct_every_matched_byte_range() {
        let original: Vec<_> = (0..32).map(|index| 200u8 + index).collect();
        for engine in [
            general_purpose::STANDARD,
            general_purpose::STANDARD_NO_PAD,
            general_purpose::URL_SAFE,
            general_purpose::URL_SAFE_NO_PAD,
        ] {
            let encoded = format!("before:{}", engine.encode(&original));
            let decoded = decode(Kind::Base64, encoded.as_bytes(), 7..encoded.len(), 1)
                .unwrap()
                .unwrap();
            assert_eq!(decoded.bytes, original);
            for start in 0..original.len() {
                for end in start + 1..=original.len() {
                    let mapped = decoded.map(start..end);
                    let reconstructed = engine.decode(&encoded.as_bytes()[mapped]).unwrap();
                    assert!(reconstructed
                        .windows(end - start)
                        .any(|bytes| bytes == &original[start..end]));
                }
            }
        }
    }

    #[test]
    fn line_checkpoints_retain_original_byte_positions() {
        let input = "one\né😀two\n".repeat(1000).into_bytes();
        let lines = Lines::new(&input);
        for offset in [
            0,
            1,
            4095,
            4096,
            4097,
            8191,
            8192,
            input.len() - 1,
            input.len(),
        ] {
            let line = 1 + input[..offset]
                .iter()
                .filter(|&&byte| byte == b'\n')
                .count();
            let start = input[..offset]
                .iter()
                .rposition(|&byte| byte == b'\n')
                .map_or(0, |last| last + 1);
            assert_eq!(lines.point(&input, offset), (line, offset - start));
        }
    }

    #[test]
    fn invalid_json_and_noncanonical_base64_are_not_supported_candidates() {
        for input in [br#""\ud800""#.as_slice(), br#""\x41""#, b"\"unterminated"] {
            assert!(decode(Kind::JsonString, input, 0..input.len(), 100)
                .unwrap()
                .is_none());
        }
        for input in [b"YR==".as_slice(), b"abc===", b"+_aa"] {
            assert!(decode(Kind::Base64, input, 0..input.len(), 100)
                .unwrap()
                .is_none());
        }
    }
}
