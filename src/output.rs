use crate::{
    config::Severity,
    error::RedflagError,
    scanner::{Finding, FindingHandler, ScanProgress},
};
use std::{
    collections::HashMap,
    io::{self, IsTerminal, Write},
    time::{Duration, Instant},
};

const PROGRESS_BAR_WIDTH: usize = 20;
const PROGRESS_DETAIL_LENGTH: usize = 80;
const PROGRESS_REFRESH: Duration = Duration::from_millis(100);

#[derive(clap::ValueEnum, Clone, Debug)]
pub enum OutputFormat {
    Text,
    Json,
}

pub struct OutputHandler {
    format: OutputFormat,
    findings_count: usize,
    first_finding: bool,
    writer: Box<dyn Write>,
    findings_by_severity: HashMap<Severity, usize>,
    progress_writer: Box<dyn Write>,
    progress_enabled: bool,
    progress_line: Option<String>,
    progress_width: usize,
    progress_phase: Option<&'static str>,
    last_progress_at: Option<Instant>,
}

impl OutputHandler {
    pub fn new(format: OutputFormat, progress: bool) -> Self {
        let stderr = io::stderr();
        let progress_enabled = progress && stderr.is_terminal();
        Self::with_writers(
            format,
            Box::new(io::stdout()),
            Box::new(stderr),
            progress_enabled,
        )
    }

    #[cfg(test)]
    fn with_writer(format: OutputFormat, writer: Box<dyn Write>) -> Self {
        Self::with_writers(format, writer, Box::new(io::sink()), false)
    }

    fn with_writers(
        format: OutputFormat,
        writer: Box<dyn Write>,
        progress_writer: Box<dyn Write>,
        progress_enabled: bool,
    ) -> Self {
        Self {
            format,
            findings_count: 0,
            first_finding: true,
            writer,
            findings_by_severity: HashMap::new(),
            progress_writer,
            progress_enabled,
            progress_line: None,
            progress_width: 0,
            progress_phase: None,
            last_progress_at: None,
        }
    }

    fn format_severity(severity: Severity) -> &'static str {
        match severity {
            Severity::Critical => "CRITICAL",
            Severity::High => "HIGH    ",
            Severity::Medium => "MEDIUM  ",
            Severity::Low => "LOW     ",
        }
    }

    fn format_commit_info(finding: &Finding) -> String {
        if let (Some(hash), Some(author), Some(date)) = (
            &finding.commit_hash,
            &finding.commit_author,
            &finding.commit_date,
        ) {
            format!("\nCommit: {hash} ({author}, {date})")
        } else {
            String::new()
        }
    }

    fn format_progress(phase: &str, current: usize, total: usize, detail: &str) -> String {
        let current = current.min(total);
        let percentage = current
            .saturating_mul(100)
            .checked_div(total)
            .unwrap_or(100);
        let filled = current
            .saturating_mul(PROGRESS_BAR_WIDTH)
            .checked_div(total)
            .unwrap_or(PROGRESS_BAR_WIDTH);
        let bar = format!(
            "{}{}",
            "#".repeat(filled),
            "-".repeat(PROGRESS_BAR_WIDTH - filled)
        );
        let detail = Self::sanitise_progress_detail(detail);
        if detail.is_empty() {
            format!("{phase} [{bar}] {current}/{total} {percentage}%")
        } else {
            format!("{phase} [{bar}] {current}/{total} {percentage}% {detail}")
        }
    }

    fn sanitise_progress_detail(detail: &str) -> String {
        let mut characters = detail.chars().map(|character| {
            if character.is_control() {
                ' '
            } else {
                character
            }
        });
        let shortened: String = characters.by_ref().take(PROGRESS_DETAIL_LENGTH).collect();
        if characters.next().is_some() {
            format!(
                "{}...",
                shortened
                    .chars()
                    .take(PROGRESS_DETAIL_LENGTH - 3)
                    .collect::<String>()
            )
        } else {
            shortened
        }
    }

    fn draw_progress(&mut self, force: bool) {
        if !self.progress_enabled {
            return;
        }
        if !force
            && self
                .last_progress_at
                .is_some_and(|last| last.elapsed() < PROGRESS_REFRESH)
        {
            return;
        }
        let Some(line) = self.progress_line.as_deref() else {
            return;
        };
        let width = line.chars().count();
        let padding = " ".repeat(self.progress_width.saturating_sub(width));
        if write!(self.progress_writer, "\r{line}{padding}")
            .and_then(|_| self.progress_writer.flush())
            .is_err()
        {
            self.progress_enabled = false;
            return;
        }
        self.progress_width = width;
        self.last_progress_at = Some(Instant::now());
    }

    fn clear_rendered_progress(&mut self) {
        if !self.progress_enabled || self.progress_width == 0 {
            return;
        }
        let padding = " ".repeat(self.progress_width);
        if write!(self.progress_writer, "\r{padding}\r")
            .and_then(|_| self.progress_writer.flush())
            .is_err()
        {
            self.progress_enabled = false;
        }
        self.progress_width = 0;
    }

    pub fn clear_progress(&mut self) {
        self.clear_rendered_progress();
        self.progress_line = None;
        self.progress_phase = None;
    }

    pub fn finish(&mut self) -> Result<(), RedflagError> {
        self.clear_progress();
        match self.format {
            OutputFormat::Json if self.first_finding => writeln!(self.writer, "[]")?,
            OutputFormat::Json => writeln!(self.writer, "\n]")?,
            OutputFormat::Text if self.findings_count == 0 => {
                writeln!(self.writer, "No secrets found!")?;
            }
            OutputFormat::Text => {
                writeln!(self.writer, "\nScan Summary:")?;
                writeln!(self.writer, "-------------")?;
                writeln!(self.writer, "Total findings: {}", self.findings_count)?;
                writeln!(
                    self.writer,
                    "  Critical: {}",
                    self.findings_by_severity
                        .get(&Severity::Critical)
                        .unwrap_or(&0)
                )?;
                writeln!(
                    self.writer,
                    "  High:     {}",
                    self.findings_by_severity.get(&Severity::High).unwrap_or(&0)
                )?;
                writeln!(
                    self.writer,
                    "  Medium:   {}",
                    self.findings_by_severity
                        .get(&Severity::Medium)
                        .unwrap_or(&0)
                )?;
                writeln!(
                    self.writer,
                    "  Low:      {}",
                    self.findings_by_severity.get(&Severity::Low).unwrap_or(&0)
                )?;
            }
        }

        self.writer.flush()?;
        Ok(())
    }

    pub fn findings_count(&self) -> usize {
        self.findings_count
    }
}

impl FindingHandler for OutputHandler {
    fn handle(&mut self, finding: Finding) -> Result<(), RedflagError> {
        let redraw_progress = self.progress_line.is_some();
        self.clear_rendered_progress();
        match self.format {
            OutputFormat::Text => {
                writeln!(
                    self.writer,
                    "[{}] {}:{} - {} - {}\nSnippet: {}{}\n",
                    Self::format_severity(finding.severity),
                    finding.file.display(),
                    finding.line,
                    finding.pattern_name,
                    finding.description,
                    finding.snippet,
                    Self::format_commit_info(&finding)
                )?;
            }
            OutputFormat::Json => {
                if self.first_finding {
                    writeln!(self.writer, "[")?;
                } else {
                    writeln!(self.writer, ",")?;
                }
                serde_json::to_writer_pretty(&mut self.writer, &finding)?;
                self.first_finding = false;
            }
        }

        self.findings_count += 1;
        *self
            .findings_by_severity
            .entry(finding.severity)
            .or_insert(0) += 1;
        self.writer.flush()?;
        if redraw_progress {
            self.draw_progress(true);
        }
        Ok(())
    }

    fn progress(&mut self, progress: ScanProgress) -> Result<(), RedflagError> {
        let phase = match &progress {
            ScanProgress::Preparing { phase }
            | ScanProgress::Item { phase, .. }
            | ScanProgress::Finished { phase, .. } => *phase,
        };
        let force = self.progress_phase != Some(phase)
            || matches!(
                progress,
                ScanProgress::Preparing { .. } | ScanProgress::Finished { .. }
            );
        self.progress_phase = Some(phase);
        self.progress_line = Some(match progress {
            ScanProgress::Preparing { phase } => format!("Preparing {phase}..."),
            ScanProgress::Item {
                phase,
                current,
                total,
                detail,
            } => Self::format_progress(phase, current, total, &detail),
            ScanProgress::Finished { phase, total } => {
                Self::format_progress(phase, total, total, "")
            }
        });
        self.draw_progress(force);
        Ok(())
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::{
        path::PathBuf,
        sync::{Arc, Mutex},
    };

    struct SharedWriter(Arc<Mutex<Vec<u8>>>);

    impl Write for SharedWriter {
        fn write(&mut self, bytes: &[u8]) -> io::Result<usize> {
            self.0.lock().unwrap().extend_from_slice(bytes);
            Ok(bytes.len())
        }

        fn flush(&mut self) -> io::Result<()> {
            Ok(())
        }
    }

    fn finding(severity: Severity) -> Finding {
        Finding {
            file: PathBuf::from("test.rs"),
            line: 42,
            pattern_name: "test-pattern".to_string(),
            description: "Test description".to_string(),
            snippet: "test snippet".to_string(),
            severity,
            commit_hash: None,
            commit_author: None,
            commit_date: None,
        }
    }

    fn output(format: OutputFormat, findings: Vec<Finding>) -> String {
        let bytes = Arc::new(Mutex::new(Vec::new()));
        let mut handler =
            OutputHandler::with_writer(format, Box::new(SharedWriter(Arc::clone(&bytes))));
        for finding in findings {
            handler.handle(finding).unwrap();
        }
        handler.finish().unwrap();
        let output = bytes.lock().unwrap().clone();
        String::from_utf8(output).unwrap()
    }

    #[test]
    fn text_output_contains_finding_and_summary() {
        let output = output(OutputFormat::Text, vec![finding(Severity::High)]);

        assert!(output.contains("[HIGH"));
        assert!(output.contains("test.rs:42"));
        assert!(output.contains("Total findings: 1"));
    }

    #[test]
    fn json_output_is_one_array() {
        let output = output(
            OutputFormat::Json,
            vec![finding(Severity::Critical), finding(Severity::Low)],
        );
        let parsed: serde_json::Value = serde_json::from_str(&output).unwrap();

        assert_eq!(parsed.as_array().unwrap().len(), 2);
    }

    #[test]
    fn progress_is_sanitised_and_redrawn_around_findings() {
        let output = Arc::new(Mutex::new(Vec::new()));
        let progress = Arc::new(Mutex::new(Vec::new()));
        let mut handler = OutputHandler::with_writers(
            OutputFormat::Text,
            Box::new(SharedWriter(Arc::clone(&output))),
            Box::new(SharedWriter(Arc::clone(&progress))),
            true,
        );

        handler
            .progress(ScanProgress::Preparing {
                phase: "Git history",
            })
            .unwrap();
        handler.last_progress_at = Some(Instant::now() - PROGRESS_REFRESH);
        handler
            .progress(ScanProgress::Item {
                phase: "History",
                current: 1,
                total: 4,
                detail: format!("a1b2c3d4 subject\n{}", "x".repeat(100)),
            })
            .unwrap();
        handler.handle(finding(Severity::High)).unwrap();
        handler.clear_progress();

        let output = String::from_utf8(output.lock().unwrap().clone()).unwrap();
        let progress = String::from_utf8(progress.lock().unwrap().clone()).unwrap();
        let status = "History [#####---------------] 1/4 25%";

        assert!(output.contains("test.rs:42"));
        assert_eq!(progress.matches(status).count(), 2);
        assert!(!progress.contains('\n'));
        assert!(progress.contains("..."));
        assert!(progress.ends_with('\r'));
    }

    #[test]
    fn disabled_progress_writes_nothing() {
        let progress = Arc::new(Mutex::new(Vec::new()));
        let mut handler = OutputHandler::with_writers(
            OutputFormat::Text,
            Box::new(io::sink()),
            Box::new(SharedWriter(Arc::clone(&progress))),
            false,
        );

        handler
            .progress(ScanProgress::Finished {
                phase: "Working tree",
                total: 10,
            })
            .unwrap();

        assert!(progress.lock().unwrap().is_empty());
    }
}
