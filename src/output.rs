use crate::{
    config::Severity,
    error::RedflagError,
    scanner::{Finding, FindingHandler},
};
use std::{
    collections::HashMap,
    io::{self, Write},
};

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
}

impl OutputHandler {
    pub fn new(format: OutputFormat) -> Self {
        Self::with_writer(format, Box::new(io::stdout()))
    }

    fn with_writer(format: OutputFormat, writer: Box<dyn Write>) -> Self {
        Self {
            format,
            findings_count: 0,
            first_finding: true,
            writer,
            findings_by_severity: HashMap::new(),
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

    pub fn finish(&mut self) -> Result<(), RedflagError> {
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
}
