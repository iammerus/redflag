use crate::config::Severity;
use crate::scanner::{Finding, FindingHandler};
use std::collections::HashMap;
use std::io::{self, Write};
use termcolor::{Color, ColorChoice, ColorSpec, StandardStream, WriteColor};

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
    color_stream: StandardStream,
    findings_by_severity: HashMap<Severity, usize>,
}

impl OutputHandler {
    pub fn new(format: OutputFormat) -> Self {
        if let OutputFormat::Json = format {
            print!("[");
            io::stdout().flush().unwrap();
        }

        OutputHandler {
            format,
            findings_count: 0,
            first_finding: true,
            writer: Box::new(io::stdout()),
            color_stream: StandardStream::stdout(ColorChoice::Auto),
            findings_by_severity: HashMap::new(),
        }
    }

    #[cfg(test)]
    fn format_finding(&self, finding: &Finding) -> String {
        match self.format {
            OutputFormat::Text => format!(
                "[{}] {}:{} - {} - {}\nSnippet: {}{}\n",
                self.format_severity(finding.severity),
                finding.file.display(),
                finding.line,
                finding.pattern_name,
                finding.description,
                finding.snippet,
                self.format_commit_info(finding)
            ),
            OutputFormat::Json => serde_json::to_string_pretty(finding).unwrap(),
        }
    }

    fn format_severity(&self, severity: Severity) -> String {
        match severity {
            Severity::Critical => "CRITICAL",
            Severity::High => "HIGH    ",
            Severity::Medium => "MEDIUM  ",
            Severity::Low => "LOW     ",
        }
        .to_string()
    }

    fn get_severity_color(&self, severity: Severity) -> Color {
        match severity {
            Severity::Critical => Color::Red,
            Severity::High => Color::Magenta,
            Severity::Medium => Color::Yellow,
            Severity::Low => Color::Blue,
        }
    }

    fn format_commit_info(&self, finding: &Finding) -> String {
        if let (Some(hash), Some(author), Some(date)) = (
            &finding.commit_hash,
            &finding.commit_author,
            &finding.commit_date,
        ) {
            format!("\nCommit: {} ({}, {})", hash, author, date)
        } else {
            String::new()
        }
    }

    pub fn finish(&mut self) -> io::Result<()> {
        match self.format {
            OutputFormat::Json => {
                writeln!(self.writer, "\n]")?;
            }
            OutputFormat::Text => {
                if self.findings_count == 0 {
                    writeln!(self.writer, "No secrets found!")?;
                } else {
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
        }

        self.writer.flush()?;
        Ok(())
    }

    pub fn findings_count(&self) -> usize {
        self.findings_count
    }
}

impl FindingHandler for OutputHandler {
    fn handle(&mut self, finding: Finding) {
        self.findings_count += 1;
        *self
            .findings_by_severity
            .entry(finding.severity)
            .or_insert(0) += 1;

        match self.format {
            OutputFormat::Text => {
                // Set color based on severity
                self.color_stream
                    .set_color(
                        ColorSpec::new().set_fg(Some(self.get_severity_color(finding.severity))),
                    )
                    .unwrap();

                write!(
                    self.color_stream,
                    "[{}] ",
                    self.format_severity(finding.severity)
                )
                .unwrap();

                // Reset color for the rest of the output
                self.color_stream.reset().unwrap();

                writeln!(
                    self.writer,
                    "{}:{} - {} - {}\nSnippet: {}{}\n",
                    finding.file.display(),
                    finding.line,
                    finding.pattern_name,
                    finding.description,
                    finding.snippet,
                    self.format_commit_info(&finding)
                )
                .unwrap();
            }
            OutputFormat::Json => {
                if !self.first_finding {
                    write!(self.writer, ",").unwrap();
                }
                self.first_finding = false;
                write!(
                    self.writer,
                    "\n{}",
                    serde_json::to_string_pretty(&finding).unwrap()
                )
                .unwrap();
            }
        }
        self.writer.flush().unwrap();
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::path::PathBuf;
    use std::sync::Arc;
    use std::sync::Mutex;

    fn create_test_finding(severity: Severity) -> Finding {
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

    #[test]
    fn test_text_output_format() {
        let finding = create_test_finding(Severity::High);
        let handler = OutputHandler::new(OutputFormat::Text);
        let output = handler.format_finding(&finding);

        assert!(output.contains("[HIGH"));
        assert!(output.contains("test.rs:42"));
        assert!(output.contains("test-pattern"));
        assert!(output.contains("Test description"));
        assert!(output.contains("test snippet"));
    }

    #[test]
    fn test_severity_formatting() {
        let handler = OutputHandler::new(OutputFormat::Text);

        assert_eq!(handler.format_severity(Severity::Critical), "CRITICAL");
        assert_eq!(handler.format_severity(Severity::High), "HIGH    ");
        assert_eq!(handler.format_severity(Severity::Medium), "MEDIUM  ");
        assert_eq!(handler.format_severity(Severity::Low), "LOW     ");
    }

    #[test]
    fn test_severity_colors() {
        let handler = OutputHandler::new(OutputFormat::Text);

        assert_eq!(handler.get_severity_color(Severity::Critical), Color::Red);
        assert_eq!(handler.get_severity_color(Severity::High), Color::Magenta);
        assert_eq!(handler.get_severity_color(Severity::Medium), Color::Yellow);
        assert_eq!(handler.get_severity_color(Severity::Low), Color::Blue);
    }

    #[test]
    fn test_json_output_format() {
        let finding = Finding {
            file: PathBuf::from("test.rs"),
            line: 42,
            pattern_name: "test-pattern".to_string(),
            description: "Test description".to_string(),
            snippet: "test snippet".to_string(),
            severity: Severity::Critical,
            commit_hash: Some("abc123".to_string()),
            commit_author: Some("Test Author".to_string()),
            commit_date: Some("2024-02-24".to_string()),
        };

        let handler = OutputHandler::new(OutputFormat::Json);
        let output = handler.format_finding(&finding);

        let parsed: serde_json::Value = serde_json::from_str(&output).unwrap();
        assert_eq!(parsed["file"], "test.rs");
        assert_eq!(parsed["line"], 42);
        assert_eq!(parsed["severity"], "Critical");
        assert_eq!(parsed["commit_hash"], "abc123");
    }

    #[test]
    fn test_findings_summary() {
        let mut handler = OutputHandler::new(OutputFormat::Text);
        handler.handle(create_test_finding(Severity::Critical));
        handler.handle(create_test_finding(Severity::Critical));
        handler.handle(create_test_finding(Severity::High));
        handler.handle(create_test_finding(Severity::Medium));
        handler.handle(create_test_finding(Severity::Low));

        // Create a Vec to store the output
        let output_buffer = Arc::new(Mutex::new(Vec::new()));
        let output_buffer_clone = Arc::clone(&output_buffer);

        struct TestWriter(Arc<Mutex<Vec<u8>>>);

        impl Write for TestWriter {
            fn write(&mut self, buf: &[u8]) -> io::Result<usize> {
                let mut buffer = self.0.lock().unwrap();
                buffer.extend_from_slice(buf);
                Ok(buf.len())
            }

            fn flush(&mut self) -> io::Result<()> {
                Ok(())
            }
        }

        // Use our test writer
        handler.writer = Box::new(TestWriter(output_buffer));
        handler.finish().unwrap();

        // Get the output from our writer
        let buffer = output_buffer_clone.lock().unwrap();
        let output = String::from_utf8(buffer.clone()).unwrap();

        assert!(output.contains("Total findings: 5"));
        assert!(output.contains("Critical: 2"));
        assert!(output.contains("High:     1"));
        assert!(output.contains("Medium:   1"));
        assert!(output.contains("Low:      1"));
    }
}
