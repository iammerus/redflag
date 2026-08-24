//! Versioned, grouped reports. Private grouping material never reaches rendering.
use crate::{
    artifacts::{digest, file_path, ArtifactCoverage},
    config::{ScanLimits, Severity},
    error::RedflagError,
    output::OutputFormat,
    scanner::{Finding, FindingHandler, FindingSpan},
};
use serde::{Deserialize, Serialize};
use std::{
    collections::{BTreeMap, BTreeSet},
    fs::File,
    io::{self, BufRead, BufReader, BufWriter, Seek, SeekFrom, Write},
    path::{Component, Path, PathBuf},
};

const MAX_REPORT_BYTES: usize = 64 * 1024 * 1024;

pub(crate) struct ReportHandler {
    format: OutputFormat,
    spool: BufWriter<File>,
    count: usize,
    bytes: usize,
    max_findings: usize,
}

#[derive(Serialize, Deserialize)]
struct StoredFinding {
    finding: Finding,
    grouping_key: String,
}

pub(crate) struct ReportContext {
    mode: &'static str,
    artifacts: BTreeMap<PathBuf, ArtifactLocation>,
}

struct ArtifactLocation {
    target: usize,
    path: String,
    version: String,
}

impl ReportContext {
    pub fn source() -> Self {
        Self {
            mode: "changes",
            artifacts: BTreeMap::new(),
        }
    }
    pub fn artifacts(coverage: &ArtifactCoverage) -> Result<Self, RedflagError> {
        let mut artifacts = BTreeMap::new();
        for file in &coverage.files {
            artifacts.insert(
                file_path(&coverage.targets[file.target], &file.path),
                ArtifactLocation {
                    target: file.target,
                    path: normalized_path(&file.path)?,
                    version: file.sha256.clone(),
                },
            );
        }
        Ok(Self {
            mode: "artifacts",
            artifacts,
        })
    }

    fn location(&self, finding: &Finding) -> Result<Location, RedflagError> {
        match self.mode {
            "changes" => Ok(Location {
                target: None,
                path: normalized_path(&finding.file)?,
                version: finding
                    .commit_hash
                    .clone()
                    .ok_or_else(|| invalid("Source finding has no commit"))?,
                commit: finding.commit_hash.clone(),
            }),
            _ => {
                let file = self.artifacts.get(&finding.file).ok_or_else(|| {
                    invalid("Artifact finding is outside the inspected inventory")
                })?;
                Ok(Location {
                    target: Some(file.target),
                    path: file.path.clone(),
                    version: file.version.clone(),
                    commit: None,
                })
            }
        }
    }
}

#[derive(Clone, PartialEq, Eq, PartialOrd, Ord, Serialize)]
pub(crate) struct Location {
    #[serde(skip_serializing_if = "Option::is_none")]
    pub target: Option<usize>,
    pub path: String,
    /// Commit ID for source; whole-file SHA-256 for artifacts.
    pub version: String,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub commit: Option<String>,
}

struct ObservationPointer {
    offset: u64,
    id: String,
    location: Location,
    primary: FindingSpan,
}

struct Group {
    observations: Vec<ObservationPointer>,
    rules: BTreeMap<String, Severity>,
    private_env: BTreeSet<String>,
    severity: Severity,
}

struct PhysicalOccurrence {
    id: String,
    location: Location,
    primary: FindingSpan,
    observations: Vec<ObservationPointer>,
}

struct PreparedGroup {
    id: String,
    rules: BTreeMap<String, Severity>,
    private_env: BTreeSet<String>,
    severity: Severity,
    occurrences: Vec<PhysicalOccurrence>,
}

#[derive(Serialize)]
struct GroupHeader<'a> {
    id: &'a str,
    title: &'static str,
    severity: Severity,
    rules: &'a BTreeMap<String, Severity>,
    private_env: &'a BTreeSet<String>,
    remediation: &'static str,
    occurrence_count: usize,
}

#[derive(Serialize)]
pub(crate) struct DetectorEvidence {
    pub id: String,
    pub rule_id: String,
    pub description: String,
    pub severity: Severity,
    pub spans: Vec<FindingSpan>,
}

#[derive(Serialize)]
pub(crate) struct ReportOccurrence {
    pub id: String,
    pub location: Location,
    pub primary: FindingSpan,
    pub evidence: Vec<DetectorEvidence>,
}

impl ReportHandler {
    pub fn new(format: OutputFormat, limits: &ScanLimits) -> Result<Self, RedflagError> {
        Ok(Self {
            format,
            spool: BufWriter::new(tempfile::tempfile()?),
            count: 0,
            bytes: 0,
            max_findings: limits.max_findings,
        })
    }

    pub fn findings_count(&self) -> usize {
        self.count
    }

    pub fn finish_report(
        mut self,
        context: ReportContext,
        coverage: &impl Serialize,
    ) -> Result<(), RedflagError> {
        self.spool.flush()?;
        self.spool.get_mut().rewind()?;
        let file = self.spool.into_inner().map_err(|e| e.into_error())?;
        let mut reader = BufReader::new(file);
        let groups = prepare(&mut reader, &context)?;
        let stdout = io::stdout();
        let mut writer = BufWriter::new(stdout.lock());
        match self.format {
            OutputFormat::Json => {
                #[derive(Serialize)]
                struct Header<'a, T> {
                    schema_version: u32,
                    mode: &'a str,
                    complete: bool,
                    scanner_version: &'static str,
                    findings_count: usize,
                    logical_findings_count: usize,
                    occurrences_count: usize,
                    identity_schema: &'static str,
                    coverage: &'a T,
                }
                let header = Header {
                    schema_version: 2,
                    mode: context.mode,
                    complete: true,
                    scanner_version: env!("CARGO_PKG_VERSION"),
                    findings_count: self.count,
                    logical_findings_count: groups.len(),
                    occurrences_count: groups.iter().map(|g| g.occurrences.len()).sum(),
                    identity_schema: "redflag-occurrence-v1",
                    coverage,
                };
                let mut bytes = serde_json::to_vec(&header)?;
                bytes.pop();
                writer.write_all(&bytes)?;
                writer.write_all(b",\"logical_findings\":[")?;
                for (index, group) in groups.iter().enumerate() {
                    if index > 0 {
                        writer.write_all(b",")?;
                    }
                    let mut header = serde_json::to_vec(&group.header(context.mode))?;
                    header.pop();
                    writer.write_all(&header)?;
                    writer.write_all(b",\"occurrences\":[")?;
                    for (i, occurrence) in group.occurrences.iter().enumerate() {
                        if i > 0 {
                            writer.write_all(b",")?;
                        }
                        serde_json::to_writer(
                            &mut writer,
                            &read_occurrence(&mut reader, occurrence)?,
                        )?;
                    }
                    writer.write_all(b"]}")?;
                }
                // Keep the original flat observations with their original meaning.
                writer.write_all(b"],\"findings\":[")?;
                reader.rewind()?;
                let mut line = String::new();
                let mut first = true;
                loop {
                    line.clear();
                    if reader.read_line(&mut line)? == 0 {
                        break;
                    }
                    let record: StoredFinding = serde_json::from_str(&line)?;
                    if !first {
                        writer.write_all(b",")?;
                    }
                    first = false;
                    serde_json::to_writer(&mut writer, &record.finding)?;
                }
                writer.write_all(b"]}\n")?;
            }
            OutputFormat::Text => {
                for group in &groups {
                    let header = group.header(context.mode);
                    writeln!(
                        writer,
                        "{} [{}] — {} occurrence(s)",
                        header.title,
                        group.id,
                        group.occurrences.len()
                    )?;
                    for occurrence in &group.occurrences {
                        let target = occurrence
                            .location
                            .target
                            .map(|n| format!("target {n}: "))
                            .unwrap_or_default();
                        let commit = occurrence
                            .location
                            .commit
                            .as_ref()
                            .map(|s| format!(" (commit {s})"))
                            .unwrap_or_default();
                        writeln!(
                            writer,
                            "  {target}{}:{}:{}{commit}",
                            clean_text(&occurrence.location.path),
                            occurrence.primary.start_line,
                            occurrence.primary.start_column
                        )?;
                        let evidence = read_occurrence(&mut reader, occurrence)?;
                        writeln!(
                            writer,
                            "    Rules: {}",
                            evidence
                                .evidence
                                .iter()
                                .map(|e| clean_text(&e.rule_id))
                                .collect::<Vec<_>>()
                                .join(", ")
                        )?;
                        writeln!(writer, "    Occurrence: {}", occurrence.id)?;
                    }
                    writeln!(writer, "  {}", header.remediation)?;
                }
                writeln!(
                    writer,
                    "{} inspection complete: {} logical finding(s), {} occurrence(s).",
                    context.mode,
                    groups.len(),
                    groups.iter().map(|g| g.occurrences.len()).sum::<usize>()
                )?;
            }
        }
        writer.flush()?;
        Ok(())
    }
}

impl FindingHandler for ReportHandler {
    fn handle(&mut self, mut finding: Finding) -> Result<(), RedflagError> {
        if self.count >= self.max_findings {
            return Err(invalid("Report exceeds limits.max_findings"));
        }
        let grouping_key = finding
            .grouping_key
            .take()
            .ok_or_else(|| invalid("Finding lacks private grouping material"))?;
        finding.snippet = "[REDACTED]".into();
        let bytes = serde_json::to_vec(&StoredFinding {
            finding,
            grouping_key,
        })?;
        if bytes.len() + 1 > MAX_REPORT_BYTES.saturating_sub(self.bytes) {
            return Err(invalid("Grouped report input exceeds 64 MiB"));
        }
        self.spool.write_all(&bytes)?;
        self.spool.write_all(b"\n")?;
        self.bytes += bytes.len() + 1;
        self.count += 1;
        Ok(())
    }
}

fn prepare(
    reader: &mut BufReader<File>,
    context: &ReportContext,
) -> Result<Vec<PreparedGroup>, RedflagError> {
    let mut groups = BTreeMap::<String, Group>::new();
    let mut line = String::new();
    loop {
        let offset = reader.stream_position()?;
        line.clear();
        if reader.read_line(&mut line)? == 0 {
            break;
        }
        let record: StoredFinding = serde_json::from_str(&line)?;
        let finding = record.finding;
        let location = context.location(&finding)?;
        let primary = finding
            .primary
            .as_ref()
            .ok_or_else(|| invalid("Finding lacks a primary location"))?;
        if finding.evidence.is_empty()
            || !valid_span(primary)
            || finding.evidence.iter().any(|s| !valid_span(s))
        {
            return Err(invalid("Finding has invalid location evidence"));
        }
        let mut spans = finding.evidence.clone();
        spans.sort();
        spans.dedup();
        let id = identity(
            "evidence",
            &(context.mode, &location, &finding.pattern_name, spans),
        )?;
        let group = groups.entry(record.grouping_key).or_insert_with(|| Group {
            observations: Vec::new(),
            rules: BTreeMap::new(),
            private_env: BTreeSet::new(),
            severity: finding.severity,
        });
        if let Some(name) = finding.pattern_name.strip_prefix("private-env:") {
            group.private_env.insert(name.into());
        }
        group.severity = maximum_severity(group.severity, finding.severity);
        group
            .rules
            .entry(finding.pattern_name)
            .and_modify(|s| *s = maximum_severity(*s, finding.severity))
            .or_insert(finding.severity);
        group.observations.push(ObservationPointer {
            offset,
            id,
            location,
            primary: primary.clone(),
        });
    }
    let mut prepared = Vec::new();
    for (_, mut group) in groups {
        group.observations.sort_by(|a, b| {
            (
                &a.location,
                a.primary.start_line,
                a.primary.start_column,
                &a.id,
            )
                .cmp(&(
                    &b.location,
                    b.primary.start_line,
                    b.primary.start_column,
                    &b.id,
                ))
        });
        let mut occurrences: Vec<PhysicalOccurrence> = Vec::new();
        for observation in group.observations {
            if let Some(last) = occurrences.last_mut().filter(|last| {
                last.location == observation.location && nested(&last.primary, &observation.primary)
            }) {
                // Anchor to the narrower region. Widening it would join separate
                // repetitions through a detector's surrounding assignment text.
                last.primary = intersection(&last.primary, &observation.primary);
                last.observations.push(observation);
            } else {
                occurrences.push(PhysicalOccurrence {
                    id: String::new(),
                    location: observation.location.clone(),
                    primary: observation.primary.clone(),
                    observations: vec![observation],
                });
            }
        }
        for occurrence in &mut occurrences {
            occurrence.observations.sort_by(|a, b| a.id.cmp(&b.id));
            occurrence.observations.dedup_by(|a, b| a.id == b.id);
            occurrence.id = identity(
                "occurrence",
                &occurrence
                    .observations
                    .iter()
                    .map(|p| &p.id)
                    .collect::<Vec<_>>(),
            )?;
        }
        let mut ids: Vec<_> = occurrences.iter().map(|o| &o.id).collect();
        ids.sort();
        prepared.push(PreparedGroup {
            id: identity("group", &ids)?,
            rules: group.rules,
            private_env: group.private_env,
            severity: group.severity,
            occurrences,
        });
    }
    prepared.sort_by(|a, b| a.id.cmp(&b.id));
    Ok(prepared)
}

impl PreparedGroup {
    fn header(&self, mode: &str) -> GroupHeader<'_> {
        let private = !self.private_env.is_empty();
        GroupHeader {
            id: &self.id,
            title: if private {
                "Declared private value"
            } else {
                "Credential candidate"
            },
            severity: self.severity,
            rules: &self.rules,
            private_env: &self.private_env,
            occurrence_count: self.occurrences.len(),
            remediation: if mode == "changes" {
                "Remove the credential from introduced commits and use a runtime secret reference. Rotate it if it was pushed or shared; removal does not establish revocation."
            } else if private {
                "Remove the declared private value from publication inputs, rebuild and scan again before upload. Rotate it if it was exposed."
            } else {
                "Remove the credential from publication inputs and scan the rebuilt output before upload. Rotate it if it was exposed."
            },
        }
    }
}

fn read_occurrence(
    reader: &mut BufReader<File>,
    occurrence: &PhysicalOccurrence,
) -> Result<ReportOccurrence, RedflagError> {
    let mut evidence = Vec::new();
    for pointer in &occurrence.observations {
        reader.seek(SeekFrom::Start(pointer.offset))?;
        let mut line = String::new();
        reader.read_line(&mut line)?;
        let record: StoredFinding = serde_json::from_str(&line)?;
        evidence.push(DetectorEvidence {
            id: pointer.id.clone(),
            rule_id: record.finding.pattern_name,
            description: record.finding.description,
            severity: record.finding.severity,
            spans: record.finding.evidence,
        });
    }
    Ok(ReportOccurrence {
        id: occurrence.id.clone(),
        location: occurrence.location.clone(),
        primary: occurrence.primary.clone(),
        evidence,
    })
}

fn normalized_path(path: &Path) -> Result<String, RedflagError> {
    let mut names = Vec::new();
    for component in path.components() {
        match component {
            Component::Normal(name) => names.push(
                name.to_str()
                    .ok_or_else(|| invalid("Report paths must be UTF-8"))?,
            ),
            Component::CurDir => {}
            _ => {
                return Err(invalid(
                    "Report locations must stay inside their selected root",
                ))
            }
        }
    }
    Ok(if names.is_empty() {
        ".".into()
    } else {
        names.join("/")
    })
}

fn identity(kind: &str, value: &impl Serialize) -> Result<String, RedflagError> {
    Ok(format!(
        "rf-{kind}-v1:{}",
        digest(&serde_json::to_vec(value)?)
    ))
}
fn valid_span(s: &FindingSpan) -> bool {
    s.start_line > 0
        && s.start_column > 0
        && (s.end_line, s.end_column) >= (s.start_line, s.start_column)
}
fn nested(a: &FindingSpan, b: &FindingSpan) -> bool {
    let contains = |a: &FindingSpan, b: &FindingSpan| {
        (a.start_line, a.start_column) <= (b.start_line, b.start_column)
            && (a.end_line, a.end_column) >= (b.end_line, b.end_column)
    };
    contains(a, b) || contains(b, a)
}
fn intersection(a: &FindingSpan, b: &FindingSpan) -> FindingSpan {
    let start = (a.start_line, a.start_column).max((b.start_line, b.start_column));
    let end = (a.end_line, a.end_column).min((b.end_line, b.end_column));
    FindingSpan {
        start_line: start.0,
        start_column: start.1,
        end_line: end.0,
        end_column: end.1,
    }
}
fn maximum_severity(a: Severity, b: Severity) -> Severity {
    let rank = |s| match s {
        Severity::Critical => 0,
        Severity::High => 1,
        Severity::Medium => 2,
        Severity::Low => 3,
    };
    if rank(a) <= rank(b) {
        a
    } else {
        b
    }
}
fn clean_text(value: &str) -> String {
    value
        .chars()
        .flat_map(|c| {
            if c.is_control() {
                c.escape_default().collect::<Vec<_>>()
            } else {
                vec![c]
            }
        })
        .collect()
}
fn invalid(message: &str) -> RedflagError {
    RedflagError::Incomplete(message.into())
}
