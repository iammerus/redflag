//! Versioned, grouped reports. Private grouping material never reaches rendering.
use crate::{
    artifacts::{digest, file_path, ArtifactCoverage},
    config::{ScanLimits, Severity},
    error::RedflagError,
    exceptions::{
        AcceptedArtifact, ArtifactApproval, Audit as ExceptionAudit, Policy as ExceptionPolicy,
        Review, ReviewStatus,
    },
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
mod github;

#[derive(clap::ValueEnum, Clone, Debug, PartialEq, Eq)]
pub(crate) enum ReportFormat {
    Text,
    Json,
    Github,
}

#[derive(clap::Args)]
pub(crate) struct ReportArgs {
    #[arg(short, long, value_enum, default_value = "text")]
    pub format: ReportFormat,
    /// Append a GitHub job summary here instead of GITHUB_STEP_SUMMARY
    #[arg(long, value_name = "FILE")]
    pub github_summary: Option<PathBuf>,
}

pub(crate) trait ReportCoverage: Serialize {
    fn summary_facts(&self) -> Vec<(&'static str, String)>;
}

pub(crate) struct ReportHandler {
    format: ReportFormat,
    github_summary: Option<PathBuf>,
    spool: BufWriter<File>,
    count: usize,
    bytes: usize,
    max_findings: usize,
}

pub(crate) struct PreparedReport {
    format: ReportFormat,
    github_summary: Option<PathBuf>,
    reader: BufReader<File>,
    count: usize,
    total: usize,
    context: ReportContext,
    groups: Vec<PreparedGroup>,
    exception_audit: ExceptionAudit,
}

#[derive(Serialize, Deserialize)]
struct StoredFinding {
    finding: Finding,
    grouping_key: String,
}

pub(crate) struct ReportContext {
    mode: &'static str,
    artifacts: BTreeMap<PathBuf, ArtifactLocation>,
    source_root: Option<PathBuf>,
    protected_paths: Vec<PathBuf>,
}

struct ArtifactLocation {
    target: usize,
    path: String,
    version: String,
}

impl ReportContext {
    pub fn source(root: PathBuf) -> Self {
        Self {
            mode: "changes",
            artifacts: BTreeMap::new(),
            source_root: Some(root),
            protected_paths: Vec::new(),
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
            source_root: None,
            protected_paths: coverage.targets.iter().map(|t| t.root.clone()).collect(),
        })
    }

    pub fn protect_output(&mut self, path: Option<&Path>) {
        if let Some(path) = path {
            self.protected_paths.push(path.to_path_buf());
        }
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
                representation: finding.representation.clone(),
                archive: finding.archive.clone(),
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
                    representation: finding.representation.clone(),
                    archive: finding.archive.clone(),
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
    #[serde(skip_serializing_if = "Vec::is_empty")]
    pub representation: Vec<crate::decoding::Step>,
    #[serde(skip_serializing_if = "Vec::is_empty")]
    pub archive: Vec<crate::archives::Member>,
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
    review: Option<Review>,
}

impl PhysicalOccurrence {
    fn accepted(&self) -> bool {
        self.review
            .as_ref()
            .is_some_and(|r| r.status == ReviewStatus::Accepted)
    }
    fn status(&self) -> &'static str {
        if self.accepted() {
            "accepted"
        } else {
            "blocking"
        }
    }
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
    blocking_occurrence_count: usize,
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
    pub status: &'static str,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub exception: Option<Review>,
}

impl ReportHandler {
    pub fn new(args: ReportArgs, limits: &ScanLimits) -> Result<Self, RedflagError> {
        let github_summary = match args.format {
            ReportFormat::Github => Some(
                args.github_summary
                    .or_else(|| std::env::var_os("GITHUB_STEP_SUMMARY").map(PathBuf::from))
                    .filter(|p| !p.as_os_str().is_empty())
                    .ok_or_else(|| {
                        RedflagError::Config(
                            "GitHub format requires --github-summary FILE or GITHUB_STEP_SUMMARY"
                                .into(),
                        )
                    })?,
            ),
            _ if args.github_summary.is_some() => {
                return Err(RedflagError::Config(
                    "--github-summary requires --format github".into(),
                ))
            }
            _ => None,
        };
        Ok(Self {
            format: args.format,
            github_summary,
            spool: BufWriter::new(tempfile::tempfile()?),
            count: 0,
            bytes: 0,
            max_findings: limits.max_findings,
        })
    }

    pub fn finish_report(
        self,
        context: ReportContext,
        coverage: &impl ReportCoverage,
        policy: ExceptionPolicy,
    ) -> Result<u8, RedflagError> {
        self.prepare_report(context, policy)?.write(coverage)
    }

    pub fn prepare_report(
        mut self,
        context: ReportContext,
        policy: ExceptionPolicy,
    ) -> Result<PreparedReport, RedflagError> {
        policy.validate_mode(context.mode)?;
        self.spool.flush()?;
        self.spool.get_mut().rewind()?;
        let file = self.spool.into_inner().map_err(|e| e.into_error())?;
        let mut reader = BufReader::new(file);
        let mut groups = prepare(&mut reader, &context)?;
        let exception_audit = apply_reviews(&mut groups, policy)?;
        let total = groups.iter().map(|g| g.occurrences.len()).sum::<usize>();
        Ok(PreparedReport {
            format: self.format,
            github_summary: self.github_summary,
            reader,
            count: self.count,
            total,
            context,
            groups,
            exception_audit,
        })
    }
}

impl PreparedReport {
    pub fn exit_code(&self) -> u8 {
        u8::from(self.total > self.exception_audit.accepted_occurrences)
    }

    pub fn artifact_approval(&self) -> Result<(usize, ArtifactApproval), RedflagError> {
        if self.context.mode != "artifacts" || self.exit_code() != 0 {
            return Err(invalid("Only a complete artifact report without blockers can authorize a publication manifest"));
        }
        let mut occurrences = Vec::new();
        for group in &self.groups {
            for occurrence in &group.occurrences {
                occurrences.push(AcceptedArtifact {
                    occurrence_id: occurrence.id.clone(),
                    target: occurrence
                        .location
                        .target
                        .ok_or_else(|| invalid("Reviewed artifact occurrence has no target"))?,
                    path: PathBuf::from(&occurrence.location.path),
                    file_sha256: occurrence.location.version.clone(),
                    review: occurrence
                        .review
                        .clone()
                        .ok_or_else(|| invalid("Publication occurrence has no accepted review"))?,
                });
            }
        }
        Ok((
            self.count,
            ArtifactApproval {
                policy: self.exception_audit.clone(),
                occurrences,
            },
        ))
    }

    pub fn write(self, coverage: &impl ReportCoverage) -> Result<u8, RedflagError> {
        let mut reader = self.reader;
        let context = self.context;
        let groups = self.groups;
        let exception_audit = self.exception_audit;
        let total = self.total;
        let blocking = total - exception_audit.accepted_occurrences;
        let exit = u8::from(blocking > 0);
        if let Some(path) = self.github_summary {
            github::render(
                &groups,
                &context,
                &mut reader,
                coverage,
                &path,
                self.count,
                &exception_audit,
            )?;
            return Ok(exit);
        }
        let stdout = io::stdout();
        let mut writer = BufWriter::new(stdout.lock());
        match self.format {
            ReportFormat::Json => {
                #[derive(Serialize)]
                struct Header<'a, T> {
                    schema_version: u32,
                    mode: &'a str,
                    complete: bool,
                    scanner_version: &'static str,
                    findings_count: usize,
                    logical_findings_count: usize,
                    occurrences_count: usize,
                    blocking_occurrences_count: usize,
                    accepted_occurrences_count: usize,
                    exception_policy: &'a ExceptionAudit,
                    identity_schema: &'static str,
                    coverage: &'a T,
                }
                let header = Header {
                    schema_version: 3,
                    mode: context.mode,
                    complete: true,
                    scanner_version: env!("CARGO_PKG_VERSION"),
                    findings_count: self.count,
                    logical_findings_count: groups.len(),
                    occurrences_count: total,
                    blocking_occurrences_count: blocking,
                    accepted_occurrences_count: exception_audit.accepted_occurrences,
                    exception_policy: &exception_audit,
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
            ReportFormat::Text => {
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
                        if !occurrence.location.archive.is_empty() {
                            writeln!(
                                writer,
                                "    Archive member: {}",
                                clean_text(&crate::archives::label(&occurrence.location.archive))
                            )?;
                        }
                        if !occurrence.location.representation.is_empty() {
                            writeln!(
                                writer,
                                "    Representation: {}",
                                crate::decoding::label(&occurrence.location.representation)
                            )?;
                        }
                        writeln!(writer, "    Status: {}", occurrence.status())?;
                        if let Some(review) = &occurrence.review {
                            writeln!(
                                writer,
                                "    Exception: {} (reviewed by {}; expires {})",
                                clean_text(&review.reason),
                                clean_text(&review.reviewed_by),
                                clean_text(&review.expires_at)
                            )?;
                            if review.status == ReviewStatus::Expired {
                                writeln!(
                                    writer,
                                    "    This exception has expired; the occurrence blocks."
                                )?;
                            } else if review.status == ReviewStatus::RejectedPrivateValue {
                                writeln!(writer, "    This exception cannot authorize a declared private value; the occurrence blocks.")?;
                            }
                        }
                    }
                    writeln!(writer, "  {}", header.remediation)?;
                }
                writeln!(
                    writer,
                    "{} inspection complete: {} logical finding(s), {} occurrence(s); {} blocking, {} accepted by review.",
                    context.mode,
                    groups.len(),
                    total, blocking, exception_audit.accepted_occurrences
                )?;
            }
            ReportFormat::Github => unreachable!("GitHub summary is prepared in new"),
        }
        writer.flush()?;
        Ok(exit)
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
            || finding
                .representation
                .iter()
                .any(|step| !valid_span(&step.encoded) || !valid_span(&step.decoded))
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
                    review: None,
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
            blocking_occurrence_count: self.occurrences.iter().filter(|o| !o.accepted()).count(),
            remediation: if self.occurrences.iter().all(PhysicalOccurrence::accepted) {
                "Revisit the reviewed exception before expiry. Acceptance does not establish revocation."
            } else if mode == "changes" {
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
        status: occurrence.status(),
        exception: occurrence.review.clone(),
    })
}

fn apply_reviews(
    groups: &mut [PreparedGroup],
    policy: ExceptionPolicy,
) -> Result<ExceptionAudit, RedflagError> {
    let now = chrono::Utc::now();
    let mut seen = BTreeSet::new();
    let mut matched = BTreeSet::new();
    let mut accepted = 0;
    let mut rejected_private = 0;
    for group in groups {
        for occurrence in &mut group.occurrences {
            if !seen.insert(occurrence.id.clone()) {
                return Err(invalid("Multiple logical candidates share an occurrence identity; review ambiguous detector evidence"));
            }
            occurrence.review = policy.review(&occurrence.id, now);
            if !group.private_env.is_empty() {
                if let Some(review) = &mut occurrence.review {
                    review.status = ReviewStatus::RejectedPrivateValue;
                    rejected_private += 1;
                }
            }
            if occurrence.review.is_some() {
                matched.insert(occurrence.id.clone());
            }
            if occurrence.accepted() {
                accepted += 1;
            }
        }
    }
    Ok(policy.audit(now, &matched, accepted, rejected_private))
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
pub(crate) fn escape_terminal(value: &str) -> String {
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
fn clean_text(value: &str) -> String {
    escape_terminal(value)
}
fn invalid(message: &str) -> RedflagError {
    RedflagError::Incomplete(message.into())
}
