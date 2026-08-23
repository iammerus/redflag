//! Prove historical debt from parent detector evidence and one-to-one byte mapping.
//! Values are never hashed into public identities or written to the finding spool.
use crate::{
    config::ScanLimits,
    engine::GeneralEngine,
    error::RedflagError,
    scanner::{CommitMetadata, Finding, FindingHandler, FindingSpan, Scanner},
};
use git2::{Blob, Oid, Repository};
use serde::{Deserialize, Serialize};
use similar::{capture_diff_slices_deadline, Algorithm, DiffOp};
use std::{
    collections::{BTreeMap, BTreeSet},
    fs::File,
    io::{BufRead, BufReader, BufWriter, Seek, Write},
    path::{Path, PathBuf},
    time::{Duration, Instant},
};

const MAX_SPOOL_BYTES: usize = 64 * 1024 * 1024;

pub(crate) struct SourceOccurrences<'repo> {
    repo: &'repo Repository,
    limits: ScanLimits,
    snapshots: Vec<Snapshot>,
    index: BTreeMap<(String, PathBuf), usize>,
    revisions: BTreeMap<usize, Vec<Option<usize>>>,
    spool: BufWriter<File>,
    spool_bytes: usize,
    count: usize,
    locations: Option<(usize, Blob<'repo>, LineLookup)>,
}

struct Snapshot {
    blob: Oid,
    occurrences: BTreeSet<Occurrence>,
}

#[derive(PartialEq, Eq, PartialOrd, Ord, Serialize, Deserialize)]
struct Occurrence {
    rule: String,
    spans: Vec<ByteSpan>,
}

#[derive(Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Serialize, Deserialize)]
struct ByteSpan {
    start: usize,
    end: usize,
}

#[derive(Serialize, Deserialize)]
struct Record {
    snapshot: usize,
    occurrence: Occurrence,
    finding: Finding,
}

#[derive(Serialize)]
pub(crate) struct OccurrenceCoverage {
    snapshots: usize,
    detector_occurrences: usize,
    existing_parent_occurrences: usize,
    finding_spool_bytes: usize,
}

impl<'repo> SourceOccurrences<'repo> {
    pub fn new(repo: &'repo Repository, limits: &ScanLimits) -> Result<Self, RedflagError> {
        Ok(Self {
            repo,
            limits: limits.clone(),
            snapshots: Vec::new(),
            index: BTreeMap::new(),
            revisions: BTreeMap::new(),
            spool: BufWriter::new(tempfile::tempfile()?),
            spool_bytes: 0,
            count: 0,
            locations: None,
        })
    }

    pub fn add_revision(
        &mut self,
        path: &Path,
        commit: CommitMetadata,
        blob: &Blob<'_>,
        parents: &[(CommitMetadata, Option<Oid>)],
        scanner: &Scanner,
        engine: &mut GeneralEngine,
    ) -> Result<(), RedflagError> {
        let child = self.snapshot(path, commit, blob, scanner, engine)?;
        let mut previous = Vec::new();
        for (metadata, oid) in parents {
            previous.push(match oid {
                Some(oid) => {
                    let blob = self.repo.find_blob(*oid)?;
                    Some(self.snapshot(path, metadata.clone(), &blob, scanner, engine)?)
                }
                None => None,
            });
        }
        self.revisions.insert(child, previous);
        Ok(())
    }

    fn snapshot(
        &mut self,
        path: &Path,
        commit: CommitMetadata,
        blob: &Blob<'_>,
        scanner: &Scanner,
        engine: &mut GeneralEngine,
    ) -> Result<usize, RedflagError> {
        let key = (commit.hash.clone(), path.to_path_buf());
        if let Some(&index) = self.index.get(&key) {
            return Ok(index);
        }
        if self.snapshots.len() >= self.limits.max_files {
            return Err(RedflagError::Incomplete(
                "Source and parent snapshots exceed limits.max_files".into(),
            ));
        }
        let index = self.snapshots.len();
        self.index.insert(key, index);
        self.snapshots.push(Snapshot {
            blob: blob.id(),
            occurrences: BTreeSet::new(),
        });
        engine.add_snapshot(path, blob.content(), Some(commit.clone()))?;
        let mut handler = CommitFindings {
            store: self,
            commit,
        };
        for (line, bytes) in blob.content().split(|&b| b == b'\n').enumerate() {
            scanner.scan_artifact_line(path, line + 1, bytes, &mut handler)?;
        }
        Ok(index)
    }

    pub fn emit_introduced<H: FindingHandler>(
        mut self,
        handler: &mut H,
    ) -> Result<OccurrenceCoverage, RedflagError> {
        let mut coverage = OccurrenceCoverage {
            snapshots: self.snapshots.len(),
            detector_occurrences: self.count,
            existing_parent_occurrences: 0,
            finding_spool_bytes: self.spool_bytes,
        };
        self.locations = None;
        self.spool.flush()?;
        self.spool.get_mut().rewind()?;
        let file = self.spool.into_inner().map_err(|e| e.into_error())?;
        let mut reader = BufReader::new(file);
        let mut line = String::new();
        let mut cache: Option<(usize, BTreeMap<usize, EqualBytes>)> = None;
        let deadline = Instant::now()
            .checked_add(Duration::from_secs(self.limits.diff_timeout_seconds))
            .ok_or_else(|| {
                RedflagError::Config("Source comparison time limit is too large".into())
            })?;
        loop {
            line.clear();
            if reader.read_line(&mut line)? == 0 {
                break;
            }
            let record: Record = serde_json::from_str(&line)?;
            let Some(parents) = self.revisions.get(&record.snapshot) else {
                continue;
            };
            if cache.as_ref().is_none_or(|(id, _)| *id != record.snapshot) {
                cache = Some((record.snapshot, BTreeMap::new()));
            }
            let (_, maps) = cache.as_mut().expect("initialized above");
            let mut existing = false;
            for &parent in parents.iter().flatten() {
                if self.snapshots[parent].occurrences.is_empty() {
                    continue;
                }
                if let std::collections::btree_map::Entry::Vacant(entry) = maps.entry(parent) {
                    let old = self.repo.find_blob(self.snapshots[parent].blob)?;
                    let new = self.repo.find_blob(self.snapshots[record.snapshot].blob)?;
                    entry.insert(EqualBytes::between(
                        old.content(),
                        new.content(),
                        &self.limits,
                        deadline,
                    )?);
                }
                let mapped: Option<Vec<_>> = record
                    .occurrence
                    .spans
                    .iter()
                    .map(|span| maps[&parent].map(*span))
                    .collect();
                if let Some(spans) = mapped {
                    let occurrence = Occurrence {
                        rule: record.occurrence.rule.clone(),
                        spans,
                    };
                    if self.snapshots[parent].occurrences.contains(&occurrence) {
                        existing = true;
                        break;
                    }
                }
            }
            if existing {
                coverage.existing_parent_occurrences += 1;
            } else {
                handler.handle(record.finding)?;
            }
        }
        Ok(coverage)
    }
}

impl FindingHandler for SourceOccurrences<'_> {
    fn handle(&mut self, finding: Finding) -> Result<(), RedflagError> {
        let hash = finding
            .commit_hash
            .as_ref()
            .ok_or_else(|| RedflagError::Incomplete("Git finding has no commit".into()))?;
        let snapshot = *self
            .index
            .get(&(hash.clone(), finding.file.clone()))
            .ok_or_else(|| {
                RedflagError::Incomplete("Git finding has no inspected snapshot".into())
            })?;
        if self
            .locations
            .as_ref()
            .is_none_or(|(index, _, _)| *index != snapshot)
        {
            let blob = self.repo.find_blob(self.snapshots[snapshot].blob)?;
            let lookup = LineLookup::new(blob.content());
            self.locations = Some((snapshot, blob, lookup));
        }
        let (_, blob, lookup) = self.locations.as_mut().expect("initialized above");
        if finding.evidence.is_empty() {
            return Err(RedflagError::Incomplete(
                "Git finding has no location evidence".into(),
            ));
        }
        let mut spans = finding
            .evidence
            .iter()
            .map(|span| lookup.span(blob.content(), span))
            .collect::<Result<Vec<_>, _>>()?;
        spans.sort();
        spans.dedup();
        let occurrence = Occurrence {
            rule: finding.pattern_name.clone(),
            spans,
        };
        if self.snapshots[snapshot].occurrences.contains(&occurrence) {
            return Ok(());
        }
        if self.count >= self.limits.max_findings {
            return Err(RedflagError::Incomplete(
                "Source and parent findings exceed limits.max_findings".into(),
            ));
        }
        let record = Record {
            snapshot,
            occurrence,
            finding,
        };
        let bytes = serde_json::to_vec(&record)?;
        if bytes.len() + 1 > MAX_SPOOL_BYTES.saturating_sub(self.spool_bytes) {
            return Err(RedflagError::Incomplete(
                "Source and parent finding spool exceeds 64 MiB".into(),
            ));
        }
        self.spool.write_all(&bytes)?;
        self.spool.write_all(b"\n")?;
        self.spool_bytes += bytes.len() + 1;
        self.count += 1;
        self.snapshots[snapshot]
            .occurrences
            .insert(record.occurrence);
        Ok(())
    }
}

struct CommitFindings<'a, 'repo> {
    store: &'a mut SourceOccurrences<'repo>,
    commit: CommitMetadata,
}
impl FindingHandler for CommitFindings<'_, '_> {
    fn handle(&mut self, mut finding: Finding) -> Result<(), RedflagError> {
        finding.commit_hash = Some(self.commit.hash.clone());
        finding.commit_author = Some(self.commit.author.clone());
        finding.commit_date = Some(self.commit.date.clone());
        self.store.handle(finding)
    }
}

/// A checkpoint every 128 lines avoids an offset allocation for every byte of a
/// newline-heavy blob. Only one snapshot's lookup is retained during detection.
struct LineLookup {
    checkpoints: Vec<usize>,
    bounds: BTreeMap<usize, (usize, usize)>,
}
impl LineLookup {
    fn new(bytes: &[u8]) -> Self {
        let mut checkpoints = vec![0];
        let mut line = 0;
        for (index, &byte) in bytes.iter().enumerate() {
            if byte == b'\n' {
                line += 1;
                if line % 128 == 0 {
                    checkpoints.push(index + 1);
                }
            }
        }
        Self {
            checkpoints,
            bounds: BTreeMap::new(),
        }
    }
    fn offset(&mut self, bytes: &[u8], line: usize, column: usize) -> Result<usize, RedflagError> {
        let zero = line.checked_sub(1).ok_or_else(location_error)?;
        let (start, end) = *match self.bounds.entry(zero) {
            std::collections::btree_map::Entry::Occupied(entry) => entry.into_mut(),
            std::collections::btree_map::Entry::Vacant(entry) => {
                let mut start = *self
                    .checkpoints
                    .get(zero / 128)
                    .ok_or_else(location_error)?;
                for _ in 0..zero % 128 {
                    start += bytes[start..]
                        .iter()
                        .position(|&b| b == b'\n')
                        .ok_or_else(location_error)?
                        + 1;
                }
                let end = bytes[start..]
                    .iter()
                    .position(|&b| b == b'\n')
                    .map_or(bytes.len(), |i| start + i + 1);
                entry.insert((start, end))
            }
        };
        start
            .checked_add(column)
            .filter(|&v| v <= end)
            .ok_or_else(location_error)
    }
    fn span(&mut self, bytes: &[u8], span: &FindingSpan) -> Result<ByteSpan, RedflagError> {
        let start = self.offset(
            bytes,
            span.start_line,
            span.start_column
                .checked_sub(1)
                .ok_or_else(location_error)?,
        )?;
        let end = self.offset(bytes, span.end_line, span.end_column)?;
        if start >= end {
            return Err(location_error());
        }
        Ok(ByteSpan { start, end })
    }
}

fn location_error() -> RedflagError {
    RedflagError::Incomplete("Detector evidence is outside the committed bytes".into())
}

struct EqualRun {
    old: usize,
    new: usize,
    len: usize,
}
struct EqualBytes {
    runs: Vec<EqualRun>,
}
impl EqualBytes {
    fn between(
        old: &[u8],
        new: &[u8],
        limits: &ScanLimits,
        deadline: Instant,
    ) -> Result<Self, RedflagError> {
        let prefix = old.iter().zip(new).take_while(|(a, b)| a == b).count();
        let suffix = old[prefix..]
            .iter()
            .rev()
            .zip(new[prefix..].iter().rev())
            .take_while(|(a, b)| a == b)
            .count();
        let a = &old[prefix..old.len() - suffix];
        let b = &new[prefix..new.len() - suffix];
        let mut result = Self { runs: Vec::new() };
        result.push(0, 0, prefix);
        if !a.is_empty() && !b.is_empty() {
            if a.len().saturating_add(b.len()) > limits.max_diff_bytes {
                return Err(RedflagError::Incomplete(
                    "Old-debt occurrence mapping exceeds limits.max_diff_bytes".into(),
                ));
            }
            if Instant::now() > deadline {
                return Err(diff_timeout());
            }
            let ops = capture_diff_slices_deadline(Algorithm::Myers, a, b, Some(deadline));
            // A deadline fallback is a coarse edit, not proof of exact mapping.
            if Instant::now() > deadline {
                return Err(diff_timeout());
            }
            for op in ops {
                if let DiffOp::Equal {
                    old_index,
                    new_index,
                    len,
                } = op
                {
                    result.push(prefix + old_index, prefix + new_index, len);
                }
            }
        }
        result.push(old.len() - suffix, new.len() - suffix, suffix);
        Ok(result)
    }
    fn push(&mut self, old: usize, new: usize, len: usize) {
        if len == 0 {
            return;
        }
        if let Some(last) = self
            .runs
            .last_mut()
            .filter(|r| r.old + r.len == old && r.new + r.len == new)
        {
            last.len += len;
        } else {
            self.runs.push(EqualRun { old, new, len });
        }
    }
    fn map(&self, span: ByteSpan) -> Option<ByteSpan> {
        let index = self
            .runs
            .partition_point(|r| r.new <= span.start)
            .checked_sub(1)?;
        let run = &self.runs[index];
        (span.end <= run.new + run.len).then_some(ByteSpan {
            start: run.old + span.start - run.new,
            end: run.old + span.end - run.new,
        })
    }
}

fn diff_timeout() -> RedflagError {
    RedflagError::Incomplete(
        "Old-debt occurrence mapping exceeded limits.diff_timeout_seconds".into(),
    )
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn expired_refinement_cannot_turn_a_coarse_edit_into_proven_old_debt() {
        let deadline = Instant::now() - Duration::from_secs(1);
        assert!(EqualBytes::between(
            b"old context",
            b"new context!",
            &ScanLimits::default(),
            deadline
        )
        .is_err());
    }

    #[test]
    fn deletion_inside_an_occurrence_is_not_an_unchanged_span() {
        let map = EqualBytes::between(
            b"abcXdef",
            b"abcdef",
            &ScanLimits::default(),
            Instant::now() + Duration::from_secs(1),
        )
        .unwrap();
        assert!(map.map(ByteSpan { start: 0, end: 6 }).is_none());
        assert!(map.map(ByteSpan { start: 0, end: 3 }).is_some());
    }
}
