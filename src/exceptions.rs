//! Reviewed, occurrence-scoped policy. Loading establishes provenance; matching
//! never treats a credential value or a logical group as a global exception.
use crate::{artifacts::digest, error::RedflagError};
use chrono::{DateTime, SecondsFormat, Utc};
use serde::{Deserialize, Serialize};
use std::{
    collections::{BTreeMap, BTreeSet},
    fs::File,
    io::Read,
    path::{Path, PathBuf},
};

const POLICY_FILE: &str = "redflag-exceptions.json";
const MAX_POLICY_BYTES: usize = 1024 * 1024;
pub(crate) const MAX_ENTRIES: usize = 10_000;

#[derive(clap::Args)]
pub(crate) struct ExceptionArgs {
    /// Read reviewed occurrence exceptions from this explicitly trusted file
    #[arg(long, value_name = "FILE", conflicts_with = "no_exceptions")]
    exceptions: Option<PathBuf>,
    /// Apply no occurrence exceptions
    #[arg(long)]
    no_exceptions: bool,
}

impl ExceptionArgs {
    pub fn path(&self) -> Option<&Path> {
        self.exceptions.as_deref()
    }
}

#[derive(Clone, Copy, Deserialize, Serialize, PartialEq, Eq)]
#[serde(rename_all = "snake_case")]
pub(crate) enum ExceptionKind {
    FalsePositive,
    AcceptedDebt,
}

#[derive(Deserialize)]
#[serde(deny_unknown_fields)]
struct PolicyFile {
    schema_version: u32,
    mode: String,
    exceptions: Vec<Entry>,
}

#[derive(Clone, Deserialize, Serialize)]
#[serde(deny_unknown_fields)]
struct Entry {
    occurrence_id: String,
    kind: ExceptionKind,
    reason: String,
    reviewed_by: String,
    expires_at: String,
}

struct ValidatedEntry {
    entry: Entry,
    expires: DateTime<Utc>,
}

pub(crate) struct Policy {
    mode: &'static str,
    origin: String,
    sha256: Option<String>,
    entries: BTreeMap<String, ValidatedEntry>,
}

#[derive(Clone, Copy, Serialize, Deserialize, PartialEq, Eq)]
#[serde(rename_all = "snake_case")]
pub(crate) enum ReviewStatus {
    Accepted,
    Expired,
    RejectedPrivateValue,
}

#[derive(Clone, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub(crate) struct Review {
    pub status: ReviewStatus,
    pub kind: ExceptionKind,
    pub reason: String,
    pub reviewed_by: String,
    pub expires_at: String,
}

#[derive(Clone, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub(crate) struct Audit {
    pub mode: String,
    pub origin: String,
    pub sha256: Option<String>,
    pub evaluated_at: String,
    pub entry_count: usize,
    pub matched_entries: usize,
    pub unmatched_entries: usize,
    pub expired_entries: usize,
    pub accepted_occurrences: usize,
    pub rejected_private_occurrences: usize,
}

#[derive(Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub(crate) struct ArtifactApproval {
    pub policy: Audit,
    pub occurrences: Vec<AcceptedArtifact>,
}

#[derive(Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub(crate) struct AcceptedArtifact {
    pub occurrence_id: String,
    pub target: usize,
    pub path: PathBuf,
    pub file_sha256: String,
    pub review: Review,
}

impl Policy {
    pub fn disabled(mode: &'static str, origin: impl Into<String>) -> Self {
        Self {
            mode,
            origin: origin.into(),
            sha256: None,
            entries: BTreeMap::new(),
        }
    }

    pub fn load_source(
        repo: &git2::Repository,
        revision: Option<git2::Oid>,
        args: &ExceptionArgs,
    ) -> Result<Self, RedflagError> {
        if args.no_exceptions {
            return Ok(Self::disabled("changes", "disabled by --no-exceptions"));
        }
        if let Some(path) = &args.exceptions {
            return Self::read_file(path, "changes");
        }
        let Some(revision) = revision else {
            return Ok(Self::disabled("changes", "no trusted policy revision"));
        };
        let tree = repo.find_commit(revision)?.tree()?;
        let entry = match tree.get_path(Path::new(POLICY_FILE)) {
            Ok(entry) => entry,
            Err(error) if error.code() == git2::ErrorCode::NotFound => {
                return Ok(Self::disabled(
                    "changes",
                    format!("no {POLICY_FILE} at {revision}"),
                ))
            }
            Err(error) => return Err(error.into()),
        };
        if !matches!(entry.filemode(), 0o100644 | 0o100755) {
            return Err(invalid(
                "Trusted redflag-exceptions.json must be a regular Git blob",
            ));
        }
        let (size, kind) = repo.odb()?.read_header(entry.id())?;
        if kind != git2::ObjectType::Blob || size > MAX_POLICY_BYTES {
            return Err(invalid(
                "Trusted exception policy exceeds 1 MiB or is not a blob",
            ));
        }
        let blob = repo.find_blob(entry.id())?;
        Self::parse(
            blob.content(),
            format!("git:{revision}:{POLICY_FILE}"),
            "changes",
        )
    }

    pub fn load_artifacts(args: &ExceptionArgs) -> Result<Self, RedflagError> {
        if let Some(path) = &args.exceptions {
            return Self::read_file(path, "artifacts");
        }
        Ok(Self::disabled(
            "artifacts",
            if args.no_exceptions {
                "disabled by --no-exceptions"
            } else {
                "no explicit artifact exception policy; source baselines do not apply"
            },
        ))
    }

    fn read_file(path: &Path, mode: &'static str) -> Result<Self, RedflagError> {
        // Opening a FIFO can block before File::metadata is available.
        let metadata = std::fs::metadata(path)?;
        if !metadata.is_file() || metadata.len() > MAX_POLICY_BYTES as u64 {
            return Err(invalid(
                "Exception policy must be a regular file of at most 1 MiB",
            ));
        }
        let mut file = File::open(path)?;
        let metadata = file.metadata()?;
        if !metadata.is_file() || metadata.len() > MAX_POLICY_BYTES as u64 {
            return Err(invalid(
                "Exception policy must be a regular file of at most 1 MiB",
            ));
        }
        let mut bytes = Vec::new();
        file.by_ref()
            .take(MAX_POLICY_BYTES as u64 + 1)
            .read_to_end(&mut bytes)?;
        Self::parse(
            &bytes,
            format!("file:{}", std::fs::canonicalize(path)?.display()),
            mode,
        )
    }

    pub fn redact_metadata(&mut self, private: &crate::protected_values::ProtectedValues) {
        let redact = |value: &mut String| {
            if private.contains(value) {
                *value = "[REDACTED PRIVATE VALUE]".into();
            }
        };
        redact(&mut self.origin);
        for entry in self.entries.values_mut() {
            redact(&mut entry.entry.reason);
            redact(&mut entry.entry.reviewed_by);
        }
    }

    fn parse(bytes: &[u8], origin: String, mode: &'static str) -> Result<Self, RedflagError> {
        if bytes.len() > MAX_POLICY_BYTES {
            return Err(invalid("Exception policy exceeds 1 MiB"));
        }
        let policy: PolicyFile = serde_json::from_slice(bytes).map_err(|error|
            invalid(&format!("Invalid exception policy JSON at line {}, column {}; check required fields and remove unknown fields", error.line(), error.column())))?;
        if policy.schema_version != 1 || policy.mode != mode {
            return Err(invalid(&format!("Exception policy requires schema_version 1 and mode {mode}; source baselines cannot authorize artifact publication")));
        }
        if policy.exceptions.len() > MAX_ENTRIES {
            return Err(invalid("Exception policy exceeds 10000 entries"));
        }
        let mut entries = BTreeMap::new();
        for entry in policy.exceptions {
            if mode == "artifacts" && entry.kind != ExceptionKind::FalsePositive {
                return Err(invalid("Artifact exceptions must be reviewed false positives; accepted source debt cannot authorize publication"));
            }
            if !valid_occurrence_id(&entry.occurrence_id) {
                return Err(invalid("Exceptions require an exact rf-occurrence-v1 ID; groups, values and glob patterns are not accepted"));
            }
            let expires =
                validate_review_fields(&entry.reason, &entry.reviewed_by, &entry.expires_at)?;
            let key = entry.occurrence_id.clone();
            if entries
                .insert(key, ValidatedEntry { entry, expires })
                .is_some()
            {
                return Err(invalid(
                    "Exception policy contains duplicate occurrence IDs",
                ));
            }
        }
        Ok(Self {
            mode,
            origin,
            sha256: Some(digest(bytes)),
            entries,
        })
    }

    pub fn review(&self, occurrence: &str, now: DateTime<Utc>) -> Option<Review> {
        let validated = self.entries.get(occurrence)?;
        let entry = &validated.entry;
        Some(Review {
            status: if validated.expires > now {
                ReviewStatus::Accepted
            } else {
                ReviewStatus::Expired
            },
            kind: entry.kind,
            reason: entry.reason.clone(),
            reviewed_by: entry.reviewed_by.clone(),
            expires_at: entry.expires_at.clone(),
        })
    }

    pub fn validate_mode(&self, mode: &str) -> Result<(), RedflagError> {
        if self.mode != mode {
            return Err(invalid("Exception policy mode does not match the inspection; source baselines cannot authorize artifact publication"));
        }
        Ok(())
    }

    pub fn audit(
        self,
        now: DateTime<Utc>,
        matched: &BTreeSet<String>,
        accepted_occurrences: usize,
        rejected_private_occurrences: usize,
    ) -> Audit {
        Audit {
            mode: self.mode.into(),
            origin: self.origin,
            sha256: self.sha256,
            evaluated_at: now.to_rfc3339_opts(SecondsFormat::Secs, true),
            entry_count: self.entries.len(),
            matched_entries: matched.len(),
            unmatched_entries: self.entries.len().saturating_sub(matched.len()),
            expired_entries: self.entries.values().filter(|e| e.expires <= now).count(),
            accepted_occurrences,
            rejected_private_occurrences,
        }
    }
}

pub(crate) fn valid_occurrence_id(value: &str) -> bool {
    value.strip_prefix("rf-occurrence-v1:").is_some_and(|hash| {
        hash.len() == 64
            && hash
                .bytes()
                .all(|b| b.is_ascii_digit() || (b'a'..=b'f').contains(&b))
    })
}

pub(crate) fn validate_review_fields(
    reason: &str,
    reviewed_by: &str,
    expires_at: &str,
) -> Result<DateTime<Utc>, RedflagError> {
    if reason.trim().is_empty()
        || reason.len() > 1024
        || reviewed_by.trim().is_empty()
        || reviewed_by.len() > 256
    {
        return Err(invalid(
            "Each exception requires a reason (1–1024 bytes) and reviewed_by (1–256 bytes)",
        ));
    }
    DateTime::parse_from_rfc3339(expires_at)
        .map(|time| time.with_timezone(&Utc))
        .map_err(|_| {
            invalid("Exception expires_at must be a complete RFC 3339 timestamp with a timezone")
        })
}
fn invalid(message: &str) -> RedflagError {
    RedflagError::Config(message.into())
}

#[cfg(test)]
mod tests {
    use super::*;
    fn entry(id: &str) -> serde_json::Value {
        serde_json::json!({"occurrence_id": id, "kind":"accepted_debt", "reason":"Tracked source debt", "reviewed_by":"security-team", "expires_at":"2026-09-12T12:00:00Z"})
    }
    fn policy(entries: Vec<serde_json::Value>) -> Result<Policy, RedflagError> {
        Policy::parse(
            &serde_json::to_vec(
                &serde_json::json!({"schema_version":1,"mode":"changes","exceptions":entries}),
            )
            .unwrap(),
            "fixture".into(),
            "changes",
        )
    }
    #[test]
    fn expiry_is_exclusive_and_unmatched_records_remain_visible_in_audit() {
        let id = format!("rf-occurrence-v1:{}", "a".repeat(64));
        let other = format!("rf-occurrence-v1:{}", "b".repeat(64));
        let policy = policy(vec![entry(&id), entry(&other)]).unwrap();
        let now = DateTime::parse_from_rfc3339("2026-09-12T12:00:00Z")
            .unwrap()
            .with_timezone(&Utc);
        assert!(
            policy
                .review(&id, now - chrono::Duration::seconds(1))
                .unwrap()
                .status
                == ReviewStatus::Accepted
        );
        assert!(policy.review(&id, now).unwrap().status == ReviewStatus::Expired);
        assert!(policy.review("unknown", now).is_none());
        let audit = policy.audit(now, &BTreeSet::from([id]), 0, 0);
        assert_eq!(audit.unmatched_entries, 1);
        assert_eq!(audit.expired_entries, 2);
    }
    #[test]
    fn policy_rejects_duplicate_broad_and_ungoverned_entries() {
        let id = format!("rf-occurrence-v1:{}", "a".repeat(64));
        assert!(policy(vec![entry(&id), entry(&id)]).is_err());
        for bad_id in [
            "*",
            "rf-group-v1:abc",
            "value:example",
            "rf-occurrence-v1:short",
        ] {
            assert!(policy(vec![entry(bad_id)]).is_err());
        }
        for (key, value) in [
            ("reason", " "),
            ("reviewed_by", ""),
            ("expires_at", "2026-10-01"),
            ("kind", "ignore_forever"),
        ] {
            let mut invalid = entry(&id);
            invalid[key] = value.into();
            assert!(policy(vec![invalid]).is_err());
        }
        let mut invalid = entry(&id);
        invalid["path"] = "**".into();
        assert!(policy(vec![invalid]).is_err());
    }
}
