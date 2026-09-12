//! Exact GitHub source scope without API access, branch-name guessing or shell evaluation.
use crate::{artifacts::digest, error::RedflagError};
use serde::Serialize;
use serde_json::Value;
use std::{fs::File, io::Read, path::Path};

const MAX_EVENT_BYTES: u64 = 25 * 1024 * 1024;

#[derive(Clone, Copy, Debug, clap::ValueEnum, Serialize)]
#[clap(rename_all = "snake_case")]
#[serde(rename_all = "snake_case")]
pub(crate) enum EventKind {
    PullRequest,
    Push,
    MergeGroup,
}

#[derive(Serialize)]
pub(crate) struct EventScope {
    pub kind: EventKind,
    pub payload_sha256: String,
    pub base: Option<String>,
    pub head: String,
    pub merge_result: Option<String>,
    pub new_branch: bool,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub pull_request: Option<u64>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub fork: Option<bool>,
}

impl EventScope {
    pub fn read(path: &Path, kind: Option<EventKind>) -> Result<Self, RedflagError> {
        let kind = match kind {
            Some(kind) => kind,
            None => match std::env::var("GITHUB_EVENT_NAME").as_deref() {
                Ok("pull_request") => EventKind::PullRequest,
                Ok("push") => EventKind::Push,
                Ok("merge_group") => EventKind::MergeGroup,
                _ => return Err(RedflagError::Config("Use --event-name pull_request, push or merge_group, or set GITHUB_EVENT_NAME. Other events require an explicit reviewed range.".into())),
            },
        };
        let file = File::open(path)?;
        if !file.metadata()?.is_file() {
            return Err(RedflagError::Config(
                "GitHub event input must be a regular file".into(),
            ));
        }
        let mut bytes = Vec::new();
        file.take(MAX_EVENT_BYTES + 1).read_to_end(&mut bytes)?;
        if bytes.len() as u64 > MAX_EVENT_BYTES {
            return Err(RedflagError::Config(
                "GitHub event input exceeds 25 MiB".into(),
            ));
        }
        Self::parse(&bytes, kind)
    }

    fn parse(bytes: &[u8], kind: EventKind) -> Result<Self, RedflagError> {
        let payload: Value = serde_json::from_slice(bytes).map_err(|_| invalid("event JSON"))?;
        let mut scope = Self {
            kind,
            payload_sha256: digest(bytes),
            base: None,
            head: String::new(),
            merge_result: None,
            new_branch: false,
            pull_request: None,
            fork: None,
        };
        match kind {
            EventKind::PullRequest => {
                if payload
                    .pointer("/pull_request/state")
                    .and_then(Value::as_str)
                    != Some("open")
                {
                    return Err(invalid("open pull_request.state"));
                }
                scope.base = Some(sha(&payload, "/pull_request/base/sha", false)?);
                scope.head = sha(&payload, "/pull_request/head/sha", false)?;
                // Null/unknown merges cannot certify the required merge-result scope.
                scope.merge_result = Some(sha(&payload, "/pull_request/merge_commit_sha", false)?);
                scope.pull_request = Some(
                    payload
                        .get("number")
                        .and_then(Value::as_u64)
                        .filter(|&n| n > 0)
                        .ok_or_else(|| invalid("pull request number"))?,
                );
                let base_id = payload
                    .pointer("/pull_request/base/repo/id")
                    .and_then(Value::as_u64)
                    .ok_or_else(|| invalid("base repository ID"))?;
                let head_id = payload
                    .pointer("/pull_request/head/repo/id")
                    .and_then(Value::as_u64)
                    .ok_or_else(|| invalid("head repository ID"))?;
                scope.fork = Some(base_id != head_id);
            }
            EventKind::Push => {
                if boolean(&payload, "deleted")? {
                    return Err(RedflagError::Config("A deleted ref has no introduced source range. Skip the changes invocation for push.deleted events.".into()));
                }
                let reference = payload
                    .get("ref")
                    .and_then(Value::as_str)
                    .ok_or_else(|| invalid("push ref"))?;
                if !reference.starts_with("refs/heads/") {
                    return Err(RedflagError::Config("Automatic push scope supports branches. Supply an explicit reviewed range for tag events.".into()));
                }
                let before = sha(&payload, "/before", true)?;
                scope.head = sha(&payload, "/after", false)?;
                scope.new_branch = boolean(&payload, "created")?;
                if before.bytes().all(|b| b == b'0') != scope.new_branch {
                    return Err(invalid("consistent push.before and push.created"));
                }
                if !scope.new_branch {
                    scope.base = Some(before);
                }
                // The payload's commits array may be truncated. Git reachability
                // from before/after is the sole source of selected commits.
            }
            EventKind::MergeGroup => {
                if payload.get("action").and_then(Value::as_str) != Some("checks_requested") {
                    return Err(invalid("merge_group checks_requested action"));
                }
                scope.base = Some(sha(&payload, "/merge_group/base_sha", false)?);
                scope.head = sha(&payload, "/merge_group/head_sha", false)?;
            }
        }
        Ok(scope)
    }
}

fn sha(payload: &Value, pointer: &str, allow_zero: bool) -> Result<String, RedflagError> {
    let value = payload
        .pointer(pointer)
        .and_then(Value::as_str)
        .ok_or_else(|| invalid(pointer))?;
    if value.len() != 40
        || !value.bytes().all(|b| b.is_ascii_hexdigit())
        || (!allow_zero && value.bytes().all(|b| b == b'0'))
    {
        return Err(invalid(pointer));
    }
    Ok(value.to_ascii_lowercase())
}

fn boolean(payload: &Value, name: &str) -> Result<bool, RedflagError> {
    payload
        .get(name)
        .and_then(Value::as_bool)
        .ok_or_else(|| invalid(name))
}

fn invalid(field: &str) -> RedflagError {
    RedflagError::Config(format!("GitHub event is missing or has invalid {field}. Fetch the exact event commits and supply a complete supported payload."))
}

#[cfg(test)]
mod tests {
    use super::*;
    use serde_json::json;

    #[test]
    fn push_uses_before_after_and_checks_new_branch_consistency() {
        let base = "1".repeat(40);
        let head = "2".repeat(40);
        let mut value = json!({"before": base, "after": head, "created": false, "deleted": false, "ref": "refs/heads/main", "commits": []});
        let parse = |v: &Value| EventScope::parse(&serde_json::to_vec(v).unwrap(), EventKind::Push);
        let scope = parse(&value).unwrap();
        assert_eq!(scope.base.as_deref(), Some(base.as_str()));
        assert_eq!(scope.head, head);
        value["before"] = json!("0".repeat(40));
        assert!(parse(&value).is_err());
        value["created"] = json!(true);
        assert!(parse(&value).unwrap().new_branch);
        assert!(parse(&value).unwrap().base.is_none());
        value["deleted"] = json!(true);
        assert!(parse(&value).is_err());
    }

    #[test]
    fn revision_expressions_and_unsupported_payloads_cannot_select_a_scope() {
        let mut value = json!({"action": "checks_requested", "merge_group": {"base_sha": "a".repeat(40), "head_sha": "b".repeat(40)}});
        let parse =
            |v: &Value| EventScope::parse(&serde_json::to_vec(v).unwrap(), EventKind::MergeGroup);
        assert!(parse(&value).is_ok());
        for invalid in [
            "HEAD",
            "main~1",
            "$(command)",
            &"0".repeat(40),
            &"c".repeat(39),
        ] {
            value["merge_group"]["head_sha"] = json!(invalid);
            assert!(parse(&value).is_err());
        }
        assert!(EventScope::parse(b"not JSON", EventKind::PullRequest).is_err());
        assert!(EventScope::parse(b"{}", EventKind::PullRequest).is_err());
    }
}
