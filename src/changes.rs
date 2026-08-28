//! Committed source ranges. Selection and policy never depend on checkout contents.
use crate::{
    artifacts::digest,
    config::{Config, ExclusionPolicy, ScanLimits},
    engine::{EngineChoice, EngineInfo, GeneralEngine},
    error::RedflagError,
    exceptions::{ExceptionArgs, Policy as ExceptionPolicy},
    github_event::{EventKind, EventScope},
    report::{ReportArgs, ReportContext, ReportCoverage, ReportHandler},
    scanner::{CommitMetadata, Scanner},
    source_occurrences::{OccurrenceCoverage, SourceOccurrences},
};
use chrono::{DateTime, Utc};
use git2::{Commit, DiffOptions, ObjectType, Oid, Patch, Repository, Sort, Tree};
use serde::Serialize;
use std::path::{Path, PathBuf};

#[derive(clap::Args)]
pub(crate) struct ChangeArgs {
    #[arg(default_value = ".")]
    path: PathBuf,
    /// Exclude commits already reachable from this trusted revision
    #[arg(
        long,
        required_unless_present_any = ["new_branch", "github_event"],
        conflicts_with_all = ["new_branch", "github_event"]
    )]
    base: Option<String>,
    #[arg(long, default_value = "HEAD", conflicts_with = "github_event")]
    head: String,
    /// Inspect all reachable commits when there is no previous branch tip
    #[arg(long, conflicts_with = "github_event")]
    new_branch: bool,
    /// Also inspect this synthetic merge; its parents must include base and head
    #[arg(long, requires = "base", conflicts_with = "github_event")]
    merge_result: Option<String>,
    /// Read exact source scope from the GitHub Actions event JSON file
    #[arg(long, value_name = "FILE")]
    github_event: Option<PathBuf>,
    /// Event type; defaults to GITHUB_EVENT_NAME when using --github-event
    #[arg(long, value_enum, requires = "github_event")]
    event_name: Option<EventKind>,
    /// Read root redflag.toml from this trusted revision instead of base
    #[arg(long, conflicts_with_all = ["config", "no_config"])]
    policy_ref: Option<String>,
    /// Explicit trusted policy outside the proposed changes
    #[arg(short, long, conflicts_with = "no_config")]
    config: Option<PathBuf>,
    /// Use built-in defaults without reading repository policy
    #[arg(long)]
    no_config: bool,
    /// Fail if the complete introduced range exceeds this commit count
    #[arg(long)]
    max_commits: Option<usize>,
    #[command(flatten)]
    report: ReportArgs,
    #[command(flatten)]
    exceptions: ExceptionArgs,
    #[arg(long, value_enum, default_value = "betterleaks")]
    engine: EngineChoice,
    #[arg(long)]
    betterleaks_path: Option<PathBuf>,
}

#[derive(Serialize)]
struct Coverage {
    repository: PathBuf,
    base: Option<String>,
    head: String,
    merge_result: Option<String>,
    new_branch: bool,
    #[serde(skip_serializing_if = "Option::is_none")]
    event: Option<EventScope>,
    selection: &'static str,
    policy_origin: String,
    config_sha256: String,
    engine: EngineInfo,
    max_commits: usize,
    limits: ScanLimits,
    commits: Vec<String>,
    files: Vec<FileRevision>,
    skipped: Vec<SkippedRevision>,
    inspected_bytes: u64,
    comparison_bytes: u64,
    occurrence_comparison: Option<OccurrenceCoverage>,
    representations: &'static str,
}

#[derive(Serialize)]
struct FileRevision {
    commit: String,
    path: PathBuf,
    blob: String,
    size: usize,
    added_against_parents: Vec<ParentChanges>,
}

impl ReportCoverage for Coverage {
    fn summary_facts(&self) -> Vec<(&'static str, String)> {
        vec![
            (
                "Base",
                self.base
                    .clone()
                    .unwrap_or_else(|| "none; all reachable history".into()),
            ),
            ("Head", self.head.clone()),
            (
                "Merge result",
                self.merge_result.clone().unwrap_or_else(|| "none".into()),
            ),
            ("Introduced commits", self.commits.len().to_string()),
            ("Inspected revisions", self.files.len().to_string()),
            ("Inspected bytes", self.inspected_bytes.to_string()),
            ("Policy", self.policy_origin.clone()),
            ("Policy SHA-256", self.config_sha256.clone()),
            (
                "Engine",
                format!("{} {}", self.engine.name, self.engine.version),
            ),
        ]
    }
}

#[derive(Serialize)]
struct ParentChanges {
    parent: Option<String>,
    lines: Vec<LineInterval>,
}

#[derive(Serialize)]
struct LineInterval {
    start: usize,
    end: usize,
}

#[derive(Serialize)]
struct SkippedRevision {
    commit: String,
    path: PathBuf,
    reason: &'static str,
}

pub(crate) fn run(mut args: ChangeArgs) -> Result<u8, RedflagError> {
    let event = args
        .github_event
        .as_ref()
        .map(|path| EventScope::read(path, args.event_name))
        .transpose()?;
    if let Some(event) = &event {
        args.base = event.base.clone();
        args.head = event.head.clone();
        args.merge_result = event.merge_result.clone();
        args.new_branch = event.new_branch;
    }
    let repo = Repository::open(&args.path)?;
    if repo.is_shallow() {
        return Err(RedflagError::Incomplete(
            "Git history is shallow. Fetch full history and retry (actions/checkout fetch-depth: 0).".into(),
        ));
    }
    let base = args
        .base
        .as_deref()
        .map(|r| resolve(&repo, r))
        .transpose()?;
    let head = resolve(&repo, &args.head)?;
    let merge_result = args
        .merge_result
        .as_deref()
        .map(|r| resolve(&repo, r))
        .transpose()?;
    if let Some(merge) = merge_result {
        let commit = repo.find_commit(merge)?;
        if commit.parent_count() < 2
            || !commit.parent_ids().any(|p| p == head)
            || !commit.parent_ids().any(|p| Some(p) == base)
        {
            return Err(RedflagError::Config(
                "--merge-result must be a merge whose parents include the selected base and head."
                    .into(),
            ));
        }
    }
    let (config, policy_origin) = trusted_policy(&repo, &args, base)?;
    let exception_revision = args
        .policy_ref
        .as_deref()
        .map(|revision| resolve(&repo, revision))
        .transpose()?
        .or(base);
    let exception_policy =
        ExceptionPolicy::load_source(&repo, exception_revision, &args.exceptions)?;
    let max_commits = args.max_commits.unwrap_or(config.git.max_depth);
    if max_commits == 0 {
        return Err(RedflagError::Config(
            "--max-commits must be positive".into(),
        ));
    }
    let commits = select(&repo, base, head, merge_result, max_commits)?;
    let config_sha256 = digest(&serde_json::to_vec(&config)?);
    let mut engine = GeneralEngine::prepare(
        args.engine,
        args.betterleaks_path,
        config.limits.engine_timeout_seconds,
        config_sha256.clone(),
    )?;
    let mut coverage = Coverage {
        repository: repo.workdir().unwrap_or(repo.path()).to_path_buf(),
        base: base.map(|v| v.to_string()),
        head: head.to_string(),
        merge_result: merge_result.map(|v| v.to_string()),
        new_branch: args.new_branch,
        event,
        selection: "reachable(head) minus reachable(base), plus optional merge result",
        policy_origin,
        config_sha256,
        engine: engine.info().clone(),
        max_commits,
        limits: config.limits.clone(),
        commits: commits.iter().map(ToString::to_string).collect(),
        files: Vec::new(),
        skipped: Vec::new(),
        inspected_bytes: 0,
        comparison_bytes: 0,
        occurrence_comparison: None,
        representations:
            "raw committed blobs and parent detector evidence; one-to-one occurrence mapping; no inline suppressions",
    };
    let mut scanner = Scanner::with_config(config)?;
    if args.engine == EngineChoice::Betterleaks {
        scanner = scanner.for_external_engine();
    }
    let mut handler = ReportHandler::new(args.report, scanner.limits())?;
    let mut occurrences = SourceOccurrences::new(&repo, scanner.limits())?;
    for oid in commits {
        inspect_commit(
            &repo,
            oid,
            &scanner,
            &mut engine,
            &mut coverage,
            &mut occurrences,
        )?;
    }
    engine.finish(&mut occurrences)?;
    coverage.occurrence_comparison = Some(occurrences.emit_introduced(&mut handler)?);
    let mut context = ReportContext::source(coverage.repository.clone());
    context.protect_output(args.exceptions.path());
    context.protect_output(args.config.as_deref());
    handler.finish_report(context, &coverage, exception_policy)
}

fn resolve(repo: &Repository, revision: &str) -> Result<Oid, RedflagError> {
    repo.revparse_single(revision)?
        .peel_to_commit()
        .map(|c| c.id())
        .map_err(Into::into)
}

fn trusted_policy(
    repo: &Repository,
    args: &ChangeArgs,
    base: Option<Oid>,
) -> Result<(Config, String), RedflagError> {
    if let Some(path) = &args.config {
        let path = std::fs::canonicalize(path)?;
        return Ok((
            Config::load(Some(path.clone()))?,
            format!("file:{}", path.display()),
        ));
    }
    let policy = if args.no_config {
        None
    } else {
        args.policy_ref
            .as_deref()
            .map(|r| resolve(repo, r))
            .transpose()?
            .or(base)
    };
    if let Some(oid) = policy {
        let tree = repo.find_commit(oid)?.tree()?;
        match tree.get_path(Path::new("redflag.toml")) {
            Ok(entry) => {
                if !regular(entry.filemode()) {
                    return Err(RedflagError::Config(
                        "Trusted redflag.toml must be a regular Git blob".into(),
                    ));
                }
                let (size, _) = repo.odb()?.read_header(entry.id())?;
                if size > 1024 * 1024 {
                    return Err(RedflagError::Config(
                        "Trusted redflag.toml exceeds 1 MiB".into(),
                    ));
                }
                let blob = repo.find_blob(entry.id())?;
                let text = std::str::from_utf8(blob.content()).map_err(|_| {
                    RedflagError::Config("Trusted redflag.toml must be UTF-8".into())
                })?;
                return Ok((Config::from_toml(text)?, format!("git:{oid}:redflag.toml")));
            }
            Err(error) if error.code() == git2::ErrorCode::NotFound => {
                return Ok((
                    Config::load(None)?,
                    format!("built-in defaults; no redflag.toml in {oid}"),
                ));
            }
            Err(error) => return Err(error.into()),
        }
    }
    Ok((Config::load(None)?, "built-in defaults".into()))
}

fn select(
    repo: &Repository,
    base: Option<Oid>,
    head: Oid,
    merge: Option<Oid>,
    limit: usize,
) -> Result<Vec<Oid>, RedflagError> {
    let mut walk = repo.revwalk()?;
    walk.set_sorting(Sort::TOPOLOGICAL | Sort::REVERSE)?;
    walk.push(head)?;
    if let Some(base) = base {
        walk.hide(base)?;
    }
    let mut commits = Vec::new();
    for oid in walk {
        if commits.len() >= limit {
            return Err(range_limit(limit));
        }
        let oid = oid?;
        validate_commit(repo, oid)?;
        commits.push(oid);
    }
    if let Some(merge) = merge {
        if !commits.contains(&merge) {
            if commits.len() >= limit {
                return Err(range_limit(limit));
            }
            validate_commit(repo, merge)?;
            commits.push(merge);
        }
    }
    Ok(commits)
}

fn validate_commit(repo: &Repository, oid: Oid) -> Result<(), RedflagError> {
    let commit = repo.find_commit(oid)?;
    commit.tree()?;
    // git2's convenience parent iterator silently stops at a missing object.
    for index in 0..commit.parent_count() {
        commit.parent(index)?.tree()?;
    }
    Ok(())
}

fn range_limit(limit: usize) -> RedflagError {
    RedflagError::Incomplete(format!("Introduced range exceeds {limit} commits. Increase --max-commits to inspect the complete range."))
}

fn inspect_commit(
    repo: &Repository,
    oid: Oid,
    scanner: &Scanner,
    engine: &mut GeneralEngine,
    coverage: &mut Coverage,
    occurrences: &mut SourceOccurrences<'_>,
) -> Result<(), RedflagError> {
    let commit = repo.find_commit(oid)?;
    let tree = commit.tree()?;
    let parents: Vec<Tree<'_>> = (0..commit.parent_count())
        .map(|index| commit.parent(index)?.tree())
        .collect::<Result<_, _>>()?;
    let diff = repo.diff_tree_to_tree(parents.first(), Some(&tree), None)?;
    let metadata = commit_metadata(&commit);
    for delta in diff.deltas() {
        let path = delta
            .new_file()
            .path()
            .ok_or_else(|| RedflagError::Incomplete("Git delta has no path".into()))?;
        let skip = if delta.new_file().id().is_zero() {
            Some("deleted")
        } else if scanner.file_policy(path, false) == ExclusionPolicy::Ignore {
            Some("trusted exclusion")
        } else {
            None
        };
        if coverage.files.len() + coverage.skipped.len() >= scanner.limits().max_files {
            return Err(RedflagError::Incomplete(
                "Git range exceeds limits.max_files file revisions".into(),
            ));
        }
        if let Some(reason) = skip {
            coverage.skipped.push(SkippedRevision {
                commit: metadata.hash.clone(),
                path: path.to_path_buf(),
                reason,
            });
            continue;
        }
        if !regular(delta.new_file().mode().into()) {
            return Err(RedflagError::Incomplete(format!("Selected Git path {} in {} is a symlink, submodule or unsupported entry. Inspect it separately or exclude it with trusted policy.", path.display(), metadata.hash)));
        }
        let entries = parents
            .iter()
            .map(|tree| entry_at(tree, path))
            .collect::<Result<Vec<_>, _>>()?;
        if entries
            .iter()
            .flatten()
            .any(|(id, mode)| *id == delta.new_file().id() && regular(*mode))
        {
            coverage.skipped.push(SkippedRevision {
                commit: metadata.hash.clone(),
                path: path.to_path_buf(),
                reason: "content unchanged in a parent",
            });
            continue;
        }
        let blob = bounded_blob(repo, delta.new_file().id(), path, scanner)?;
        charge(
            &mut coverage.inspected_bytes,
            blob.size(),
            coverage.comparison_bytes,
            scanner.limits(),
        )?;
        let mut added = Vec::new();
        let mut comparison_parents = Vec::new();
        if entries.is_empty() {
            added.push(ParentChanges {
                parent: None,
                lines: added_lines(&[], blob.content(), path)?,
            });
        }
        for (parent_index, entry) in entries.iter().enumerate() {
            let previous = entry
                .filter(|(_, mode)| regular(*mode))
                .map(|(id, _)| bounded_blob(repo, id, path, scanner))
                .transpose()?;
            let bytes = previous.as_ref().map_or(&[][..], |b| b.content());
            charge(
                &mut coverage.comparison_bytes,
                bytes.len(),
                coverage.inspected_bytes,
                scanner.limits(),
            )?;
            added.push(ParentChanges {
                parent: Some(commit.parent_id(parent_index)?.to_string()),
                lines: added_lines(bytes, blob.content(), path)?,
            });
            comparison_parents.push((
                commit_metadata(&commit.parent(parent_index)?),
                previous.as_ref().map(|b| b.id()),
            ));
        }
        coverage.files.push(FileRevision {
            commit: metadata.hash.clone(),
            path: path.to_path_buf(),
            blob: blob.id().to_string(),
            size: blob.size(),
            added_against_parents: added,
        });
        occurrences.add_revision(
            path,
            metadata.clone(),
            &blob,
            &comparison_parents,
            scanner,
            engine,
        )?;
    }
    Ok(())
}

fn regular(mode: i32) -> bool {
    matches!(mode, 0o100644 | 0o100755)
}

fn entry_at(tree: &Tree<'_>, path: &Path) -> Result<Option<(Oid, i32)>, RedflagError> {
    match tree.get_path(path) {
        Ok(entry) => Ok(Some((entry.id(), entry.filemode()))),
        Err(error) if error.code() == git2::ErrorCode::NotFound => Ok(None),
        Err(error) => Err(error.into()),
    }
}

fn bounded_blob<'a>(
    repo: &'a Repository,
    oid: Oid,
    path: &Path,
    scanner: &Scanner,
) -> Result<git2::Blob<'a>, RedflagError> {
    let (size, kind) = repo.odb()?.read_header(oid)?;
    scanner.check_file_limit(path, size as u64)?;
    if kind != ObjectType::Blob {
        return Err(RedflagError::Incomplete(
            "Selected Git object is not a blob".into(),
        ));
    }
    Ok(repo.find_blob(oid)?)
}

fn charge(
    total: &mut u64,
    size: usize,
    other: u64,
    limits: &ScanLimits,
) -> Result<(), RedflagError> {
    *total = total
        .checked_add(size as u64)
        .ok_or_else(|| RedflagError::Incomplete("Git byte count overflow".into()))?;
    if total
        .checked_add(other)
        .is_none_or(|t| t > limits.max_total_bytes)
    {
        return Err(RedflagError::Incomplete(
            "Git inspection and parent comparisons exceed limits.max_total_bytes".into(),
        ));
    }
    Ok(())
}

fn added_lines(old: &[u8], new: &[u8], path: &Path) -> Result<Vec<LineInterval>, RedflagError> {
    let mut options = DiffOptions::new();
    options.force_text(true).context_lines(0);
    let patch = Patch::from_buffers(old, Some(path), new, Some(path), Some(&mut options))?;
    let mut lines: Vec<LineInterval> = Vec::new();
    for hunk in 0..patch.num_hunks() {
        let (_, count) = patch.hunk(hunk)?;
        for i in 0..count {
            let line = patch.line_in_hunk(hunk, i)?;
            if line.origin() == '+' {
                let number = line.new_lineno().ok_or_else(|| {
                    RedflagError::Incomplete("Git addition has no line number".into())
                })? as usize;
                if let Some(last) = lines.last_mut().filter(|last| last.end + 1 == number) {
                    last.end = number;
                } else {
                    lines.push(LineInterval {
                        start: number,
                        end: number,
                    });
                }
            }
        }
    }
    Ok(lines)
}

fn commit_metadata(commit: &Commit<'_>) -> CommitMetadata {
    CommitMetadata {
        hash: commit.id().to_string(),
        author: commit.author().to_string(),
        date: DateTime::<Utc>::from_timestamp(commit.time().seconds(), 0)
            .map(|d| d.to_rfc3339())
            .unwrap_or_else(|| commit.time().seconds().to_string()),
    }
}
