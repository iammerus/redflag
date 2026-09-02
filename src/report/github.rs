//! GitHub workflow commands and bounded job summaries; no API calls or tokens.
use super::{
    clean_text, invalid, read_occurrence, ExceptionAudit, PhysicalOccurrence, PreparedGroup,
    ReportContext, ReportCoverage,
};
use crate::error::RedflagError;
use std::{
    fs::{self, File, OpenOptions},
    io::{self, BufReader, Read, Write},
    path::{Path, PathBuf},
};

const MAX_ANNOTATIONS: usize = 10;
const MAX_ROWS: usize = 100;
const MAX_SUMMARY: usize = 1024 * 1024;

pub(super) fn render(
    groups: &[PreparedGroup],
    context: &ReportContext,
    reader: &mut BufReader<File>,
    coverage: &impl ReportCoverage,
    summary_path: &Path,
    observations: usize,
    exceptions: &ExceptionAudit,
) -> Result<(), RedflagError> {
    let total: usize = groups.iter().map(|g| g.occurrences.len()).sum();
    let blocking = total - exceptions.accepted_occurrences;
    let scope = LinkScope::from_environment();
    let mut summary = format!(
        "\n## Redflag {} inspection\n\n**Complete — {} logical finding(s), {total} occurrence(s), {observations} detector observation(s).**\n\n",
        context.mode, groups.len()
    );
    if total == 0 {
        summary.push_str("No findings in the selected scope. Require this step to succeed before publication.\n\n");
    }
    summary.push_str(&format!(
        "**Blocking occurrences: {blocking}. Accepted by reviewed exception: {}.**\n\n",
        exceptions.accepted_occurrences
    ));
    summary.push_str("| Coverage | Value |\n| --- | --- |\n");
    for (name, value) in coverage.summary_facts() {
        summary.push_str(&format!("| {name} | {} |\n", code(&short(&value, 512))));
    }
    summary.push_str(&format!(
        "| Exception policy | {} |\n| Exception review | {} |\n",
        code(&short(&exceptions.origin, 512)),
        code(&format!(
            "{} matched; {} unmatched; {} expired entries; evaluated {}",
            exceptions.matched_entries,
            exceptions.unmatched_entries,
            exceptions.expired_entries,
            exceptions.evaluated_at
        ))
    ));
    summary.push_str("\nLocations refer to inspected versions. Source links retain the reported commit; file annotations require matching bytes at the GitHub checked revision. Artifact targets are indexed in selection order. Columns in the JSON report are byte offsets.\n\n");
    let mut annotations = String::new();
    let mut rows = 0;
    let mut emitted = 0;
    if total > 0 {
        summary.push_str("| Finding | Location | Rules | Occurrence | Review | Remediation |\n| --- | --- | --- | --- | --- | --- |\n");
    }
    let occurrences = || {
        groups.iter().flat_map(|group| {
            group
                .occurrences
                .iter()
                .map(move |occurrence| (group, occurrence))
        })
    };
    for (group, occurrence) in occurrences()
        .filter(|(_, o)| !o.accepted())
        .chain(occurrences().filter(|(_, o)| o.accepted()))
        .take(MAX_ROWS)
    {
        let evidence = read_occurrence(reader, occurrence)?;
        let rules = short(
            &evidence
                .evidence
                .iter()
                .map(|e| e.rule_id.as_str())
                .collect::<Vec<_>>()
                .join(", "),
            512,
        );
        let header = group.header(context.mode);
        let label = location_label(occurrence);
        let location = match scope
            .as_ref()
            .and_then(|scope| scope.location_url(occurrence))
        {
            Some(url) => format!("[{}]({url})", code(&short(&label, 512))),
            None => code(&short(&label, 512)),
        };
        let row = format!(
            "| {} ({:?}, {})<br>{} | {location} | {} | {} | {} | {} |\n",
            header.title,
            header.severity,
            occurrence.status(),
            code(header.id),
            code(&rules),
            code(&occurrence.id),
            occurrence
                .review
                .as_ref()
                .map(|r| code(&short(
                    &format!(
                        "{}; reviewed by {}; expires {}{}",
                        r.reason,
                        r.reviewed_by,
                        r.expires_at,
                        match r.status {
                            super::ReviewStatus::Accepted => "",
                            super::ReviewStatus::Expired => "; EXPIRED",
                            super::ReviewStatus::RejectedPrivateValue =>
                                "; REJECTED: declared private values cannot be exempted",
                        }
                    ),
                    768
                )))
                .unwrap_or_else(|| "No exception".into()),
            header.remediation
        );
        if summary.len() + row.len() > MAX_SUMMARY / 2 {
            break;
        }
        summary.push_str(&row);
        if !occurrence.accepted() && emitted < MAX_ANNOTATIONS {
            let mut properties =
                format!("title={}", property(&format!("Redflag: {}", header.title)));
            if let Some(path) = annotation_path(context, occurrence) {
                let end = occurrence
                    .primary
                    .end_line
                    .saturating_sub(usize::from(occurrence.primary.end_column == 0))
                    .max(occurrence.primary.start_line);
                properties.push_str(&format!(
                    ",file={},line={},endLine={}",
                    property(&path),
                    occurrence.primary.start_line,
                    end
                ));
            }
            let message = format!(
                "{}; {}. Rules: {rules}. {}",
                short(&label, 512),
                occurrence.id,
                header.remediation
            );
            annotations.push_str(&format!("::error {properties}::{}\n", data(&message)));
            emitted += 1;
        }
        rows += 1;
    }
    if rows < total {
        summary.push_str(&format!("\nShowing {rows} of {total} occurrences. Inspection included every occurrence; use `--format json` for the complete report.\n"));
    }
    summary.push_str(&format!("\nEmitted {emitted} of {blocking} blocking occurrence annotations (display limit {MAX_ANNOTATIONS}). Exit codes: 0 no blockers, 1 blocking occurrences, 2 incomplete/error.\n"));
    if blocking == 0 {
        annotations.push_str(&format!("::notice title=Redflag inspection complete::{} inspection complete; no blocking occurrences; {} occurrences accepted by reviewed exceptions.\n", context.mode, exceptions.accepted_occurrences));
    } else if blocking > MAX_ANNOTATIONS {
        annotations.push_str(&format!("Redflag: showing {MAX_ANNOTATIONS} of {blocking} occurrence annotations; see the job summary or use --format json for all findings.\n"));
    }
    append_summary(summary_path, &summary, context)?;
    let mut stdout = io::stdout().lock();
    stdout.write_all(annotations.as_bytes())?;
    stdout.flush()?;
    Ok(())
}

fn location_label(occurrence: &PhysicalOccurrence) -> String {
    let location = &occurrence.location;
    let mut label = match &location.commit {
        Some(commit) => format!(
            "{}:{} (commit {commit})",
            location.path, occurrence.primary.start_line
        ),
        None => format!(
            "target {}: {}:{} (SHA-256 {})",
            location.target.unwrap_or(0),
            location.path,
            occurrence.primary.start_line,
            location.version
        ),
    };
    if !location.representation.is_empty() {
        label.push_str(&format!(
            " [{}]",
            crate::decoding::label(&location.representation)
        ));
    }
    label
}

fn append_summary(path: &Path, text: &str, context: &ReportContext) -> Result<(), RedflagError> {
    let parent = path
        .parent()
        .filter(|p| !p.as_os_str().is_empty())
        .unwrap_or_else(|| Path::new("."));
    let resolved = fs::canonicalize(parent)?.join(
        path.file_name()
            .ok_or_else(|| invalid("GitHub summary requires a file path"))?,
    );
    for protected in &context.protected_paths {
        // Artifact roots exist. A requested manifest may be absent on findings.
        let protected = if protected.exists() {
            fs::canonicalize(protected)?
        } else {
            let parent = protected
                .parent()
                .filter(|p| !p.as_os_str().is_empty())
                .unwrap_or_else(|| Path::new("."));
            fs::canonicalize(parent)?.join(
                protected
                    .file_name()
                    .ok_or_else(|| invalid("Invalid protected output path"))?,
            )
        };
        if resolved.starts_with(protected) {
            return Err(invalid(
                "GitHub summary must be separate from publication inputs, manifests and policy files",
            ));
        }
    }
    let existing = match fs::symlink_metadata(&resolved) {
        Ok(meta) if meta.file_type().is_file() => true,
        Ok(_) => {
            return Err(invalid(
                "GitHub summary must be a regular file, not a symlink or special file",
            ))
        }
        Err(error) if error.kind() == io::ErrorKind::NotFound => false,
        Err(error) => return Err(error.into()),
    };
    let mut file = if existing {
        OpenOptions::new().append(true).open(resolved)?
    } else {
        OpenOptions::new()
            .append(true)
            .create_new(true)
            .open(resolved)?
    };
    #[cfg(unix)]
    {
        use std::os::unix::fs::MetadataExt;
        if file.metadata()?.nlink() != 1 {
            return Err(invalid(
                "GitHub summary must not share a hard link with another file",
            ));
        }
    }
    if file.metadata()?.len().saturating_add(text.len() as u64) > MAX_SUMMARY as u64 {
        return Err(invalid(
            "GitHub summary would exceed the 1 MiB step limit; use a separate step summary",
        ));
    }
    file.write_all(text.as_bytes())?;
    file.flush()?;
    Ok(())
}

/// Attach to the checked version only when its blob and current worktree bytes
/// exactly match the reported committed blob. Never remap historical line numbers.
fn annotation_path(context: &ReportContext, occurrence: &PhysicalOccurrence) -> Option<String> {
    let root = context.source_root.as_ref()?;
    let repo = git2::Repository::open(root).ok()?;
    let path = Path::new(&occurrence.location.path);
    if occurrence.location.path.chars().any(char::is_control) {
        return None;
    }
    let reported = repo
        .find_commit(git2::Oid::from_str(occurrence.location.commit.as_ref()?).ok()?)
        .ok()?;
    let checked = std::env::var("GITHUB_SHA").ok()?;
    if checked.len() != 40 {
        return None;
    }
    let checked = repo.find_commit(git2::Oid::from_str(&checked).ok()?).ok()?;
    let original = reported.tree().ok()?.get_path(path).ok()?.id();
    if checked.tree().ok()?.get_path(path).ok()?.id() != original {
        return None;
    }
    let file = root.join(path);
    if !fs::symlink_metadata(&file).ok()?.file_type().is_file() {
        return None;
    }
    let file = fs::canonicalize(file).ok()?;
    if !file.starts_with(fs::canonicalize(root).ok()?) {
        return None;
    }
    let mut bytes = Vec::new();
    File::open(&file)
        .ok()?
        .take(64 * 1024 * 1024 + 1)
        .read_to_end(&mut bytes)
        .ok()?;
    if bytes.len() > 64 * 1024 * 1024
        || git2::Oid::hash_object(git2::ObjectType::Blob, &bytes).ok()? != original
    {
        return None;
    }
    let workspace = std::env::var_os("GITHUB_WORKSPACE")
        .map(PathBuf::from)
        .unwrap_or_else(|| root.clone());
    let workspace = fs::canonicalize(workspace).ok()?;
    // Nested/multiple checkouts need an explicit repository-path mapping. Keep
    // general annotations until that mapping can be established.
    if workspace != fs::canonicalize(root).ok()? {
        return None;
    }
    super::normalized_path(file.strip_prefix(workspace).ok()?).ok()
}

struct LinkScope {
    base: String,
}
impl LinkScope {
    fn from_environment() -> Option<Self> {
        let server =
            std::env::var("GITHUB_SERVER_URL").unwrap_or_else(|_| "https://github.com".into());
        let repository = std::env::var("GITHUB_REPOSITORY").ok()?;
        Self::parse(&server, &repository)
    }
    fn parse(server: &str, repository: &str) -> Option<Self> {
        let server = server.trim_end_matches('/');
        let host = server.strip_prefix("https://")?;
        if host.is_empty()
            || !host
                .bytes()
                .all(|b| b.is_ascii_alphanumeric() || b".-:".contains(&b))
        {
            return None;
        }
        let parts: Vec<_> = repository.split('/').collect();
        if parts.len() != 2
            || parts.iter().any(|part| {
                part.is_empty()
                    || *part == "."
                    || *part == ".."
                    || part.len() > 100
                    || !part
                        .bytes()
                        .all(|b| b.is_ascii_alphanumeric() || b"._-".contains(&b))
            })
        {
            return None;
        }
        Some(Self {
            base: format!("{server}/{repository}"),
        })
    }
    fn location_url(&self, occurrence: &PhysicalOccurrence) -> Option<String> {
        let commit = occurrence.location.commit.as_ref()?;
        if commit.len() != 40 || !commit.bytes().all(|b| b.is_ascii_hexdigit()) {
            return None;
        }
        let path: String = occurrence
            .location
            .path
            .bytes()
            .map(|b| {
                if b.is_ascii_alphanumeric() || b"-._~/".contains(&b) {
                    (b as char).to_string()
                } else {
                    format!("%{b:02X}")
                }
            })
            .collect();
        Some(format!(
            "{}/blob/{commit}/{path}#L{}",
            self.base, occurrence.primary.start_line
        ))
    }
}

fn short(value: &str, limit: usize) -> String {
    let text = clean_text(value);
    let mut chars = text.chars();
    let mut text: String = chars.by_ref().take(limit).collect();
    if chars.next().is_some() {
        text.push('…');
    }
    text
}
fn code(value: &str) -> String {
    let escaped: String = clean_text(value)
        .chars()
        .map(|c| {
            if c.is_alphanumeric() || c == ' ' {
                c.to_string()
            } else {
                format!("&#x{:X};", c as u32)
            }
        })
        .collect();
    format!("<code>{escaped}</code>")
}
fn data(value: &str) -> String {
    value
        .replace('%', "%25")
        .replace('\r', "%0D")
        .replace('\n', "%0A")
}
fn property(value: &str) -> String {
    data(value).replace(':', "%3A").replace(',', "%2C")
}

#[cfg(test)]
mod tests {
    use super::*;
    #[test]
    fn command_and_markdown_data_cannot_create_commands_links_or_markup() {
        assert_eq!(data("x%0A\r\n::error::oops"), "x%250A%0D%0A::error::oops");
        assert_eq!(property("x,y:z%\n"), "x%2Cy%3Az%25%0A");
        let escaped = code("[link](https://example.invalid)|<img>\n`tail`");
        assert!(!escaped.contains("[link]"));
        assert!(!escaped.contains("<img>"));
        assert!(!escaped.contains('|'));
        assert!(!escaped.contains('\n'));
    }

    #[test]
    fn links_require_safe_repository_and_https_server_components() {
        assert!(LinkScope::parse("https://github.example:443/", "team/repo-name").is_some());
        for server in [
            "javascript:alert(1)",
            "https://github.com/@evil",
            "https://github.com) [x](evil",
            "https://user@example.com",
            "https://",
        ] {
            assert!(LinkScope::parse(server, "team/repo").is_none());
        }
        for repository in [
            "../repo",
            "owner/repo/extra",
            "owner/repo?x=1",
            "owner/",
            "owner/repo\n::error::",
        ] {
            assert!(LinkScope::parse("https://github.com", repository).is_none());
        }
    }
}
