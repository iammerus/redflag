//! In-memory publication archive traversal. Never materializes member paths.
use crate::{artifacts::digest, config::ScanLimits, error::RedflagError};
use flate2::bufread::MultiGzDecoder;
use serde::{Deserialize, Serialize};
use std::{
    collections::BTreeSet,
    io::{Cursor, Read},
    path::Path,
};

#[derive(Debug, Clone, Copy, Serialize, Deserialize, PartialEq, Eq, PartialOrd, Ord)]
#[serde(rename_all = "snake_case")]
pub enum Kind {
    Gzip,
    Zip,
    Tar,
}
const FORMATS: [Kind; 3] = [Kind::Gzip, Kind::Zip, Kind::Tar];

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq, PartialOrd, Ord)]
#[serde(deny_unknown_fields)]
pub struct Member {
    pub format: Kind,
    pub index: usize,
    pub path: String,
    pub bytes: u64,
    pub sha256: String,
}

pub fn label(members: &[Member]) -> String {
    members
        .iter()
        .map(|member| format!("{:?}[{}]:{}", member.format, member.index, member.path))
        .collect::<Vec<_>>()
        .join(" -> ")
}

#[derive(Clone, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub(crate) struct Coverage {
    pub schema_version: u32,
    pub formats: Vec<Kind>,
    pub archives: usize,
    pub members: usize,
    pub expanded_bytes: u64,
    pub max_depth_reached: usize,
}
impl Coverage {
    pub fn new() -> Self {
        Self {
            schema_version: 1,
            formats: FORMATS.to_vec(),
            archives: 0,
            members: 0,
            expanded_bytes: 0,
            max_depth_reached: 0,
        }
    }
    pub fn validate(&self, limits: &ScanLimits) -> Result<(), RedflagError> {
        if self.schema_version != 1
            || self.formats != FORMATS
            || self.members > limits.max_archive_members
            || self.expanded_bytes > limits.max_expanded_bytes
            || self.max_depth_reached > limits.max_archive_depth
            || self.archives > limits.max_files.saturating_add(self.members)
            || (self.archives == 0
                && (self.members != 0 || self.expanded_bytes != 0 || self.max_depth_reached != 0))
            || (self.archives > 0 && self.max_depth_reached == 0)
            || (self.members == 0 && self.expanded_bytes != 0)
        {
            return Err(invalid(
                "Invalid archive coverage; scan publication inputs again",
            ));
        }
        Ok(())
    }
}

pub(crate) fn inspect<F>(
    name: &Path,
    bytes: &[u8],
    limits: &ScanLimits,
    coverage: &mut Coverage,
    mut handle: F,
) -> Result<(), RedflagError>
where
    F: FnMut(&[u8], &[Member]) -> Result<(), RedflagError>,
{
    Inspection {
        limits,
        coverage,
        handle: &mut handle,
    }
    .visit(name, bytes, &mut Vec::new())
}

struct Inspection<'a, F> {
    limits: &'a ScanLimits,
    coverage: &'a mut Coverage,
    handle: &'a mut F,
}
impl<F: FnMut(&[u8], &[Member]) -> Result<(), RedflagError>> Inspection<'_, F> {
    fn visit(
        &mut self,
        name: &Path,
        bytes: &[u8],
        chain: &mut Vec<Member>,
    ) -> Result<(), RedflagError> {
        let Some(kind) = identify(name, bytes)? else {
            return Ok(());
        };
        if chain.len() >= self.limits.max_archive_depth {
            return Err(limit("max_archive_depth"));
        }
        self.coverage.archives += 1;
        self.coverage.max_depth_reached = self.coverage.max_depth_reached.max(chain.len() + 1);
        match kind {
            Kind::Gzip => {
                // gzip concatenation is one logical output stream; inspecting it
                // together also finds values crossing compressed-member boundaries.
                self.count_member()?;
                let expanded = self.expand(MultiGzDecoder::new(bytes), bytes.len() as u64)?;
                let name = name
                    .file_name()
                    .and_then(|name| name.to_str())
                    .unwrap_or("content.gz");
                let name = if let Some(stem) = name.strip_suffix(".tgz") {
                    format!("{stem}.tar")
                } else {
                    name.strip_suffix(".gz").unwrap_or("content").to_string()
                };
                self.member(kind, 0, safe_name(name.as_bytes(), false)?, expanded, chain)?;
            }
            Kind::Tar => self.tar(bytes, chain)?,
            Kind::Zip => self.zip(bytes, chain)?,
        }
        Ok(())
    }
    fn count_member(&mut self) -> Result<(), RedflagError> {
        if self.coverage.members >= self.limits.max_archive_members {
            return Err(limit("max_archive_members"));
        }
        self.coverage.members += 1;
        Ok(())
    }
    fn expand(&mut self, input: impl Read, compressed: u64) -> Result<Vec<u8>, RedflagError> {
        let remaining = self.limits.max_expanded_bytes - self.coverage.expanded_bytes;
        let ratio = compressed
            .max(1)
            .saturating_mul(self.limits.max_archive_ratio);
        let maximum = remaining
            .min(self.limits.max_archive_member_bytes)
            .min(ratio);
        let mut result = Vec::new();
        input
            .take(maximum.saturating_add(1))
            .read_to_end(&mut result)
            .map_err(|_| {
                invalid("Archive member is malformed, truncated or has an invalid checksum")
            })?;
        if result.len() as u64 > maximum {
            return Err(limit(if maximum == remaining {
                "max_expanded_bytes"
            } else if maximum == ratio {
                "max_archive_ratio"
            } else {
                "max_archive_member_bytes"
            }));
        }
        self.coverage.expanded_bytes += result.len() as u64;
        Ok(result)
    }
    fn member(
        &mut self,
        format: Kind,
        index: usize,
        path: String,
        bytes: Vec<u8>,
        chain: &mut Vec<Member>,
    ) -> Result<(), RedflagError> {
        chain.push(Member {
            format,
            index,
            path: path.clone(),
            bytes: bytes.len() as u64,
            sha256: digest(&bytes),
        });
        (self.handle)(&bytes, chain)?;
        self.visit(Path::new(&path), &bytes, chain)?;
        chain.pop();
        Ok(())
    }
    fn tar(&mut self, bytes: &[u8], chain: &mut Vec<Member>) -> Result<(), RedflagError> {
        let mut archive = tar::Archive::new(bytes);
        let entries = archive
            .entries()
            .map_err(|_| invalid("Invalid tar archive"))?
            .raw(true);
        let mut names = BTreeSet::new();
        let mut end = 0usize;
        for (index, entry) in entries.enumerate() {
            self.count_member()?;
            let mut entry = entry.map_err(|_| invalid("Invalid tar entry or checksum"))?;
            let kind = entry.header().entry_type();
            if !kind.is_file() && !kind.is_dir() {
                return Err(invalid(
                    "Tar links, special files and extended headers are unsupported",
                ));
            }
            let name = safe_name(&entry.path_bytes(), kind.is_dir())?;
            if !names.insert(name.clone()) {
                return Err(invalid("Archive contains duplicate member paths"));
            }
            let size = entry.size();
            end = usize::try_from(
                entry
                    .raw_file_position()
                    .checked_add(size.div_ceil(512).saturating_mul(512))
                    .ok_or_else(|| invalid("Tar size overflow"))?,
            )
            .map_err(|_| invalid("Tar size overflow"))?;
            if end > bytes.len() {
                return Err(invalid("Tar entry is truncated"));
            }
            if kind.is_dir() {
                if size != 0 {
                    return Err(invalid("Archive directory has payload bytes"));
                }
                continue;
            }
            let expanded = self.expand(&mut entry, size)?;
            if expanded.len() as u64 != size {
                return Err(invalid("Tar entry size does not match its header"));
            }
            self.member(Kind::Tar, index, name, expanded, chain)?;
        }
        // Require the conventional two zero terminators, and reject later data
        // which another reader might interpret as a second concatenated archive.
        let trailing = bytes
            .get(end..)
            .ok_or_else(|| invalid("Invalid tar extent"))?;
        if trailing.len() < 1024
            || trailing.len() % 512 != 0
            || trailing.iter().any(|&byte| byte != 0)
        {
            return Err(invalid(
                "Tar requires complete zero terminators without trailing payload",
            ));
        }
        Ok(())
    }
    fn zip(&mut self, bytes: &[u8], chain: &mut Vec<Member>) -> Result<(), RedflagError> {
        // Preflight the classic central-directory count before library allocation.
        // ZIP64 and duplicate-name collapsing are outside this bounded contract.
        let (count, directory) = zip_directory(bytes)?;
        if count > self.limits.max_archive_members - self.coverage.members {
            return Err(limit("max_archive_members"));
        }
        let mut archive = zip::ZipArchive::new(Cursor::new(bytes))
            .map_err(|_| invalid("Invalid or unsupported ZIP archive"))?;
        if archive.len() != count || archive.offset() != 0 {
            return Err(invalid("ZIP has duplicate names or a prepended payload"));
        }
        let mut names = BTreeSet::new();
        let mut extents = Vec::new();
        for index in 0..count {
            self.count_member()?;
            let mut entry = archive.by_index(index).map_err(|_| {
                invalid("ZIP entry is encrypted, malformed or uses unsupported compression")
            })?;
            if !matches!(
                entry.compression(),
                zip::CompressionMethod::Stored | zip::CompressionMethod::Deflated
            ) {
                return Err(invalid("ZIP compression must be stored or deflate"));
            }
            let directory_entry = entry.is_dir();
            if let Some(mode) = entry.unix_mode() {
                let kind = mode & 0o170000;
                if !matches!(kind, 0 | 0o100000 | 0o040000)
                    || (kind == 0o040000 && !directory_entry)
                    || (kind == 0o100000 && directory_entry)
                {
                    return Err(invalid("ZIP links and special files are unsupported"));
                }
            }
            let name = safe_name(entry.name_raw(), directory_entry)?;
            if !names.insert(name.clone()) {
                return Err(invalid("Archive contains duplicate member paths"));
            }
            let header =
                usize::try_from(entry.header_start()).map_err(|_| invalid("Invalid ZIP extent"))?;
            let data = entry
                .data_start()
                .ok_or_else(|| invalid("Missing ZIP data offset"))?;
            let end = data
                .checked_add(entry.compressed_size())
                .ok_or_else(|| invalid("ZIP size overflow"))?;
            if end > directory as u64 || header as u64 >= data {
                return Err(invalid("ZIP member extent overlaps its directory"));
            }
            let local = bytes
                .get(header..header.saturating_add(30))
                .ok_or_else(|| invalid("Truncated ZIP local header"))?;
            let name_end = header + 30 + u16le(local, 26)? as usize;
            let central = usize::try_from(entry.central_header_start())
                .map_err(|_| invalid("Invalid ZIP central offset"))?;
            if !local.starts_with(b"PK\x03\x04")
                || bytes.get(header + 30..name_end) != Some(entry.name_raw())
                || u16le(local, 6)? != u16le(bytes, central + 8)?
                || u16le(local, 8)? != u16le(bytes, central + 10)?
            {
                return Err(invalid(
                    "ZIP local and central names or encoding flags disagree",
                ));
            }
            extents.push((header as u64, end));
            let size = entry.size();
            let compressed = entry.compressed_size();
            let expanded = self.expand(&mut entry, compressed)?;
            if expanded.len() as u64 != size {
                return Err(invalid("ZIP entry size does not match its header"));
            }
            if directory_entry {
                if size != 0 {
                    return Err(invalid("Archive directory has payload bytes"));
                }
                continue;
            }
            self.member(Kind::Zip, index, name, expanded, chain)?;
        }
        extents.sort_unstable();
        if extents.windows(2).any(|pair| pair[0].1 > pair[1].0) {
            return Err(invalid("ZIP member extents overlap"));
        }
        Ok(())
    }
}

fn zip_directory(bytes: &[u8]) -> Result<(usize, usize), RedflagError> {
    let offset = (bytes.len().saturating_sub(65557)..bytes.len().saturating_sub(21))
        .rev()
        .find(|&at| {
            bytes[at..].starts_with(b"PK\x05\x06")
                && u16le(bytes, at + 20).is_ok_and(|len| at + 22 + len as usize == bytes.len())
        })
        .ok_or_else(|| invalid("ZIP has no complete central-directory terminator"))?;
    let count = u16le(bytes, offset + 10)? as usize;
    let size = u32le(bytes, offset + 12)? as usize;
    let start = u32le(bytes, offset + 16)? as usize;
    if u16le(bytes, offset + 4)? != 0
        || u16le(bytes, offset + 6)? != 0
        || u16le(bytes, offset + 8)? as usize != count
        || count == u16::MAX as usize
        || start.checked_add(size) != Some(offset)
    {
        return Err(invalid(
            "Split ZIP, ZIP64 and inconsistent directories are unsupported",
        ));
    }
    // Check physical record count too, before the library can collapse duplicate
    // names or allocate metadata from a count inconsistent with the directory.
    let mut cursor = start;
    for _ in 0..count {
        let record = bytes
            .get(cursor..cursor.saturating_add(46))
            .ok_or_else(|| invalid("Truncated ZIP directory"))?;
        if !record.starts_with(b"PK\x01\x02") {
            return Err(invalid("Invalid ZIP directory record"));
        }
        if u32le(record, 20)? == u32::MAX
            || u32le(record, 24)? == u32::MAX
            || u32le(record, 42)? == u32::MAX
            || u16le(record, 34)? != 0
        {
            return Err(invalid("ZIP64 and split ZIP entries are unsupported"));
        }
        cursor = cursor
            .checked_add(
                46 + u16le(record, 28)? as usize
                    + u16le(record, 30)? as usize
                    + u16le(record, 32)? as usize,
            )
            .filter(|&next| next <= offset)
            .ok_or_else(|| invalid("Invalid ZIP directory size"))?;
    }
    if cursor != offset {
        return Err(invalid("ZIP directory count does not cover its bytes"));
    }
    Ok((count, start))
}
fn u16le(bytes: &[u8], at: usize) -> Result<u16, RedflagError> {
    bytes
        .get(at..at + 2)
        .map(|raw| u16::from_le_bytes(raw.try_into().expect("two bytes")))
        .ok_or_else(|| invalid("Truncated archive metadata"))
}
fn u32le(bytes: &[u8], at: usize) -> Result<u32, RedflagError> {
    bytes
        .get(at..at + 4)
        .map(|raw| u32::from_le_bytes(raw.try_into().expect("four bytes")))
        .ok_or_else(|| invalid("Truncated archive metadata"))
}
fn safe_name(bytes: &[u8], directory: bool) -> Result<String, RedflagError> {
    let text =
        std::str::from_utf8(bytes).map_err(|_| invalid("Archive member names must be UTF-8"))?;
    if text.len() > 4096
        || text.chars().any(char::is_control)
        || text.contains(['\\', ':'])
        || text.starts_with('/')
    {
        return Err(invalid("Archive member has an unsafe or oversized path"));
    }
    let mut parts = Vec::new();
    for part in text.split('/') {
        if part == ".." {
            return Err(invalid("Archive member path traverses a parent"));
        }
        if part != "." && !part.is_empty() {
            parts.push(part);
        }
    }
    if parts.is_empty() && !directory {
        return Err(invalid("Archive file has an empty path"));
    }
    Ok(if parts.is_empty() {
        ".".into()
    } else {
        parts.join("/")
    })
}
fn identify(name: &Path, bytes: &[u8]) -> Result<Option<Kind>, RedflagError> {
    let ext = name
        .extension()
        .and_then(|ext| ext.to_str())
        .unwrap_or("")
        .to_ascii_lowercase();
    if bytes.starts_with(b"\x1f\x8b") {
        return Ok(Some(Kind::Gzip));
    }
    if bytes.starts_with(b"PK\x03\x04") || bytes.starts_with(b"PK\x05\x06") {
        return Ok(Some(Kind::Zip));
    }
    if bytes.get(257..262) == Some(b"ustar") {
        return Ok(Some(Kind::Tar));
    }
    if ext == "tar" {
        return Ok(Some(Kind::Tar));
    }
    if matches!(ext.as_str(), "gz" | "tgz" | "zip" | "jar" | "whl") {
        return Err(invalid(
            "Archive extension does not match a supported archive header",
        ));
    }
    if matches!(
        ext.as_str(),
        "7z" | "rar" | "bz2" | "xz" | "zst" | "br" | "tbz" | "tbz2" | "txz"
    ) || bytes.starts_with(b"7z\xbc\xaf\x27\x1c")
        || bytes.starts_with(b"Rar!\x1a\x07")
        || bytes.starts_with(b"BZh")
        || bytes.starts_with(b"\xfd7zXZ\0")
        || bytes.starts_with(b"\x28\xb5\x2f\xfd")
    {
        return Err(invalid(
            "Recognized archive compression is unsupported; provide unpacked publication inputs",
        ));
    }
    Ok(None)
}
fn invalid(message: &str) -> RedflagError {
    RedflagError::Incomplete(message.into())
}
fn limit(name: &str) -> RedflagError {
    invalid(&format!(
        "Archive inspection exceeds limits.{name}; inspection is incomplete"
    ))
}
