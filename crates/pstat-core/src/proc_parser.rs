//! String-based /proc file parsers.
//!
//! These parsers work on content strings, not file paths. This lets both
//! `LocalCollector` (reads files via std::fs) and `RsdbCollector` (gets
//! content via rsdb agent exec) share the same parsing logic.

use crate::collector::PstatError;
use crate::schema::{ProcessState, VmaEntry};

/// Fields extracted from /proc/[pid]/stat.
#[derive(Debug)]
pub struct StatFields {
    pub pid: u32,
    pub comm: String,
    pub state: ProcessState,
    pub ppid: u32,
    pub utime: u64,
    pub stime: u64,
    pub num_threads: u32,
    pub start_time: u64,
    pub vsize: u64,
    pub rss_pages: i64,
}

/// Parse /proc/[pid]/stat content.
///
/// The comm field is enclosed in parentheses and may contain spaces and
/// parentheses, so we find the LAST ')' to safely split the remaining fields.
pub fn parse_stat(content: &str) -> Result<StatFields, PstatError> {
    let content = content.trim();
    let open = content
        .find('(')
        .ok_or_else(|| PstatError::ParseError("stat: missing '('".into()))?;
    let close = content
        .rfind(')')
        .ok_or_else(|| PstatError::ParseError("stat: missing ')'".into()))?;

    let pid_str = content[..open].trim();
    let pid: u32 = pid_str
        .parse()
        .map_err(|_| PstatError::ParseError(format!("stat: bad pid '{pid_str}'")))?;
    let comm = content[open + 1..close].to_string();

    let rest = content.get(close + 2..).ok_or_else(|| {
        PstatError::ParseError("stat: truncated after comm field".into())
    })?;
    let fields: Vec<&str> = rest.split_whitespace().collect();
    // Fields after comm: state(0) ppid(1) pgrp(2) session(3) tty_nr(4)
    // tpgid(5) flags(6) minflt(7) cminflt(8) majflt(9) cmajflt(10)
    // utime(11) stime(12) cutime(13) cstime(14) priority(15) nice(16)
    // num_threads(17) itrealvalue(18) starttime(19) vsize(20) rss(21)
    if fields.len() < 22 {
        return Err(PstatError::ParseError(format!(
            "stat: expected >=22 fields after comm, got {}",
            fields.len()
        )));
    }

    let parse_u64 = |i: usize, name: &str| -> Result<u64, PstatError> {
        fields[i]
            .parse()
            .map_err(|_| PstatError::ParseError(format!("stat: bad {name} '{}'", fields[i])))
    };
    let parse_u32 = |i: usize, name: &str| -> Result<u32, PstatError> {
        fields[i]
            .parse()
            .map_err(|_| PstatError::ParseError(format!("stat: bad {name} '{}'", fields[i])))
    };
    let parse_i64 = |i: usize, name: &str| -> Result<i64, PstatError> {
        fields[i]
            .parse()
            .map_err(|_| PstatError::ParseError(format!("stat: bad {name} '{}'", fields[i])))
    };

    let state_char = fields[0]
        .chars()
        .next()
        .ok_or_else(|| PstatError::ParseError("stat: empty state".into()))?;

    Ok(StatFields {
        pid,
        comm,
        state: ProcessState::from_char(state_char),
        ppid: parse_u32(1, "ppid")?,
        utime: parse_u64(11, "utime")?,
        stime: parse_u64(12, "stime")?,
        num_threads: parse_u32(17, "num_threads")?,
        start_time: parse_u64(19, "starttime")?,
        vsize: parse_u64(20, "vsize")?,
        rss_pages: parse_i64(21, "rss")?,
    })
}

/// Fields extracted from /proc/[pid]/status.
#[derive(Debug, Default)]
pub struct StatusFields {
    pub vm_peak: Option<u64>,
    pub vm_size: Option<u64>,
    pub vm_rss: Option<u64>,
    /// VmHWM: peak RSS ever (High Water Mark). This is the actual peak physical memory.
    pub vm_hwm: Option<u64>,
    pub vm_swap: Option<u64>,
    pub rss_shared: Option<u64>,
    pub rss_file: Option<u64>,
    pub threads: Option<u32>,
    pub voluntary_ctxt_switches: Option<u64>,
    pub nonvoluntary_ctxt_switches: Option<u64>,
}

/// Parse /proc/[pid]/status content (key:\tvalue format).
pub fn parse_status(content: &str) -> Result<StatusFields, PstatError> {
    let mut f = StatusFields::default();
    for line in content.lines() {
        let Some((key, val)) = line.split_once(':') else { continue };
        let val = val.trim();
        match key {
            "VmPeak" => f.vm_peak = parse_kb_to_bytes(val),
            "VmSize" => f.vm_size = parse_kb_to_bytes(val),
            "VmRSS" => f.vm_rss = parse_kb_to_bytes(val),
            "VmHWM" => f.vm_hwm = parse_kb_to_bytes(val),
            "VmSwap" => f.vm_swap = parse_kb_to_bytes(val),
            "RssShmem" => f.rss_shared = parse_kb_to_bytes(val),
            "RssFile" => f.rss_file = parse_kb_to_bytes(val),
            "Threads" => f.threads = val.parse().ok(),
            "voluntary_ctxt_switches" => f.voluntary_ctxt_switches = val.parse().ok(),
            "nonvoluntary_ctxt_switches" => f.nonvoluntary_ctxt_switches = val.parse().ok(),
            _ => {}
        }
    }
    Ok(f)
}

/// Parse "12345 kB" -> bytes. Uses checked_mul to avoid overflow.
fn parse_kb_to_bytes(val: &str) -> Option<u64> {
    let num_str = val.split_whitespace().next()?;
    let kb: u64 = num_str.parse().ok()?;
    kb.checked_mul(1024)
}

/// Fields extracted from /proc/[pid]/io.
#[derive(Debug)]
pub struct IoFields {
    pub read_bytes: u64,
    pub write_bytes: u64,
    pub syscr: u64,
    pub syscw: u64,
}

/// Parse /proc/[pid]/io content. Returns None for PSTAT_UNAVAILABLE or empty input.
pub fn parse_io(content: &str) -> Result<Option<IoFields>, PstatError> {
    let content = content.trim();
    if content.is_empty() || content.contains("PSTAT_UNAVAILABLE") || content.contains("PSTAT_ERR")
    {
        return Ok(None);
    }

    let mut read_bytes = None;
    let mut write_bytes = None;
    let mut syscr = None;
    let mut syscw = None;

    for line in content.lines() {
        let line = line.trim();
        if line == "PSTAT_OK" {
            continue;
        }
        let Some((key, val)) = line.split_once(':') else { continue };
        let val = val.trim();
        match key.trim() {
            "read_bytes" => read_bytes = val.parse().ok(),
            "write_bytes" => write_bytes = val.parse().ok(),
            "syscr" => syscr = val.parse().ok(),
            "syscw" => syscw = val.parse().ok(),
            _ => {}
        }
    }

    match (read_bytes, write_bytes, syscr, syscw) {
        (Some(rb), Some(wb), Some(sr), Some(sw)) => Ok(Some(IoFields {
            read_bytes: rb,
            write_bytes: wb,
            syscr: sr,
            syscw: sw,
        })),
        _ => Ok(None),
    }
}

/// Parse hex-encoded cmdline (output of `od -An -tx1`).
///
/// Input looks like: " 2f 75 73 72 2f 62 69 6e 2f 66 6f 6f 00 2d 2d 66\n 6c 61 67 00"
/// We decode hex bytes and split on 0x00 to reconstruct argv.
pub fn parse_cmdline_hex(content: &str) -> Result<Vec<String>, PstatError> {
    let content = content.trim();
    if content.is_empty() || content == "PSTAT_OK" {
        return Ok(vec![]);
    }

    // Filter out PSTAT_OK/PSTAT_ERR markers
    let hex_content: String = content
        .lines()
        .filter(|l| {
            let t = l.trim();
            t != "PSTAT_OK" && t != "PSTAT_ERR"
        })
        .collect::<Vec<_>>()
        .join(" ");

    let bytes: Vec<u8> = hex_content
        .split_whitespace()
        .filter_map(|h| u8::from_str_radix(h, 16).ok())
        .collect();

    Ok(split_cmdline_bytes(&bytes))
}

/// Parse raw /proc/[pid]/cmdline bytes (null-byte separated, used for local collection).
pub fn parse_cmdline_raw(bytes: &[u8]) -> Vec<String> {
    split_cmdline_bytes(bytes)
}

/// Split cmdline bytes on null bytes into argument strings.
fn split_cmdline_bytes(bytes: &[u8]) -> Vec<String> {
    if bytes.is_empty() {
        return vec![];
    }
    bytes
        .split(|&b| b == 0)
        .filter(|s| !s.is_empty())
        .map(|s| String::from_utf8_lossy(s).into_owned())
        .collect()
}

/// Parse MemTotal from /proc/meminfo. Returns bytes.
pub fn parse_meminfo_total(content: &str) -> Result<u64, PstatError> {
    for line in content.lines() {
        if let Some(rest) = line.strip_prefix("MemTotal:") {
            return parse_kb_to_bytes(rest.trim())
                .ok_or_else(|| PstatError::ParseError("meminfo: bad MemTotal".into()));
        }
    }
    Err(PstatError::ParseError("meminfo: MemTotal not found".into()))
}

/// Fields from /proc/[pid]/smaps_rollup.
#[derive(Debug, Default)]
pub struct SmapsFields {
    pub pss: Option<u64>,
    pub shared_clean: Option<u64>,
    pub shared_dirty: Option<u64>,
    pub private_clean: Option<u64>,
    pub private_dirty: Option<u64>,
    pub referenced: Option<u64>,
    pub anonymous: Option<u64>,
    pub swap_pss: Option<u64>,
}

impl SmapsFields {
    /// USS = Private_Clean + Private_Dirty (memory freed when process exits).
    pub fn uss(&self) -> Option<u64> {
        match (self.private_clean, self.private_dirty) {
            (Some(c), Some(d)) => Some(c + d),
            _ => None,
        }
    }
}

/// Parse /proc/[pid]/smaps_rollup content. Returns None if unavailable.
pub fn parse_smaps_rollup(content: &str) -> Result<Option<SmapsFields>, PstatError> {
    let content = content.trim();
    if content.is_empty() || content.contains("PSTAT_UNAVAILABLE") || content.contains("PSTAT_ERR") {
        return Ok(None);
    }
    let mut f = SmapsFields::default();
    for line in content.lines() {
        let Some((key, val)) = line.split_once(':') else { continue };
        let val = val.trim();
        match key.trim() {
            "Pss" => f.pss = parse_kb_to_bytes(val),
            "Shared_Clean" => f.shared_clean = parse_kb_to_bytes(val),
            "Shared_Dirty" => f.shared_dirty = parse_kb_to_bytes(val),
            "Private_Clean" => f.private_clean = parse_kb_to_bytes(val),
            "Private_Dirty" => f.private_dirty = parse_kb_to_bytes(val),
            "Referenced" => f.referenced = parse_kb_to_bytes(val),
            "Anonymous" => f.anonymous = parse_kb_to_bytes(val),
            "SwapPss" => f.swap_pss = parse_kb_to_bytes(val),
            _ => {}
        }
    }
    Ok(Some(f))
}

/// Parse /proc/[pid]/smaps into per-VMA entries. Each VMA block starts with a
/// header line (address range + perm + offset + dev + inode + optional path)
/// followed by key:value detail lines.
pub fn parse_smaps(content: &str) -> Vec<VmaEntry> {
    let mut entries: Vec<VmaEntry> = Vec::new();
    let mut current: Option<VmaEntry> = None;

    for line in content.lines() {
        if is_smaps_header(line) {
            if let Some(e) = current.take() {
                entries.push(e);
            }
            current = Some(parse_smaps_header(line));
        } else if let Some(ref mut e) = current {
            let Some((key, val)) = line.split_once(':') else { continue };
            let val = val.trim();
            let Some(bytes) = parse_kb_to_bytes(val) else { continue };
            match key.trim() {
                "Size" => e.size = bytes,
                "Rss" => e.rss = bytes,
                "Pss" => e.pss = bytes,
                "Anonymous" => e.anonymous = bytes,
                "Swap" => e.swap = bytes,
                _ => {}
            }
        }
    }
    if let Some(e) = current.take() {
        entries.push(e);
    }
    detect_glibc_arenas(&mut entries);
    entries
}

/// Detect glibc secondary malloc arenas and relabel them as `[glibc-arena]`.
///
/// Signature: a private anonymous rw-p VMA followed immediately (same end/start
/// address) by a private anonymous ---p guard VMA. This is how glibc carves
/// secondary arenas for per-thread malloc — initial mmap allocates a 1 MB region
/// PROT_NONE then mprotects the used portion to RW, leaving the unused tail as
/// ---p. The kernel doesn't semantically label these so they otherwise land in
/// the "other anon" bucket even though they're really part of the heap.
fn detect_glibc_arenas(entries: &mut [VmaEntry]) {
    for i in 0..entries.len().saturating_sub(1) {
        let is_arena = {
            let data = &entries[i];
            let guard = &entries[i + 1];
            data.path.is_none()
                && data.label == "anon"
                && data.perm == "rw-p"
                && guard.path.is_none()
                && guard.label == "anon"
                && guard.perm == "---p"
                && data.end_addr == guard.start_addr
        };
        if is_arena {
            entries[i].label = "[glibc-arena]".to_string();
        }
    }
}

fn is_smaps_header(line: &str) -> bool {
    let first = line.split_whitespace().next().unwrap_or("");
    let Some((start, end)) = first.split_once('-') else {
        return false;
    };
    !start.is_empty()
        && !end.is_empty()
        && start.chars().all(|c| c.is_ascii_hexdigit())
        && end.chars().all(|c| c.is_ascii_hexdigit())
}

fn parse_smaps_header(line: &str) -> VmaEntry {
    let mut it = line.split_whitespace();
    let range = it.next().unwrap_or("");
    let (start_addr, end_addr) = range
        .split_once('-')
        .and_then(|(s, e)| Some((u64::from_str_radix(s, 16).ok()?, u64::from_str_radix(e, 16).ok()?)))
        .unwrap_or((0, 0));
    let perm = it.next().unwrap_or("").to_string();
    let _offset = it.next();
    let _device = it.next();
    let _inode = it.next();
    let tail: Vec<&str> = it.collect();
    let tail_joined = tail.join(" ");

    let (path, label) = if tail_joined.is_empty() {
        (None, "anon".to_string())
    } else if tail_joined.starts_with('[') {
        // [heap], [stack], [stack:TID], [tstack: ...], [vdso], [vectors], etc.
        (None, tail_joined.clone())
    } else {
        let basename = tail_joined
            .rsplit('/')
            .next()
            .unwrap_or(&tail_joined)
            .to_string();
        (Some(tail_joined), basename)
    };

    VmaEntry {
        start_addr,
        end_addr,
        perm,
        path,
        label,
        size: 0,
        rss: 0,
        pss: 0,
        anonymous: 0,
        swap: 0,
    }
}

/// Parse /proc/[pid]/oom_score (single integer).
pub fn parse_oom_score(content: &str) -> Option<u32> {
    content.trim().parse().ok()
}

/// Parse /proc/[pid]/oom_score_adj (single signed integer).
pub fn parse_oom_score_adj(content: &str) -> Option<i32> {
    content.trim().parse().ok()
}

/// Parse /proc/[pid]/cgroup. Returns the primary cgroup path.
pub fn parse_cgroup(content: &str) -> Option<String> {
    // Take the last line (cgroup v2 unified, or the most specific v1 cgroup)
    content
        .lines()
        .last()
        .and_then(|line| {
            // Format: "hierarchy-id:controller-list:path"
            let parts: Vec<&str> = line.splitn(3, ':').collect();
            parts.get(2).map(|p| p.trim().to_string())
        })
        .filter(|s| !s.is_empty())
}

/// Check a batched section for PSTAT_OK/PSTAT_ERR markers.
/// Returns (is_ok, content_without_marker).
pub fn check_section_status(section: &str) -> (bool, String) {
    let trimmed = section.trim();
    let lines: Vec<&str> = trimmed.lines().collect();

    // Check if any line is PSTAT_ERR
    if lines.iter().any(|l| l.trim() == "PSTAT_ERR") {
        let content: String = lines
            .iter()
            .filter(|l| {
                let t = l.trim();
                t != "PSTAT_OK" && t != "PSTAT_ERR"
            })
            .copied()
            .collect::<Vec<_>>()
            .join("\n");
        return (false, content);
    }

    // Strip PSTAT_OK markers
    let content: String = lines
        .iter()
        .filter(|l| l.trim() != "PSTAT_OK")
        .copied()
        .collect::<Vec<_>>()
        .join("\n");
    (true, content)
}

#[cfg(test)]
mod tests {
    use super::*;

    // Real captured data from Tizen target zeroclaw process.
    const TIZEN_STAT: &str = "18997 (zeroclaw) S 1 18997 18997 0 -1 1077936384 37032753 26488 20789020 75 88341 559444 164 113 20 0 6 0 2016830 51396608 700 4294967295 5029888 22216196 3182079456 0 0 0 0 4096 81923 0 0 0 17 2 0 0 0 0 0 22285624 23479524 30248960 3182079705 3182079759 3182079759 3182079978 0";

    const TIZEN_STATUS: &str = "\
Name:\tzeroclaw
Umask:\t0022
State:\tS (sleeping)
Tgid:\t18997
Ngid:\t0
Pid:\t18997
PPid:\t1
TracerPid:\t0
Uid:\t0\t0\t0\t0
Gid:\t0\t0\t0\t0
FDSize:\t256
Groups:\t
VmPeak:\t   55488 kB
VmSize:\t   50192 kB
VmRSS:\t    2800 kB
RssAnon:\t     616 kB
RssFile:\t    2184 kB
RssShmem:\t       0 kB
VmData:\t   27220 kB
VmStk:\t     224 kB
VmExe:\t   16784 kB
VmLib:\t    1972 kB
VmPTE:\t      62 kB
VmSwap:\t    5292 kB
Threads:\t6
voluntary_ctxt_switches:\t15
nonvoluntary_ctxt_switches:\t54";

    const TIZEN_IO: &str = "\
rchar: 704192372
wchar: 415934077
syscr: 1543406
syscw: 499360
read_bytes: 121702592512
write_bytes: 1141047296
cancelled_write_bytes: 631136256";

    #[test]
    fn parse_stat_normal() {
        let f = parse_stat("1234 (bash) S 1 1234 1234 0 -1 0 0 0 0 0 100 50 0 0 20 0 1 0 99999 1048576 256 0 0 0 0 0 0 0 0 0 0 0 0 0 0 0 0 0 0 0 0 0 0 0 0 0 0 0 0 0").unwrap();
        assert_eq!(f.pid, 1234);
        assert_eq!(f.comm, "bash");
        assert_eq!(f.state, ProcessState::Sleeping);
        assert_eq!(f.ppid, 1);
        assert_eq!(f.utime, 100);
        assert_eq!(f.stime, 50);
        assert_eq!(f.num_threads, 1);
        assert_eq!(f.start_time, 99999);
    }

    #[test]
    fn parse_stat_spaces_in_name() {
        let f = parse_stat("5678 (Web Content) R 100 5678 5678 0 -1 0 0 0 0 0 200 100 0 0 20 0 4 0 50000 2097152 512 0 0 0 0 0 0 0 0 0 0 0 0 0 0 0 0 0 0 0 0 0 0 0 0 0 0 0 0 0").unwrap();
        assert_eq!(f.pid, 5678);
        assert_eq!(f.comm, "Web Content");
        assert_eq!(f.state, ProcessState::Running);
    }

    #[test]
    fn parse_stat_parens_in_name() {
        let f = parse_stat("9999 ((sd-pam)) S 1 9999 9999 0 -1 0 0 0 0 0 10 5 0 0 20 0 1 0 1000 4096 100 0 0 0 0 0 0 0 0 0 0 0 0 0 0 0 0 0 0 0 0 0 0 0 0 0 0 0 0 0").unwrap();
        assert_eq!(f.comm, "(sd-pam)");
    }

    #[test]
    fn parse_stat_real_tizen() {
        let f = parse_stat(TIZEN_STAT).unwrap();
        assert_eq!(f.pid, 18997);
        assert_eq!(f.comm, "zeroclaw");
        assert_eq!(f.state, ProcessState::Sleeping);
        assert_eq!(f.ppid, 1);
        assert_eq!(f.utime, 88341);
        assert_eq!(f.stime, 559444);
        assert_eq!(f.num_threads, 6);
        assert_eq!(f.start_time, 2016830);
    }

    #[test]
    fn parse_stat_truncated() {
        let result = parse_stat("1234 (bash) S 1");
        assert!(result.is_err());
    }

    #[test]
    fn parse_stat_no_data_after_comm() {
        // Triggers the close+2 bounds check
        assert!(parse_stat("1234 (bash)").is_err());
        assert!(parse_stat("1234 (bash))").is_err());
    }

    #[test]
    fn parse_status_real_tizen() {
        let f = parse_status(TIZEN_STATUS).unwrap();
        assert_eq!(f.vm_peak, Some(55488 * 1024));
        assert_eq!(f.vm_size, Some(50192 * 1024));
        assert_eq!(f.vm_rss, Some(2800 * 1024));
        assert_eq!(f.vm_swap, Some(5292 * 1024));
        assert_eq!(f.rss_shared, Some(0));
        assert_eq!(f.rss_file, Some(2184 * 1024));
        assert_eq!(f.threads, Some(6));
        assert_eq!(f.voluntary_ctxt_switches, Some(15));
        assert_eq!(f.nonvoluntary_ctxt_switches, Some(54));
    }

    #[test]
    fn parse_status_missing_vm_swap() {
        let content = "Name:\ttest\nVmRSS:\t100 kB\nThreads:\t1\n";
        let f = parse_status(content).unwrap();
        assert_eq!(f.vm_rss, Some(100 * 1024));
        assert_eq!(f.vm_swap, None);
    }

    #[test]
    fn parse_status_kernel_thread() {
        let content = "Name:\tkworker\nState:\tI (idle)\nThreads:\t1\n";
        let f = parse_status(content).unwrap();
        assert_eq!(f.vm_rss, None);
        assert_eq!(f.threads, Some(1));
    }

    #[test]
    fn parse_io_normal() {
        let f = parse_io(TIZEN_IO).unwrap().unwrap();
        assert_eq!(f.read_bytes, 121702592512);
        assert_eq!(f.write_bytes, 1141047296);
        assert_eq!(f.syscr, 1543406);
        assert_eq!(f.syscw, 499360);
    }

    #[test]
    fn parse_io_unavailable() {
        assert!(parse_io("PSTAT_UNAVAILABLE").unwrap().is_none());
    }

    #[test]
    fn parse_io_err_marker() {
        assert!(parse_io("PSTAT_ERR").unwrap().is_none());
    }

    #[test]
    fn parse_io_empty() {
        assert!(parse_io("").unwrap().is_none());
    }

    #[test]
    fn parse_cmdline_hex_multi_arg() {
        // "/usr/bin/zeroclaw\0--config-dir\0/root/.zeroclaw\0daemon\0"
        let hex = " 2f 75 73 72 2f 62 69 6e 2f 7a 65 72 6f 63 6c 61\n 77 00 2d 2d 63 6f 6e 66 69 67 2d 64 69 72 00 2f\n 72 6f 6f 74 2f 2e 7a 65 72 6f 63 6c 61 77 00 64\n 61 65 6d 6f 6e 00";
        let args = parse_cmdline_hex(hex).unwrap();
        assert_eq!(args, vec![
            "/usr/bin/zeroclaw",
            "--config-dir",
            "/root/.zeroclaw",
            "daemon",
        ]);
    }

    #[test]
    fn parse_cmdline_hex_empty() {
        assert!(parse_cmdline_hex("").unwrap().is_empty());
    }

    #[test]
    fn parse_cmdline_hex_single_arg() {
        // "/bin/sh" with no trailing null
        let hex = "2f 62 69 6e 2f 73 68";
        let args = parse_cmdline_hex(hex).unwrap();
        assert_eq!(args, vec!["/bin/sh"]);
    }

    #[test]
    fn parse_cmdline_hex_with_marker() {
        let hex = " 2f 62 69 6e 2f 73 68 00\nPSTAT_OK";
        let args = parse_cmdline_hex(hex).unwrap();
        assert_eq!(args, vec!["/bin/sh"]);
    }

    #[test]
    fn parse_cmdline_raw_normal() {
        let bytes = b"/usr/bin/foo\0--flag\0value\0";
        let args = parse_cmdline_raw(bytes);
        assert_eq!(args, vec!["/usr/bin/foo", "--flag", "value"]);
    }

    #[test]
    fn parse_cmdline_raw_empty() {
        assert!(parse_cmdline_raw(b"").is_empty());
    }

    #[test]
    fn parse_meminfo_total() {
        let content = "MemTotal:        1821100 kB\nMemFree:          107604 kB\nMemAvailable:     624744 kB\n";
        let total = super::parse_meminfo_total(content).unwrap();
        assert_eq!(total, 1821100 * 1024);
    }

    #[test]
    fn check_section_pstat_ok() {
        let (ok, content) = check_section_status("PSTAT_OK\nhello world\n");
        assert!(ok);
        assert_eq!(content.trim(), "hello world");
    }

    #[test]
    fn check_section_pstat_err() {
        let (ok, _content) = check_section_status("PSTAT_ERR\n");
        assert!(!ok);
    }

    #[test]
    fn check_section_mixed() {
        let (ok, content) = check_section_status("some data\nPSTAT_OK\n");
        assert!(ok);
        assert_eq!(content.trim(), "some data");
    }

    #[test]
    fn parse_smaps_multiple_vmas() {
        let content = "\
00400000-004a2000 r-xp 00000000 fd:01 12345                              /usr/bin/foo
Size:                648 kB
Rss:                 192 kB
Pss:                 192 kB
Anonymous:             0 kB
Swap:                  0 kB
VmFlags: rd ex mr mw me dw sd
004a2000-004a3000 rw-p 000a2000 fd:01 12345                              /usr/bin/foo
Size:                  4 kB
Rss:                   4 kB
Pss:                   4 kB
Anonymous:             4 kB
Swap:                  0 kB
VmFlags: rd wr mr mw me ac sd
7fff12345000-7fff12367000 rw-p 00000000 00:00 0                          [stack]
Size:                140 kB
Rss:                  16 kB
Pss:                  16 kB
Anonymous:            16 kB
Swap:                  0 kB
VmFlags: rd wr mr mw me gd ac
";
        let entries = parse_smaps(content);
        assert_eq!(entries.len(), 3);

        assert_eq!(entries[0].perm, "r-xp");
        assert_eq!(entries[0].path.as_deref(), Some("/usr/bin/foo"));
        assert_eq!(entries[0].label, "foo");
        assert_eq!(entries[0].size, 648 * 1024);
        assert_eq!(entries[0].rss, 192 * 1024);
        assert_eq!(entries[0].anonymous, 0);

        assert_eq!(entries[1].perm, "rw-p");
        assert_eq!(entries[1].label, "foo");
        assert_eq!(entries[1].anonymous, 4 * 1024);

        assert_eq!(entries[2].path, None);
        assert_eq!(entries[2].label, "[stack]");
        assert_eq!(entries[2].rss, 16 * 1024);
    }

    #[test]
    fn parse_smaps_anonymous_mapping_has_no_label() {
        let content = "\
b2a00000-b2beb000 rw-p 00000000 00:00 0
Size:               1964 kB
Rss:                 104 kB
Pss:                 104 kB
Anonymous:           104 kB
Swap:                 32 kB
";
        let entries = parse_smaps(content);
        assert_eq!(entries.len(), 1);
        assert_eq!(entries[0].path, None);
        assert_eq!(entries[0].label, "anon");
        assert_eq!(entries[0].rss, 104 * 1024);
        assert_eq!(entries[0].swap, 32 * 1024);
    }

    #[test]
    fn parse_smaps_empty_returns_empty() {
        assert!(parse_smaps("").is_empty());
    }

    #[test]
    fn parse_smaps_detects_glibc_arena() {
        // Arena data rw-p at b2200000-b22df000 (892 KB)
        // followed by guard ---p at b22df000-b2300000 (132 KB, contiguous).
        // An unrelated unlabeled rw-p anon (not followed by a guard) should
        // stay as "anon" (not promoted).
        let content = "\
b2200000-b22df000 rw-p 00000000 00:00 0
Size:                892 kB
Rss:                   8 kB
Pss:                   8 kB
Anonymous:             8 kB
Swap:                  0 kB
b22df000-b2300000 ---p 00000000 00:00 0
Size:                132 kB
Rss:                   0 kB
Pss:                   0 kB
Anonymous:             0 kB
Swap:                  0 kB
c0000000-c0100000 rw-p 00000000 00:00 0
Size:               1024 kB
Rss:                  12 kB
Pss:                  12 kB
Anonymous:            12 kB
Swap:                  0 kB
";
        let entries = parse_smaps(content);
        assert_eq!(entries.len(), 3);
        assert_eq!(entries[0].label, "[glibc-arena]");
        assert_eq!(entries[1].label, "anon"); // the guard stays as anon
        assert_eq!(entries[2].label, "anon"); // standalone anon, no guard pair
    }
}
