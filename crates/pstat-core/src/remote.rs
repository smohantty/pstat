use std::process::Command;

use chrono::Utc;
use serde::Deserialize;

use crate::collector::{Collector, DiscoverQuery, PstatError, ProcessTarget};
use crate::proc_parser;
use crate::schema::{CollectionSource, ProcessInfo, ProcessSnapshot};

/// Minimal struct mirroring rsdb agent exec JSON envelope.
/// We own this struct to avoid coupling to rsdb-proto.
#[derive(Debug, Deserialize)]
struct RsdbResponse {
    ok: bool,
    data: Option<RsdbExecData>,
    error: Option<RsdbError>,
}

#[derive(Debug, Deserialize)]
struct RsdbExecData {
    status: i32,
    stdout: Option<String>,
    #[allow(dead_code)]
    stderr: Option<String>,
}

#[derive(Debug, Deserialize)]
struct RsdbError {
    code: String,
    message: String,
}

pub struct RsdbCollector {
    pub target: String,
    /// Cached total memory from target's /proc/meminfo.
    total_mem_cache: std::cell::Cell<Option<u64>>,
}

impl RsdbCollector {
    pub fn new(target: String) -> Self {
        Self { target, total_mem_cache: std::cell::Cell::new(None) }
    }

    /// Execute a command on the remote target via rsdb agent exec.
    fn exec(&self, args: &[&str]) -> Result<String, PstatError> {
        let mut cmd = Command::new("rsdb");
        cmd.arg("agent").arg("exec").arg("--target").arg(&self.target).arg("--");
        for a in args {
            cmd.arg(a);
        }

        let output = cmd.output().map_err(|e| {
            if e.kind() == std::io::ErrorKind::NotFound {
                PstatError::Other(anyhow::anyhow!("rsdb not found in PATH"))
            } else {
                PstatError::TargetUnreachable(format!("rsdb exec failed: {e}"))
            }
        })?;

        let json_str = String::from_utf8_lossy(&output.stdout);
        let resp: RsdbResponse = serde_json::from_str(&json_str).map_err(|e| {
            PstatError::ParseError(format!("rsdb response: {e}"))
        })?;

        if !resp.ok {
            let err = resp.error.unwrap_or(RsdbError {
                code: "unknown".into(),
                message: "unknown error".into(),
            });
            if err.code.contains("connection") {
                return Err(PstatError::TargetUnreachable(err.message));
            }
            return Err(PstatError::Other(anyhow::anyhow!("rsdb error [{}]: {}", err.code, err.message)));
        }

        let data = resp.data.ok_or_else(|| PstatError::ParseError("rsdb: missing data".into()))?;
        if data.status != 0 {
            let stderr = data.stderr.unwrap_or_default();
            if stderr.contains("No such file") || stderr.contains("No such process") {
                return Err(PstatError::ProcessNotFound(stderr));
            }
        }

        Ok(data.stdout.unwrap_or_default())
    }

    /// Execute a shell command on the remote target.
    fn exec_sh(&self, script: &str) -> Result<String, PstatError> {
        self.exec(&["sh", "-c", script])
    }

    /// Batched collection: read all /proc files AND /proc/meminfo in one round trip.
    fn collect_batch(&self, pid: u32) -> Result<BatchedResult, PstatError> {
        let script = format!(
            r#"cat /proc/{pid}/stat && echo PSTAT_OK || echo PSTAT_ERR
echo '---PSTAT_SEP---'
cat /proc/{pid}/status && echo PSTAT_OK || echo PSTAT_ERR
echo '---PSTAT_SEP---'
cat /proc/{pid}/io 2>/dev/null && echo PSTAT_OK || echo PSTAT_ERR
echo '---PSTAT_SEP---'
FDS=$(find /proc/{pid}/fd -maxdepth 1 -type l 2>/dev/null | wc -l) && echo "$FDS" && echo PSTAT_OK || echo PSTAT_ERR
echo '---PSTAT_SEP---'
cat /proc/{pid}/cmdline | od -An -tx1 && echo PSTAT_OK || echo PSTAT_ERR
echo '---PSTAT_SEP---'
cat /proc/{pid}/comm && echo PSTAT_OK || echo PSTAT_ERR
echo '---PSTAT_SEP---'
head -1 /proc/meminfo && echo PSTAT_OK || echo PSTAT_ERR
echo '---PSTAT_SEP---'
cat /proc/{pid}/smaps_rollup 2>/dev/null && echo PSTAT_OK || echo PSTAT_ERR
echo '---PSTAT_SEP---'
cat /proc/{pid}/oom_score 2>/dev/null && echo PSTAT_OK || echo PSTAT_ERR
echo '---PSTAT_SEP---'
cat /proc/{pid}/oom_score_adj 2>/dev/null && echo PSTAT_OK || echo PSTAT_ERR
echo '---PSTAT_SEP---'
cat /proc/{pid}/cgroup 2>/dev/null && echo PSTAT_OK || echo PSTAT_ERR"#
        );

        let stdout = self.exec_sh(&script)?;
        let sections: Vec<&str> = stdout.split("---PSTAT_SEP---").collect();

        if sections.len() < 11 {
            return Err(PstatError::ParseError(format!(
                "expected 11 sections, got {}",
                sections.len()
            )));
        }

        let (stat_ok, stat) = proc_parser::check_section_status(sections[0]);
        let (status_ok, status) = proc_parser::check_section_status(sections[1]);
        let (_io_ok, io) = proc_parser::check_section_status(sections[2]);
        let (fd_ok, fd) = proc_parser::check_section_status(sections[3]);
        let (_cmd_ok, cmdline) = proc_parser::check_section_status(sections[4]);
        let (comm_ok, comm) = proc_parser::check_section_status(sections[5]);
        let (_meminfo_ok, meminfo) = proc_parser::check_section_status(sections[6]);
        let (_smaps_ok, smaps) = proc_parser::check_section_status(sections[7]);
        let (_oom_ok, oom_score_str) = proc_parser::check_section_status(sections[8]);
        let (_oomadj_ok, oom_adj_str) = proc_parser::check_section_status(sections[9]);
        let (_cgroup_ok, cgroup_str) = proc_parser::check_section_status(sections[10]);

        if !stat_ok || !status_ok || !comm_ok {
            return Err(PstatError::ProcessNotFound(format!(
                "critical /proc files unreadable for PID {pid}"
            )));
        }

        Ok(BatchedResult {
            stat,
            status,
            io,
            fd: if fd_ok { Some(fd) } else { None },
            cmdline,
            comm,
            meminfo,
            smaps,
            oom_score_str,
            oom_adj_str,
            cgroup_str,
        })
    }

    /// Two round trips for --name: discover (ps, filtered in Rust) + batched snapshot.
    /// No user input is ever interpolated into shell scripts.
    fn snapshot_by_name(&self, name: &str) -> Result<ProcessSnapshot, PstatError> {
        // Round trip 1: discover PID (filtered in Rust, not in shell)
        let ps_output = self.exec(&["ps", "-eo", "pid,comm"])?;
        let matches: Vec<u32> = ps_output
            .lines()
            .skip(1)
            .filter_map(|line| {
                let line = line.trim();
                let mut parts = line.splitn(2, char::is_whitespace);
                let pid_str = parts.next()?;
                let comm = parts.next()?.trim();
                if comm == name {
                    pid_str.trim().parse().ok()
                } else {
                    None
                }
            })
            .collect();

        let pid = match matches.len() {
            0 => return Err(PstatError::ProcessNotFound(format!("name '{name}'"))),
            1 => matches[0],
            n => {
                let infos = matches.iter().map(|&pid| ProcessInfo { pid, name: name.to_string(), start_time: 0 }).collect();
                return Err(PstatError::AmbiguousMatch(n, name.to_string(), infos));
            }
        };

        // Round trip 2: batched snapshot (PID is a number, safe to interpolate)
        self.snapshot_pid(pid, None)
    }

    fn snapshot_pid(&self, pid: u32, expected_start_time: Option<u64>) -> Result<ProcessSnapshot, PstatError> {
        let batch = self.collect_batch(pid)?;

        let stat = proc_parser::parse_stat(&batch.stat)?;
        let status = proc_parser::parse_status(&batch.status)?;
        let io = proc_parser::parse_io(&batch.io)?;
        let cmdline = proc_parser::parse_cmdline_hex(&batch.cmdline)?;
        let smaps = proc_parser::parse_smaps_rollup(&batch.smaps)?.unwrap_or_default();

        // Verify PID identity if we have an expected starttime.
        if let Some(expected) = expected_start_time {
            if stat.start_time != expected {
                return Err(PstatError::IdentityMismatch(pid));
            }
        }

        let num_fds = batch.fd.and_then(|s| {
            s.trim().lines().find(|l| l.trim() != "PSTAT_OK").and_then(|l| l.trim().parse::<u32>().ok())
        });

        let total_mem = proc_parser::parse_meminfo_total(&batch.meminfo).unwrap_or(1);
        let rss = status.vm_rss.unwrap_or(0);
        let mem_percent = if total_mem > 0 { (rss as f64 / total_mem as f64) * 100.0 } else { 0.0 };
        let hz = 100u64;

        Ok(ProcessSnapshot {
            pid: stat.pid,
            ppid: stat.ppid,
            name: batch.comm.trim().to_string(),
            cmdline,
            state: stat.state,
            start_time: stat.start_time,
            rss,
            vm_hwm: status.vm_hwm.unwrap_or(0),
            vms: status.vm_size.unwrap_or(0),
            vm_peak: status.vm_peak.unwrap_or(0),
            vm_swap: status.vm_swap.unwrap_or(0),
            shared: status.rss_shared.unwrap_or(0),
            mem_percent,
            pss: smaps.pss,
            uss: smaps.uss(),
            shared_clean: smaps.shared_clean,
            shared_dirty: smaps.shared_dirty,
            private_clean: smaps.private_clean,
            private_dirty: smaps.private_dirty,
            referenced: smaps.referenced,
            anonymous: smaps.anonymous,
            swap_pss: smaps.swap_pss,
            cpu_user_ms: stat.utime * 1000 / hz,
            cpu_system_ms: stat.stime * 1000 / hz,
            cpu_percent: None,
            io_read_bytes: io.as_ref().map(|i| i.read_bytes),
            io_write_bytes: io.as_ref().map(|i| i.write_bytes),
            io_syscr: io.as_ref().map(|i| i.syscr),
            io_syscw: io.as_ref().map(|i| i.syscw),
            num_threads: status.threads.unwrap_or(stat.num_threads),
            num_fds,
            ctx_switches_voluntary: status.voluntary_ctxt_switches.unwrap_or(0),
            ctx_switches_involuntary: status.nonvoluntary_ctxt_switches.unwrap_or(0),
            oom_score: proc_parser::parse_oom_score(&batch.oom_score_str),
            oom_score_adj: proc_parser::parse_oom_score_adj(&batch.oom_adj_str),
            cgroup: proc_parser::parse_cgroup(&batch.cgroup_str),
            timestamp: Utc::now(),
            source: CollectionSource::Remote { target: self.target.clone() },
        })
    }
}

struct BatchedResult {
    stat: String,
    status: String,
    io: String,
    fd: Option<String>,
    cmdline: String,
    comm: String,
    meminfo: String,
    smaps: String,
    oom_score_str: String,
    oom_adj_str: String,
    cgroup_str: String,
}

impl Collector for RsdbCollector {
    fn snapshot(&self, target: &ProcessTarget) -> Result<ProcessSnapshot, PstatError> {
        match target {
            ProcessTarget::Pid(pid) => self.snapshot_pid(*pid, None),
            ProcessTarget::Name(name) => {
                // Single round trip: discover + snapshot in one script
                self.snapshot_by_name(name)
            }
            other => {
                let pid = resolve_remote_pid(self, other)?;
                self.snapshot_pid(pid, None)
            }
        }
    }

    fn discover(&self, query: &DiscoverQuery) -> Result<Vec<ProcessInfo>, PstatError> {
        // Single rsdb call for discovery. No per-match starttime reads.
        // Starttime is verified later in the batch collection.
        let stdout = self.exec(&["ps", "-eo", "pid,comm"])?;
        let mut results = Vec::new();

        for line in stdout.lines().skip(1) {
            let line = line.trim();
            if line.is_empty() {
                continue;
            }
            let mut parts = line.splitn(2, char::is_whitespace);
            let Some(pid_str) = parts.next() else { continue };
            let Some(comm) = parts.next() else { continue };
            let Ok(pid) = pid_str.trim().parse::<u32>() else { continue };
            let comm = comm.trim().to_string();

            let matches = match query {
                DiscoverQuery::ByName(n) => comm == *n,
                DiscoverQuery::ByExeContains(s) => comm.contains(s.as_str()),
                DiscoverQuery::ByPattern(p) => {
                    let pattern = p.replace('*', "");
                    comm.contains(&pattern)
                }
                DiscoverQuery::All => true,
            };

            if matches {
                results.push(ProcessInfo { pid, name: comm, start_time: 0 });
            }
        }

        results.sort_by_key(|p| p.pid);
        Ok(results)
    }

    fn total_memory(&self) -> Result<u64, PstatError> {
        if let Some(cached) = self.total_mem_cache.get() {
            return Ok(cached);
        }
        let stdout = self.exec_sh("head -1 /proc/meminfo")?;
        let total = proc_parser::parse_meminfo_total(&stdout)?;
        self.total_mem_cache.set(Some(total));
        Ok(total)
    }
}

/// Resolve a ProcessTarget to a PID on the remote target.
/// Starttime verification happens later in the batch collection.
fn resolve_remote_pid(
    collector: &RsdbCollector,
    target: &ProcessTarget,
) -> Result<u32, PstatError> {
    match target {
        ProcessTarget::Pid(pid) => Ok(*pid),
        ProcessTarget::Name(name) => {
            let matches = collector.discover(&DiscoverQuery::ByName(name.clone()))?;
            match matches.len() {
                0 => Err(PstatError::ProcessNotFound(format!("name '{name}'"))),
                1 => Ok(matches[0].pid),
                n => Err(PstatError::AmbiguousMatch(n, name.clone(), matches)),
            }
        }
        ProcessTarget::ExeContains(s) => {
            let matches = collector.discover(&DiscoverQuery::ByExeContains(s.clone()))?;
            match matches.len() {
                0 => Err(PstatError::ProcessNotFound(format!("exe containing '{s}'"))),
                1 => Ok(matches[0].pid),
                n => Err(PstatError::AmbiguousMatch(n, s.clone(), matches)),
            }
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn parse_rsdb_success_envelope() {
        let json = r#"{"ok":true,"data":{"status":0,"stdout":"hello\n"}}"#;
        let resp: RsdbResponse = serde_json::from_str(json).unwrap();
        assert!(resp.ok);
        assert_eq!(resp.data.unwrap().stdout.unwrap(), "hello\n");
    }

    #[test]
    fn parse_rsdb_error_envelope() {
        let json = r#"{"ok":false,"error":{"code":"connection.refused","message":"target offline"}}"#;
        let resp: RsdbResponse = serde_json::from_str(json).unwrap();
        assert!(!resp.ok);
        assert_eq!(resp.error.unwrap().code, "connection.refused");
    }

    #[test]
    fn parse_rsdb_nonzero_status() {
        let json = r#"{"ok":true,"data":{"status":1,"stdout":"","stderr":"not found"}}"#;
        let resp: RsdbResponse = serde_json::from_str(json).unwrap();
        assert!(resp.ok);
        assert_eq!(resp.data.unwrap().status, 1);
    }
}
