use std::fs;
use std::path::PathBuf;

use chrono::Utc;

use crate::collector::{Collector, DiscoverQuery, ProcessTarget, PstatError, ticks_to_millis};
use crate::proc_parser;
use crate::schema::{CollectionSource, MemoryMapReport, ProcessInfo, ProcessSnapshot};

pub struct LocalCollector;

impl LocalCollector {
    fn proc_path(pid: u32, file: &str) -> PathBuf {
        PathBuf::from(format!("/proc/{pid}/{file}"))
    }

    fn read_proc(pid: u32, file: &str) -> Result<String, PstatError> {
        fs::read_to_string(Self::proc_path(pid, file)).map_err(|e| {
            if e.kind() == std::io::ErrorKind::NotFound {
                PstatError::ProcessNotFound(format!("PID {pid}"))
            } else if e.kind() == std::io::ErrorKind::PermissionDenied {
                PstatError::PermissionDenied(format!("/proc/{pid}/{file}"))
            } else {
                PstatError::Other(e.into())
            }
        })
    }

    fn read_proc_optional(pid: u32, file: &str) -> Option<String> {
        fs::read_to_string(Self::proc_path(pid, file)).ok()
    }

    fn clock_ticks_per_second() -> Result<u64, PstatError> {
        let hz = unsafe { libc::sysconf(libc::_SC_CLK_TCK) };
        if hz <= 0 {
            return Err(PstatError::ParseError("local CLK_TCK unavailable".into()));
        }
        Ok(hz as u64)
    }

    fn snapshot_pid(&self, pid: u32) -> Result<ProcessSnapshot, PstatError> {
        let stat_content = Self::read_proc(pid, "stat")?;
        let status_content = Self::read_proc(pid, "status")?;
        let comm_content = Self::read_proc(pid, "comm")?;

        let stat = proc_parser::parse_stat(&stat_content)?;
        let status = proc_parser::parse_status(&status_content)?;

        // Optional files
        let io = Self::read_proc_optional(pid, "io")
            .and_then(|c| proc_parser::parse_io(&c).ok().flatten());

        let smaps = Self::read_proc_optional(pid, "smaps_rollup")
            .and_then(|c| proc_parser::parse_smaps_rollup(&c).ok().flatten())
            .unwrap_or_default();

        let num_fds = fs::read_dir(format!("/proc/{pid}/fd"))
            .ok()
            .map(|entries| entries.count() as u32);

        let cmdline_bytes = fs::read(format!("/proc/{pid}/cmdline")).unwrap_or_default();
        let cmdline = proc_parser::parse_cmdline_raw(&cmdline_bytes);

        let oom_score = Self::read_proc_optional(pid, "oom_score")
            .and_then(|c| proc_parser::parse_oom_score(&c));
        let oom_score_adj = Self::read_proc_optional(pid, "oom_score_adj")
            .and_then(|c| proc_parser::parse_oom_score_adj(&c));
        let cgroup =
            Self::read_proc_optional(pid, "cgroup").and_then(|c| proc_parser::parse_cgroup(&c));

        // /proc/[pid]/exe is a magic symlink — fs::metadata follows it and returns the binary's stat.
        let exe_size = fs::metadata(Self::proc_path(pid, "exe")).ok().map(|m| m.len());

        let total_mem = self.total_memory().unwrap_or(1);
        let rss = status.vm_rss.unwrap_or(0);
        let mem_percent = if total_mem > 0 {
            (rss as f64 / total_mem as f64) * 100.0
        } else {
            0.0
        };

        let hz = Self::clock_ticks_per_second()?;

        Ok(ProcessSnapshot {
            pid: stat.pid,
            ppid: stat.ppid,
            name: comm_content.trim().to_string(),
            cmdline,
            state: stat.state,
            start_time: stat.start_time,
            rss,
            vm_hwm: status.vm_hwm.unwrap_or(0),
            vms: status.vm_size.unwrap_or(0),
            vm_peak: status.vm_peak.unwrap_or(0),
            vm_swap: status.vm_swap.unwrap_or(0),
            shared: status.rss_shared.unwrap_or(0),
            rss_file: status.rss_file.unwrap_or(0),
            exe_size,
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
            cpu_user_ms: ticks_to_millis(stat.utime, hz),
            cpu_system_ms: ticks_to_millis(stat.stime, hz),
            cpu_percent: None,
            io_read_bytes: io.as_ref().map(|i| i.read_bytes),
            io_write_bytes: io.as_ref().map(|i| i.write_bytes),
            io_syscr: io.as_ref().map(|i| i.syscr),
            io_syscw: io.as_ref().map(|i| i.syscw),
            num_threads: status.threads.unwrap_or(stat.num_threads),
            num_fds,
            ctx_switches_voluntary: status.voluntary_ctxt_switches.unwrap_or(0),
            ctx_switches_involuntary: status.nonvoluntary_ctxt_switches.unwrap_or(0),
            oom_score,
            oom_score_adj,
            cgroup,
            timestamp: Utc::now(),
            source: CollectionSource::Local,
        })
    }
}

impl Collector for LocalCollector {
    fn snapshot(&self, target: &ProcessTarget) -> Result<ProcessSnapshot, PstatError> {
        let (pid, expected_start_time) = resolve_local(self, target)?;
        let snap = self.snapshot_pid(pid)?;
        // Verify PID identity: starttime must match what we discovered
        if let Some(expected) = expected_start_time {
            if expected != 0 && snap.start_time != expected {
                return Err(PstatError::IdentityMismatch(pid));
            }
        }
        Ok(snap)
    }

    fn discover(&self, query: &DiscoverQuery) -> Result<Vec<ProcessInfo>, PstatError> {
        let mut results = Vec::new();
        let entries = fs::read_dir("/proc").map_err(|e| PstatError::Other(e.into()))?;

        for entry in entries.flatten() {
            let name = entry.file_name();
            let name_str = name.to_string_lossy();
            let Ok(pid) = name_str.parse::<u32>() else {
                continue;
            };

            let Ok(comm) = fs::read_to_string(format!("/proc/{pid}/comm")) else {
                continue;
            };
            let comm = comm.trim().to_string();

            let matches = match query {
                DiscoverQuery::ByName(n) => comm == *n,
                DiscoverQuery::ByExeContains(s) => {
                    let cmdline = fs::read(format!("/proc/{pid}/cmdline")).unwrap_or_default();
                    let full = String::from_utf8_lossy(&cmdline);
                    full.contains(s.as_str())
                }
                DiscoverQuery::ByPattern(p) => {
                    // Simple glob: * matches anything
                    let pattern = p.replace('*', "");
                    comm.contains(&pattern)
                }
                DiscoverQuery::All => true,
            };

            if matches {
                // Read starttime for identity verification
                let start_time = fs::read_to_string(format!("/proc/{pid}/stat"))
                    .ok()
                    .and_then(|s| proc_parser::parse_stat(&s).ok())
                    .map(|s| s.start_time)
                    .unwrap_or(0);

                results.push(ProcessInfo {
                    pid,
                    name: comm,
                    start_time,
                });
            }
        }

        results.sort_by_key(|p| p.pid);
        Ok(results)
    }

    fn total_memory(&self) -> Result<u64, PstatError> {
        let content =
            fs::read_to_string("/proc/meminfo").map_err(|e| PstatError::Other(e.into()))?;
        proc_parser::parse_meminfo_total(&content)
    }

    fn memory_map(&self, target: &ProcessTarget) -> Result<MemoryMapReport, PstatError> {
        let (pid, _) = resolve_local(self, target)?;
        let smaps = Self::read_proc(pid, "smaps")?;
        let entries = proc_parser::parse_smaps(&smaps);

        let comm = Self::read_proc(pid, "comm")?.trim().to_string();
        let exe_path = fs::read_link(Self::proc_path(pid, "exe"))
            .ok()
            .and_then(|p| p.to_str().map(|s| s.to_string()));
        let exe_size = fs::metadata(Self::proc_path(pid, "exe")).ok().map(|m| m.len());
        let total_rss = entries.iter().map(|e| e.rss).sum();

        Ok(MemoryMapReport {
            pid,
            name: comm,
            exe_path,
            exe_size,
            total_rss,
            entries,
            timestamp: Utc::now(),
            source: CollectionSource::Local,
        })
    }
}

/// Resolve a ProcessTarget to (PID, Option<start_time>) for identity verification.
fn resolve_local(
    collector: &LocalCollector,
    target: &ProcessTarget,
) -> Result<(u32, Option<u64>), PstatError> {
    match target {
        ProcessTarget::Pid(pid) => Ok((*pid, None)),
        ProcessTarget::Name(name) => {
            let matches = collector.discover(&DiscoverQuery::ByName(name.clone()))?;
            match matches.len() {
                0 => Err(PstatError::ProcessNotFound(format!("name '{name}'"))),
                1 => Ok((matches[0].pid, Some(matches[0].start_time))),
                n => Err(PstatError::AmbiguousMatch(n, name.clone(), matches)),
            }
        }
        ProcessTarget::ExeContains(s) => {
            let matches = collector.discover(&DiscoverQuery::ByExeContains(s.clone()))?;
            match matches.len() {
                0 => Err(PstatError::ProcessNotFound(format!("exe containing '{s}'"))),
                1 => Ok((matches[0].pid, Some(matches[0].start_time))),
                n => Err(PstatError::AmbiguousMatch(n, s.clone(), matches)),
            }
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn snapshot_self() {
        let collector = LocalCollector;
        let pid = std::process::id();
        let snap = collector
            .snapshot(&ProcessTarget::Pid(pid))
            .expect("should snapshot own process");
        assert_eq!(snap.pid, pid);
        assert!(snap.rss > 0);
        assert!(snap.num_threads > 0);
        assert!(snap.start_time > 0);
        assert_eq!(snap.source, CollectionSource::Local);
    }

    #[test]
    fn snapshot_nonexistent() {
        let collector = LocalCollector;
        let result = collector.snapshot(&ProcessTarget::Pid(999_999_999));
        assert!(matches!(result, Err(PstatError::ProcessNotFound(_))));
    }

    #[test]
    fn discover_own_process() {
        let collector = LocalCollector;
        let results = collector.discover(&DiscoverQuery::All).unwrap();
        assert!(!results.is_empty());
    }

    #[test]
    fn total_memory_positive() {
        let collector = LocalCollector;
        let mem = collector.total_memory().unwrap();
        assert!(mem > 0);
    }
}
