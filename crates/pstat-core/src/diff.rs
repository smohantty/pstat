use crate::schema::{DiffField, DiffReport, DiffSeverity, ProcessSnapshot};

/// Compute the diff between two snapshots.
pub fn compute_diff(before: &ProcessSnapshot, after: &ProcessSnapshot) -> DiffReport {
    let elapsed_s = (after.timestamp - before.timestamp).num_milliseconds() as f64 / 1000.0;
    let mut deltas = Vec::new();

    let add = |deltas: &mut Vec<DiffField>, name: &str, b: f64, a: f64, is_mem: bool| {
        let severity = DiffSeverity::classify(b, a, is_mem);
        deltas.push(DiffField {
            name: name.to_string(),
            before: b,
            after: a,
            delta: a - b,
            severity,
        });
    };

    add(&mut deltas, "RSS", before.rss as f64, after.rss as f64, true);
    add(&mut deltas, "VMS", before.vms as f64, after.vms as f64, true);
    add(&mut deltas, "VM Peak", before.vm_peak as f64, after.vm_peak as f64, true);
    add(&mut deltas, "VM Swap", before.vm_swap as f64, after.vm_swap as f64, true);
    add(&mut deltas, "Shared", before.shared as f64, after.shared as f64, true);
    add(
        &mut deltas,
        "CPU (user)",
        before.cpu_user_ms as f64,
        after.cpu_user_ms as f64,
        false,
    );
    add(
        &mut deltas,
        "CPU (system)",
        before.cpu_system_ms as f64,
        after.cpu_system_ms as f64,
        false,
    );

    // IO fields: only diff if both are Some.
    if let (Some(br), Some(ar)) = (before.io_read_bytes, after.io_read_bytes) {
        add(&mut deltas, "IO Read", br as f64, ar as f64, false);
    }
    if let (Some(bw), Some(aw)) = (before.io_write_bytes, after.io_write_bytes) {
        add(&mut deltas, "IO Write", bw as f64, aw as f64, false);
    }

    add(
        &mut deltas,
        "Threads",
        before.num_threads as f64,
        after.num_threads as f64,
        false,
    );

    if let (Some(bf), Some(af)) = (before.num_fds, after.num_fds) {
        add(&mut deltas, "FDs", bf as f64, af as f64, false);
    }

    add(
        &mut deltas,
        "CtxSw (vol)",
        before.ctx_switches_voluntary as f64,
        after.ctx_switches_voluntary as f64,
        false,
    );
    add(
        &mut deltas,
        "CtxSw (invol)",
        before.ctx_switches_involuntary as f64,
        after.ctx_switches_involuntary as f64,
        false,
    );

    DiffReport {
        before: before.clone(),
        after: after.clone(),
        elapsed_s,
        deltas,
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::schema::{CollectionSource, ProcessState};
    use chrono::Utc;

    fn make_snap(rss: u64, io_read: Option<u64>, fds: Option<u32>) -> ProcessSnapshot {
        ProcessSnapshot {
            pid: 1,
            ppid: 0,
            name: "test".into(),
            cmdline: vec![],
            state: ProcessState::Running,
            start_time: 100,
            rss,
            vms: rss * 2,
            vm_hwm: rss * 2,
            vm_peak: rss * 3,
            vm_swap: 0,
            shared: 0,
            rss_file: 0,
            exe_size: None,
            mem_percent: 0.0,
            cpu_user_ms: 1000,
            cpu_system_ms: 200,
            cpu_percent: None,
            io_read_bytes: io_read,
            io_write_bytes: io_read,
            io_syscr: None,
            io_syscw: None,
            num_threads: 4,
            num_fds: fds,
            ctx_switches_voluntary: 100,
            ctx_switches_involuntary: 10,
            pss: None, uss: None, shared_clean: None, shared_dirty: None,
            private_clean: None, private_dirty: None, referenced: None,
            anonymous: None, swap_pss: None,
            oom_score: None, oom_score_adj: None, cgroup: None,
            timestamp: Utc::now(),
            source: CollectionSource::Local,
        }
    }

    #[test]
    fn diff_memory_growth() {
        let before = make_snap(45 * 1024 * 1024, Some(1000), Some(10));
        let after = make_snap(82 * 1024 * 1024, Some(2000), Some(10));
        let report = compute_diff(&before, &after);
        let rss = report.deltas.iter().find(|d| d.name == "RSS").unwrap();
        assert!(rss.delta > 0.0);
        assert_eq!(rss.severity, DiffSeverity::Significant);
    }

    #[test]
    fn diff_no_change() {
        let snap = make_snap(1024, Some(100), Some(5));
        let report = compute_diff(&snap, &snap);
        for d in &report.deltas {
            assert_eq!(d.delta, 0.0);
            assert_eq!(d.severity, DiffSeverity::Minor);
        }
    }

    #[test]
    fn diff_io_none_skipped() {
        let before = make_snap(1024, None, Some(5));
        let after = make_snap(1024, Some(100), Some(5));
        let report = compute_diff(&before, &after);
        assert!(!report.deltas.iter().any(|d| d.name == "IO Read"));
    }

    #[test]
    fn diff_severity_thresholds() {
        assert_eq!(DiffSeverity::classify(100.0, 105.0, false), DiffSeverity::Minor);
        assert_eq!(DiffSeverity::classify(100.0, 130.0, false), DiffSeverity::Moderate);
        assert_eq!(DiffSeverity::classify(100.0, 200.0, false), DiffSeverity::Significant);
    }
}
