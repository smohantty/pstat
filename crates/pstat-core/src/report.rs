use comfy_table::{Attribute, Cell, CellAlignment, ContentArrangement, Table, presets};

use crate::schema::{
    CollectionSource, DiffReport, DiffSeverity, MemoryMapReport, ProcessSnapshot, SampleSeries,
    SampleSummary, StatBucket, Trend, VmaEntry, VmaKind,
};

/// Format a snapshot as pretty JSON.
pub fn format_json(snapshot: &ProcessSnapshot) -> String {
    serde_json::to_string_pretty(snapshot).unwrap_or_else(|e| format!("{{\"error\": \"{e}\"}}"))
}

/// Format a snapshot as markdown. `verbose` controls which fields are shown.
fn format_snapshot_markdown(snapshot: &ProcessSnapshot, verbose: bool) -> String {
    let source = match &snapshot.source {
        CollectionSource::Local => "local".to_string(),
        CollectionSource::Remote { target } => format!("remote ({target})"),
    };
    let state = format!("{:?}", snapshot.state);
    let time = snapshot
        .timestamp
        .format("%Y-%m-%d %H:%M:%S UTC")
        .to_string();

    let mut md = String::new();
    if let Some(sz) = snapshot.exe_size {
        md.push_str(&format!(
            "# {} (PID {}) \u{00b7} size: {}\n\n",
            snapshot.name,
            snapshot.pid,
            fmt_bytes(sz as f64)
        ));
    } else {
        md.push_str(&format!("# {} (PID {})\n\n", snapshot.name, snapshot.pid));
    }
    if !snapshot.cmdline.is_empty() {
        md.push_str(&format!("`{}`\n\n", snapshot.cmdline.join(" ")));
    }
    md.push_str(&format!("{source} \u{00b7} {state} \u{00b7} {time}\n\n"));

    md.push_str("| Metric | Value |\n");
    md.push_str("|--------|-------|\n");
    md.push_str(&format!(
        "| Resident (VmRSS) | {} |\n",
        fmt_bytes(snapshot.rss as f64)
    ));
    if let Some(a) = snapshot.anonymous {
        md.push_str(&format!(
            "| Anon (heap+stack) | {} |\n",
            fmt_bytes(a as f64)
        ));
    }
    md.push_str(&format!(
        "| File-backed (RssFile) | {} |\n",
        fmt_bytes(snapshot.rss_file as f64)
    ));
    if verbose {
        md.push_str(&format!(
            "| Shmem (RssShmem) | {} |\n",
            fmt_bytes(snapshot.shared as f64)
        ));
    }
    if let Some(uss) = snapshot.uss {
        md.push_str(&format!("| Unique (USS) | {} |\n", fmt_bytes(uss as f64)));
    }
    if let Some(pss) = snapshot.pss {
        md.push_str(&format!(
            "| Proportional (Pss) | {} |\n",
            fmt_bytes(pss as f64)
        ));
    }
    if verbose {
        if let Some(sc) = snapshot.shared_clean {
            md.push_str(&format!("| Shared clean | {} |\n", fmt_bytes(sc as f64)));
        }
        if let Some(sd) = snapshot.shared_dirty {
            md.push_str(&format!("| Shared dirty | {} |\n", fmt_bytes(sd as f64)));
        }
        if let Some(pc) = snapshot.private_clean {
            md.push_str(&format!("| Private clean | {} |\n", fmt_bytes(pc as f64)));
        }
        if let Some(pd) = snapshot.private_dirty {
            md.push_str(&format!("| Private dirty | {} |\n", fmt_bytes(pd as f64)));
        }
        if let Some(r) = snapshot.referenced {
            md.push_str(&format!(
                "| Referenced (recent) | {} |\n",
                fmt_bytes(r as f64)
            ));
        }
        if let Some(sp) = snapshot.swap_pss {
            md.push_str(&format!(
                "| Swap proportional | {} |\n",
                fmt_bytes(sp as f64)
            ));
        }
        if snapshot.vm_swap > 0 {
            md.push_str(&format!(
                "| Swap (VmSwap) | {} |\n",
                fmt_bytes(snapshot.vm_swap as f64)
            ));
        }
        md.push_str(&format!(
            "| % of total RAM | {:.2}% |\n",
            snapshot.mem_percent
        ));
    }
    if snapshot.vm_hwm > 0 {
        md.push_str(&format!(
            "| Peak resident (VmHWM) | {} |\n",
            fmt_bytes(snapshot.vm_hwm as f64)
        ));
    }
    if verbose {
        md.push_str(&format!(
            "| Virtual (VmSize) | {} |\n",
            fmt_bytes(snapshot.vms as f64)
        ));
        md.push_str(&format!(
            "| Peak virtual (VmPeak) | {} |\n",
            fmt_bytes(snapshot.vm_peak as f64)
        ));
        md.push_str(&format!(
            "| CPU (user) | {} |\n",
            fmt_ms(snapshot.cpu_user_ms)
        ));
        md.push_str(&format!(
            "| CPU (system) | {} |\n",
            fmt_ms(snapshot.cpu_system_ms)
        ));
        if let Some(pct) = snapshot.cpu_percent {
            md.push_str(&format!("| CPU % | {:.1}% |\n", pct));
        }
    }
    if let Some(rb) = snapshot.io_read_bytes {
        md.push_str(&format!("| IO Read | {} |\n", fmt_bytes(rb as f64)));
    }
    if let Some(wb) = snapshot.io_write_bytes {
        md.push_str(&format!("| IO Write | {} |\n", fmt_bytes(wb as f64)));
    }
    if verbose {
        if let Some(sr) = snapshot.io_syscr {
            md.push_str(&format!("| IO Syscalls (r) | {} |\n", sr));
        }
        if let Some(sw) = snapshot.io_syscw {
            md.push_str(&format!("| IO Syscalls (w) | {} |\n", sw));
        }
    }
    md.push_str(&format!("| Threads | {} |\n", snapshot.num_threads));
    if let Some(fds) = snapshot.num_fds {
        md.push_str(&format!("| FDs | {} |\n", fds));
    }
    if verbose {
        md.push_str(&format!(
            "| CtxSw (vol) | {} |\n",
            snapshot.ctx_switches_voluntary
        ));
        md.push_str(&format!(
            "| CtxSw (invol) | {} |\n",
            snapshot.ctx_switches_involuntary
        ));
        if let Some(score) = snapshot.oom_score {
            md.push_str(&format!("| OOM Score | {} |\n", score));
        }
        if let Some(adj) = snapshot.oom_score_adj {
            let label = if adj < 0 {
                format!("{adj} (protected)")
            } else {
                format!("{adj}")
            };
            md.push_str(&format!("| OOM Adj | {} |\n", label));
        }
        if let Some(ref cg) = snapshot.cgroup {
            md.push_str(&format!("| Cgroup | `{}` |\n", cg));
        }
    }
    md
}

/// Clean snapshot markdown.
pub fn format_snapshot_md(snapshot: &ProcessSnapshot) -> String {
    format_snapshot_markdown(snapshot, false)
}

/// Verbose snapshot markdown.
pub fn format_snapshot_md_verbose(snapshot: &ProcessSnapshot) -> String {
    format_snapshot_markdown(snapshot, true)
}

/// Format a snapshot as single-line JSON (for NDJSON streaming).
pub fn format_ndjson_line(snapshot: &ProcessSnapshot) -> String {
    serde_json::to_string(snapshot).unwrap_or_else(|e| format!("{{\"error\": \"{e}\"}}"))
}

/// Format the sample summary as a tagged NDJSON line.
pub fn format_summary_ndjson(summary: &SampleSummary) -> String {
    // Wrap with type tag for agents to identify
    let mut val = serde_json::to_value(summary).unwrap_or_default();
    if let Some(obj) = val.as_object_mut() {
        obj.insert("type".into(), serde_json::Value::String("summary".into()));
    }
    serde_json::to_string(&val).unwrap_or_default()
}

/// Human-readable byte formatting.
fn fmt_bytes(bytes: f64) -> String {
    if bytes >= 1_073_741_824.0 {
        format!("{:.1} GB", bytes / 1_073_741_824.0)
    } else if bytes >= 1_048_576.0 {
        format!("{:.1} MB", bytes / 1_048_576.0)
    } else if bytes >= 1024.0 {
        format!("{:.1} KB", bytes / 1024.0)
    } else {
        format!("{:.0} B", bytes)
    }
}

fn fmt_ms(ms: u64) -> String {
    if ms >= 60_000 {
        format!("{:.1}m", ms as f64 / 60_000.0)
    } else if ms >= 1_000 {
        format!("{:.1}s", ms as f64 / 1_000.0)
    } else {
        format!("{ms}ms")
    }
}

fn fmt_bucket_or_na(
    bucket: Option<&StatBucket>,
    formatter: impl FnOnce(&StatBucket) -> String,
) -> String {
    bucket.map(formatter).unwrap_or_else(|| "n/a".to_string())
}

/// Format a snapshot as a table. `verbose` controls which rows are shown.
/// Same layout for both modes, just filtered data.
fn format_snapshot_table(snapshot: &ProcessSnapshot, verbose: bool) -> String {
    let source = match &snapshot.source {
        CollectionSource::Local => "local".to_string(),
        CollectionSource::Remote { target } => format!("remote ({target})"),
    };
    let state = format!("{:?}", snapshot.state);
    let time = snapshot
        .timestamp
        .format("%Y-%m-%d %H:%M:%S UTC")
        .to_string();

    let mut table = Table::new();
    table
        .load_preset(presets::UTF8_FULL_CONDENSED)
        .set_content_arrangement(ContentArrangement::Dynamic);

    let title = if let Some(sz) = snapshot.exe_size {
        format!(
            "{} (PID {}) \u{00b7} size: {}",
            snapshot.name,
            snapshot.pid,
            fmt_bytes(sz as f64)
        )
    } else {
        format!("{} (PID {})", snapshot.name, snapshot.pid)
    };
    table.set_header(vec![
        Cell::new(title).add_attribute(Attribute::Bold),
        Cell::new(format!("{state} \u{00b7} {time}")),
    ]);

    table.add_row(vec![Cell::new("Source"), Cell::new(&source)]);
    if verbose {
        table.add_row(vec![
            Cell::new("Cmdline"),
            Cell::new(snapshot.cmdline.join(" ")),
        ]);
    }

    table.add_row(vec![
        Cell::new("Resident (VmRSS)"),
        Cell::new(fmt_bytes(snapshot.rss as f64)),
    ]);
    if let Some(a) = snapshot.anonymous {
        table.add_row(vec![
            Cell::new("Anon (heap+stack)"),
            Cell::new(fmt_bytes(a as f64)),
        ]);
    }
    table.add_row(vec![
        Cell::new("File-backed (RssFile)"),
        Cell::new(fmt_bytes(snapshot.rss_file as f64)),
    ]);
    if verbose {
        table.add_row(vec![
            Cell::new("Shmem (RssShmem)"),
            Cell::new(fmt_bytes(snapshot.shared as f64)),
        ]);
    }
    if let Some(uss) = snapshot.uss {
        table.add_row(vec![
            Cell::new("Unique (USS)"),
            Cell::new(fmt_bytes(uss as f64)),
        ]);
    }
    if let Some(pss) = snapshot.pss {
        table.add_row(vec![
            Cell::new("Proportional (Pss)"),
            Cell::new(fmt_bytes(pss as f64)),
        ]);
    }
    if verbose {
        if let Some(sc) = snapshot.shared_clean {
            table.add_row(vec![
                Cell::new("Shared clean"),
                Cell::new(fmt_bytes(sc as f64)),
            ]);
        }
        if let Some(sd) = snapshot.shared_dirty {
            table.add_row(vec![
                Cell::new("Shared dirty"),
                Cell::new(fmt_bytes(sd as f64)),
            ]);
        }
        if let Some(pc) = snapshot.private_clean {
            table.add_row(vec![
                Cell::new("Private clean"),
                Cell::new(fmt_bytes(pc as f64)),
            ]);
        }
        if let Some(pd) = snapshot.private_dirty {
            table.add_row(vec![
                Cell::new("Private dirty"),
                Cell::new(fmt_bytes(pd as f64)),
            ]);
        }
        if let Some(r) = snapshot.referenced {
            table.add_row(vec![
                Cell::new("Referenced (recent)"),
                Cell::new(fmt_bytes(r as f64)),
            ]);
        }
        if let Some(sp) = snapshot.swap_pss {
            table.add_row(vec![
                Cell::new("Swap proportional"),
                Cell::new(fmt_bytes(sp as f64)),
            ]);
        }
        if snapshot.vm_swap > 0 {
            table.add_row(vec![
                Cell::new("Swap (VmSwap)"),
                Cell::new(fmt_bytes(snapshot.vm_swap as f64)),
            ]);
        }
        table.add_row(vec![
            Cell::new("% of total RAM"),
            Cell::new(format!("{:.2}%", snapshot.mem_percent)),
        ]);
    }

    if snapshot.vm_hwm > 0 {
        table.add_row(vec![
            Cell::new("Peak resident (VmHWM)"),
            Cell::new(fmt_bytes(snapshot.vm_hwm as f64)),
        ]);
    }

    if verbose {
        table.add_row(vec![
            Cell::new("Virtual (VmSize)"),
            Cell::new(fmt_bytes(snapshot.vms as f64)),
        ]);
        table.add_row(vec![
            Cell::new("Peak virtual (VmPeak)"),
            Cell::new(fmt_bytes(snapshot.vm_peak as f64)),
        ]);
        table.add_row(vec![
            Cell::new("CPU (user)"),
            Cell::new(fmt_ms(snapshot.cpu_user_ms)),
        ]);
        table.add_row(vec![
            Cell::new("CPU (system)"),
            Cell::new(fmt_ms(snapshot.cpu_system_ms)),
        ]);
        if let Some(pct) = snapshot.cpu_percent {
            table.add_row(vec![Cell::new("CPU %"), Cell::new(format!("{:.1}%", pct))]);
        }
    }

    if let Some(rb) = snapshot.io_read_bytes {
        table.add_row(vec![Cell::new("IO Read"), Cell::new(fmt_bytes(rb as f64))]);
    }
    if let Some(wb) = snapshot.io_write_bytes {
        table.add_row(vec![Cell::new("IO Write"), Cell::new(fmt_bytes(wb as f64))]);
    }
    if verbose {
        if let Some(sr) = snapshot.io_syscr {
            table.add_row(vec![
                Cell::new("IO Syscalls (r)"),
                Cell::new(format!("{sr}")),
            ]);
        }
        if let Some(sw) = snapshot.io_syscw {
            table.add_row(vec![
                Cell::new("IO Syscalls (w)"),
                Cell::new(format!("{sw}")),
            ]);
        }
    }

    table.add_row(vec![
        Cell::new("Threads"),
        Cell::new(format!("{}", snapshot.num_threads)),
    ]);
    if let Some(fds) = snapshot.num_fds {
        table.add_row(vec![Cell::new("FDs"), Cell::new(format!("{fds}"))]);
    }

    if verbose {
        table.add_row(vec![
            Cell::new("CtxSw (vol)"),
            Cell::new(format!("{}", snapshot.ctx_switches_voluntary)),
        ]);
        table.add_row(vec![
            Cell::new("CtxSw (invol)"),
            Cell::new(format!("{}", snapshot.ctx_switches_involuntary)),
        ]);
        if let Some(score) = snapshot.oom_score {
            table.add_row(vec![Cell::new("OOM Score"), Cell::new(format!("{score}"))]);
        }
        if let Some(adj) = snapshot.oom_score_adj {
            let label = if adj < 0 {
                format!("{adj} (protected)")
            } else {
                format!("{adj}")
            };
            table.add_row(vec![Cell::new("OOM Adj"), Cell::new(label)]);
        }
        if let Some(ref cg) = snapshot.cgroup {
            table.add_row(vec![Cell::new("Cgroup"), Cell::new(cg)]);
        }
    }

    table.to_string()
}

/// Clean snapshot table (important metrics only).
pub fn format_table(snapshot: &ProcessSnapshot) -> String {
    format_snapshot_table(snapshot, false)
}

/// Verbose snapshot table (all metrics).
pub fn format_table_verbose(snapshot: &ProcessSnapshot) -> String {
    format_snapshot_table(snapshot, true)
}

// ============================================================================
// Memory map rendering
// ============================================================================

fn vma_kind_label(k: VmaKind) -> &'static str {
    match k {
        VmaKind::Binary => "Binary",
        VmaKind::SharedLibrary => "Shared libraries",
        VmaKind::Heap => "Heap",
        VmaKind::Stack => "Stacks",
        VmaKind::AnonOther => "Other anon",
        VmaKind::Shmem => "Shared memory",
    }
}

/// Sum RSS and Size per kind, returning a fixed-order vec of
/// (kind, rss, size) — ordered for display.
fn bucket_summary(report: &MemoryMapReport) -> Vec<(VmaKind, u64, u64)> {
    let order = [
        VmaKind::Binary,
        VmaKind::SharedLibrary,
        VmaKind::Heap,
        VmaKind::Stack,
        VmaKind::AnonOther,
        VmaKind::Shmem,
    ];
    order
        .iter()
        .map(|&k| {
            let (rss, size) = report
                .entries
                .iter()
                .filter(|e| e.classify(report.exe_path.as_deref()) == k)
                .fold((0u64, 0u64), |(r, s), e| (r + e.rss, s + e.size));
            (k, rss, size)
        })
        .collect()
}

/// Group VMAs by (display label, perm) and sum size / rss / anon across duplicates.
/// Returns rows sorted by RSS descending. Anonymous entries are collapsed under their label.
fn group_vmas(entries: &[VmaEntry]) -> Vec<(String, String, u64, u64, u64)> {
    use std::collections::BTreeMap;
    let mut map: BTreeMap<(String, String), (u64, u64, u64)> = BTreeMap::new();
    for e in entries {
        let key = (e.label.clone(), e.perm.clone());
        let slot = map.entry(key).or_default();
        slot.0 += e.size;
        slot.1 += e.rss;
        slot.2 += e.anonymous;
    }
    let mut rows: Vec<(String, String, u64, u64, u64)> = map
        .into_iter()
        .map(|((label, perm), (size, rss, anon))| (label, perm, size, rss, anon))
        .collect();
    rows.sort_by(|a, b| b.3.cmp(&a.3));
    rows
}

/// Format a memory-map report as a terminal table (or two tables in verbose mode).
pub fn format_map_table(report: &MemoryMapReport, verbose: bool) -> String {
    let source = match &report.source {
        CollectionSource::Local => "local".to_string(),
        CollectionSource::Remote { target } => format!("remote ({target})"),
    };
    let time = report
        .timestamp
        .format("%Y-%m-%d %H:%M:%S UTC")
        .to_string();

    let mut out = String::new();

    // Summary table: bucketed RSS breakdown.
    let mut summary = Table::new();
    summary
        .load_preset(presets::UTF8_FULL_CONDENSED)
        .set_content_arrangement(ContentArrangement::Dynamic);

    let title = if let Some(sz) = report.exe_size {
        format!(
            "{} (PID {}) \u{00b7} size: {}",
            report.name,
            report.pid,
            fmt_bytes(sz as f64)
        )
    } else {
        format!("{} (PID {})", report.name, report.pid)
    };
    summary.set_header(vec![
        Cell::new(title).add_attribute(Attribute::Bold),
        Cell::new(format!("{source} \u{00b7} {time}")),
    ]);

    summary.add_row(vec![
        Cell::new("Total RSS").add_attribute(Attribute::Bold),
        Cell::new(format!("{:>9}  100.0%", fmt_bytes(report.total_rss as f64)))
            .add_attribute(Attribute::Bold)
            .set_alignment(CellAlignment::Right),
    ]);

    let buckets = bucket_summary(report);
    let total = report.total_rss.max(1);
    for (kind, rss, _size) in buckets {
        let pct = (rss as f64 / total as f64) * 100.0;
        summary.add_row(vec![
            Cell::new(vma_kind_label(kind)),
            Cell::new(format!("{:>9}  {:>5.1}%", fmt_bytes(rss as f64), pct))
                .set_alignment(CellAlignment::Right),
        ]);
    }
    out.push_str(&summary.to_string());
    out.push('\n');

    if !verbose {
        return out;
    }

    // Per-mapping detail table (verbose).
    let mut detail = Table::new();
    detail
        .load_preset(presets::UTF8_FULL_CONDENSED)
        .set_content_arrangement(ContentArrangement::Dynamic);
    detail.set_header(vec![
        Cell::new("Mapping").add_attribute(Attribute::Bold),
        Cell::new("Perm").add_attribute(Attribute::Bold),
        Cell::new("Size").add_attribute(Attribute::Bold),
        Cell::new("RSS").add_attribute(Attribute::Bold),
        Cell::new("Anon").add_attribute(Attribute::Bold),
    ]);

    for (label, perm, size, rss, anon) in group_vmas(&report.entries) {
        if rss < 1024 {
            continue;
        }
        detail.add_row(vec![
            Cell::new(label),
            Cell::new(perm),
            Cell::new(fmt_bytes(size as f64)).set_alignment(CellAlignment::Right),
            Cell::new(fmt_bytes(rss as f64)).set_alignment(CellAlignment::Right),
            Cell::new(fmt_bytes(anon as f64)).set_alignment(CellAlignment::Right),
        ]);
    }
    out.push_str(&detail.to_string());
    out.push('\n');

    out
}

/// Format the memory-map report as pretty JSON.
pub fn format_map_json(report: &MemoryMapReport) -> String {
    serde_json::to_string_pretty(report).unwrap_or_else(|e| format!("{{\"error\": \"{e}\"}}"))
}

/// Format the memory-map report as markdown.
pub fn format_map_md(report: &MemoryMapReport, verbose: bool) -> String {
    let source = match &report.source {
        CollectionSource::Local => "local".to_string(),
        CollectionSource::Remote { target } => format!("remote ({target})"),
    };
    let time = report
        .timestamp
        .format("%Y-%m-%d %H:%M:%S UTC")
        .to_string();

    let mut md = String::new();
    if let Some(sz) = report.exe_size {
        md.push_str(&format!(
            "# {} (PID {}) \u{00b7} size: {}\n\n",
            report.name,
            report.pid,
            fmt_bytes(sz as f64)
        ));
    } else {
        md.push_str(&format!("# {} (PID {})\n\n", report.name, report.pid));
    }
    md.push_str(&format!("{source} \u{00b7} {time}\n\n"));

    md.push_str("## RSS breakdown\n\n");
    md.push_str("| Source | RSS | % |\n|--------|-----|---|\n");
    md.push_str(&format!(
        "| **Total** | **{}** | 100% |\n",
        fmt_bytes(report.total_rss as f64)
    ));
    let total = report.total_rss.max(1);
    for (kind, rss, _) in bucket_summary(report) {
        let pct = (rss as f64 / total as f64) * 100.0;
        md.push_str(&format!(
            "| {} | {} | {:.1}% |\n",
            vma_kind_label(kind),
            fmt_bytes(rss as f64),
            pct
        ));
    }

    if verbose {
        md.push_str("\n## Per-mapping detail\n\n");
        md.push_str("| Mapping | Perm | Size | RSS | Anon |\n|---------|------|------|-----|------|\n");
        for (label, perm, size, rss, anon) in group_vmas(&report.entries) {
            if rss < 1024 {
                continue;
            }
            md.push_str(&format!(
                "| {} | {} | {} | {} | {} |\n",
                label,
                perm,
                fmt_bytes(size as f64),
                fmt_bytes(rss as f64),
                fmt_bytes(anon as f64)
            ));
        }
    }

    md
}

/// Format a diff report as a professional terminal table using comfy-table.
pub fn format_diff_table(report: &DiffReport) -> String {
    let mut out = String::new();
    out.push_str(&format!(
        "┌─ {} (PID {}) ── diff ── {:.1}s elapsed\n",
        report.after.name, report.after.pid, report.elapsed_s
    ));

    let mut table = Table::new();
    table
        .load_preset(presets::UTF8_FULL_CONDENSED)
        .set_content_arrangement(ContentArrangement::Dynamic)
        .set_header(vec![
            Cell::new("Metric"),
            Cell::new("Before").set_alignment(CellAlignment::Right),
            Cell::new("After").set_alignment(CellAlignment::Right),
            Cell::new("Delta").set_alignment(CellAlignment::Right),
            Cell::new(""),
        ]);

    for d in &report.deltas {
        let is_mem = matches!(
            d.name.as_str(),
            "RSS" | "VMS" | "VM Peak" | "VM Swap" | "Shared" | "IO Read" | "IO Write"
        );
        let is_cpu_time = matches!(d.name.as_str(), "CPU (user)" | "CPU (system)");

        let display_name = match d.name.as_str() {
            "RSS" => "Resident (VmRSS)",
            "VMS" => "Virtual (VmSize)",
            "VM Peak" => "Peak virtual (VmPeak)",
            "VM Swap" => "Swap (VmSwap)",
            "Shared" => "Shmem (RssShmem)",
            other => other,
        };

        let severity_marker = match d.severity {
            DiffSeverity::Significant => "\u{25b2}\u{25b2}\u{25b2}",
            DiffSeverity::Moderate => "\u{25b2}\u{25b2}",
            DiffSeverity::Minor => {
                if d.delta.abs() < f64::EPSILON {
                    ""
                } else if d.delta > 0.0 {
                    "\u{25b2}"
                } else {
                    "\u{25bc}"
                }
            }
        };

        let fmt_delta_val = |val: f64, positive: bool| -> String {
            let prefix = if positive { "+" } else { "-" };
            let abs = val.abs();
            if is_mem {
                format!("{prefix}{}", fmt_bytes(abs))
            } else if is_cpu_time {
                format!("{prefix}{}", fmt_ms(abs as u64))
            } else if positive {
                format!("+{:.0}", val)
            } else {
                format!("{:.0}", val)
            }
        };

        let (b, a, delta) = if is_mem {
            (
                fmt_bytes(d.before),
                fmt_bytes(d.after),
                fmt_delta_val(d.delta, d.delta >= 0.0),
            )
        } else if is_cpu_time {
            (
                fmt_ms(d.before as u64),
                fmt_ms(d.after as u64),
                fmt_delta_val(d.delta, d.delta >= 0.0),
            )
        } else {
            (
                format!("{:.0}", d.before),
                format!("{:.0}", d.after),
                fmt_delta_val(d.delta, d.delta >= 0.0),
            )
        };

        table.add_row(vec![
            Cell::new(display_name),
            Cell::new(&b).set_alignment(CellAlignment::Right),
            Cell::new(&a).set_alignment(CellAlignment::Right),
            Cell::new(&delta).set_alignment(CellAlignment::Right),
            Cell::new(severity_marker),
        ]);
    }

    out.push_str(&table.to_string());
    out
}

/// Compute statistical summary from a sample series.
pub fn compute_summary(series: &SampleSeries) -> SampleSummary {
    let samples = &series.samples;
    let n = samples.len();
    if n == 0 {
        return SampleSummary {
            duration_s: 0.0,
            sample_count: 0,
            rss: StatBucket::from_values(&[]),
            vms: StatBucket::from_values(&[]),
            vm_hwm_max: 0.0,
            vm_swap_max: 0.0,
            cpu_percent: None,
            io_read_rate: None,
            io_write_rate: None,
            num_threads: StatBucket::from_values(&[]),
            num_fds: None,
            rss_trend: Trend::Stable,
        };
    }

    let duration_s = if n >= 2 {
        (samples[n - 1].timestamp - samples[0].timestamp).num_milliseconds() as f64 / 1000.0
    } else {
        0.0
    };

    let rss_vals: Vec<f64> = samples.iter().map(|s| s.rss as f64).collect();
    let vms_vals: Vec<f64> = samples.iter().map(|s| s.vms as f64).collect();
    let cpu_vals: Vec<f64> = samples.iter().filter_map(|s| s.cpu_percent).collect();
    let thread_vals: Vec<f64> = samples.iter().map(|s| s.num_threads as f64).collect();
    let fd_vals: Vec<f64> = samples
        .iter()
        .filter_map(|s| s.num_fds.map(|f| f as f64))
        .collect();

    // Compute IO rates between consecutive samples.
    let mut io_read_rates = Vec::new();
    let mut io_write_rates = Vec::new();
    for i in 1..n {
        let dt =
            (samples[i].timestamp - samples[i - 1].timestamp).num_milliseconds() as f64 / 1000.0;
        if dt > 0.0 {
            if let (Some(rb1), Some(rb2)) = (samples[i - 1].io_read_bytes, samples[i].io_read_bytes)
            {
                io_read_rates.push((rb2 as f64 - rb1 as f64) / dt);
            }
            if let (Some(wb1), Some(wb2)) =
                (samples[i - 1].io_write_bytes, samples[i].io_write_bytes)
            {
                io_write_rates.push((wb2 as f64 - wb1 as f64) / dt);
            }
        }
    }

    let vm_hwm_max = samples
        .iter()
        .map(|s| s.vm_hwm as f64)
        .fold(0.0f64, f64::max);
    let vm_swap_max = samples
        .iter()
        .map(|s| s.vm_swap as f64)
        .fold(0.0f64, f64::max);

    SampleSummary {
        duration_s,
        sample_count: n,
        rss: StatBucket::from_values(&rss_vals),
        vms: StatBucket::from_values(&vms_vals),
        vm_hwm_max,
        vm_swap_max,
        cpu_percent: StatBucket::from_nonempty(&cpu_vals),
        io_read_rate: StatBucket::from_nonempty(&io_read_rates),
        io_write_rate: StatBucket::from_nonempty(&io_write_rates),
        num_threads: StatBucket::from_values(&thread_vals),
        num_fds: StatBucket::from_nonempty(&fd_vals),
        rss_trend: Trend::from_values(&rss_vals),
    }
}

/// Format a sample series as a markdown report.
pub fn format_markdown(series: &SampleSeries) -> String {
    let summary = series
        .summary
        .as_ref()
        .map_or_else(|| compute_summary(series), |s| s.clone());

    let source = match &series.source {
        CollectionSource::Local => "Local".to_string(),
        CollectionSource::Remote { target } => format!("Remote ({target} via rsdb)"),
    };

    let mut md = String::new();
    md.push_str(&format!("# Process Report: {}\n\n", series.process_name));

    if let (Some(first), Some(last)) = (series.samples.first(), series.samples.last()) {
        md.push_str(&format!(
            "Collected: {} to {}\n",
            first.timestamp.format("%Y-%m-%d %H:%M:%S"),
            last.timestamp.format("%H:%M:%S")
        ));
    }
    md.push_str(&format!("Source: {source}\n"));
    md.push_str(&format!(
        "Samples: {} at {}ms interval\n\n",
        summary.sample_count, series.interval_ms
    ));

    md.push_str("## Memory\n\n");
    md.push_str("| Metric | Min | Max | Avg | P95 | Trend |\n");
    md.push_str("|--------|-----|-----|-----|-----|-------|\n");
    md.push_str(&format!(
        "| Resident (VmRSS) | {} | {} | {} | {} | {:?} |\n",
        fmt_bytes(summary.rss.min),
        fmt_bytes(summary.rss.max),
        fmt_bytes(summary.rss.avg),
        fmt_bytes(summary.rss.p95),
        summary.rss_trend
    ));
    md.push_str(&format!(
        "| Virtual (VmSize) | {} | {} | {} | {} | - |\n",
        fmt_bytes(summary.vms.min),
        fmt_bytes(summary.vms.max),
        fmt_bytes(summary.vms.avg),
        fmt_bytes(summary.vms.p95),
    ));
    md.push_str(&format!(
        "| Peak resident (VmHWM) | - | {} | - | - | - |\n",
        fmt_bytes(summary.vm_hwm_max)
    ));
    if summary.vm_swap_max > 0.0 {
        md.push_str(&format!(
            "| Swap (VmSwap) | - | {} | - | - | - |\n",
            fmt_bytes(summary.vm_swap_max)
        ));
    }

    md.push_str("\n## CPU\n\n");
    md.push_str("| Metric | Min | Max | Avg | P95 |\n");
    md.push_str("|--------|-----|-----|-----|-----|\n");
    md.push_str(&format!(
        "| CPU % | {} | {} | {} | {} |\n",
        fmt_bucket_or_na(summary.cpu_percent.as_ref(), |b| format!("{:.1}%", b.min)),
        fmt_bucket_or_na(summary.cpu_percent.as_ref(), |b| format!("{:.1}%", b.max)),
        fmt_bucket_or_na(summary.cpu_percent.as_ref(), |b| format!("{:.1}%", b.avg)),
        fmt_bucket_or_na(summary.cpu_percent.as_ref(), |b| format!("{:.1}%", b.p95)),
    ));

    md.push_str("\n## IO\n\n");
    md.push_str("| Metric | Avg Rate |\n");
    md.push_str("|--------|----------|\n");
    md.push_str(&format!(
        "| Read | {} |\n",
        fmt_bucket_or_na(summary.io_read_rate.as_ref(), |b| format!(
            "{}/s",
            fmt_bytes(b.avg)
        ))
    ));
    md.push_str(&format!(
        "| Write | {} |\n",
        fmt_bucket_or_na(summary.io_write_rate.as_ref(), |b| format!(
            "{}/s",
            fmt_bytes(b.avg)
        ))
    ));

    md.push_str("\n## Summary\n\n");
    md.push_str(&format!("- Memory trend: {:?}", summary.rss_trend));
    let rss_delta = summary.rss.max - summary.rss.min;
    match summary.rss_trend {
        Trend::Rising => {
            md.push_str(&format!(
                " (+{} over {:.0}s) ... potential leak",
                fmt_bytes(rss_delta),
                summary.duration_s
            ));
        }
        Trend::Falling => {
            md.push_str(&format!(
                " (-{} over {:.0}s)",
                fmt_bytes(rss_delta),
                summary.duration_s
            ));
        }
        Trend::Stable => {}
    }
    md.push('\n');

    if let Some(cpu_percent) = summary.cpu_percent.as_ref().filter(|cpu| cpu.max > 0.0) {
        let burst_ratio = if cpu_percent.avg > 0.0 {
            cpu_percent.p95 / cpu_percent.avg
        } else {
            0.0
        };
        if burst_ratio > 2.0 {
            md.push_str(&format!(
                "- CPU: bursty (P95 is {:.1}x average)\n",
                burst_ratio
            ));
        } else {
            md.push_str(&format!(
                "- CPU: avg {:.1}%, peak {:.1}%\n",
                cpu_percent.avg, cpu_percent.max
            ));
        }
    }

    if let (Some(io_read_rate), Some(io_write_rate)) = (
        summary.io_read_rate.as_ref(),
        summary.io_write_rate.as_ref(),
    ) {
        if io_write_rate.avg <= 0.0 && io_read_rate.avg <= 0.0 {
            return md;
        }

        let read_write = if io_write_rate.avg > io_read_rate.avg * 2.0 {
            "write-heavy"
        } else if io_read_rate.avg > io_write_rate.avg * 2.0 {
            "read-heavy"
        } else {
            "balanced"
        };
        md.push_str(&format!("- IO: {read_write} workload\n"));
    }

    md
}

/// Format a sample series as a professional terminal report using comfy-table.
pub fn format_report_table(series: &SampleSeries) -> String {
    let summary = series
        .summary
        .as_ref()
        .map_or_else(|| compute_summary(series), |s| s.clone());

    let source = match &series.source {
        CollectionSource::Local => "local".to_string(),
        CollectionSource::Remote { target } => format!("remote ({target})"),
    };

    let mut out = String::new();
    out.push_str(&format!(
        "┌─ {} (PID {}) ── report\n",
        series.process_name, series.pid
    ));
    out.push_str(&format!("│  {source}"));
    if let (Some(first), Some(last)) = (series.samples.first(), series.samples.last()) {
        out.push_str(&format!(
            " \u{00b7} {} to {}",
            first.timestamp.format("%Y-%m-%d %H:%M:%S"),
            last.timestamp.format("%H:%M:%S")
        ));
    }
    out.push_str(&format!(
        " \u{00b7} {} samples at {}ms ({:.0}s)\n",
        summary.sample_count, series.interval_ms, summary.duration_s
    ));

    // Memory table
    let mut mem_table = Table::new();
    mem_table
        .load_preset(presets::UTF8_FULL_CONDENSED)
        .set_content_arrangement(ContentArrangement::Dynamic)
        .set_header(vec![
            Cell::new("Memory").add_attribute(Attribute::Bold),
            Cell::new("Min").set_alignment(CellAlignment::Right),
            Cell::new("Max").set_alignment(CellAlignment::Right),
            Cell::new("Avg").set_alignment(CellAlignment::Right),
            Cell::new("P95").set_alignment(CellAlignment::Right),
            Cell::new("Trend"),
        ]);
    mem_table.add_row(vec![
        Cell::new("Resident (VmRSS)"),
        Cell::new(fmt_bytes(summary.rss.min)).set_alignment(CellAlignment::Right),
        Cell::new(fmt_bytes(summary.rss.max)).set_alignment(CellAlignment::Right),
        Cell::new(fmt_bytes(summary.rss.avg)).set_alignment(CellAlignment::Right),
        Cell::new(fmt_bytes(summary.rss.p95)).set_alignment(CellAlignment::Right),
        Cell::new(format!("{:?}", summary.rss_trend)),
    ]);
    mem_table.add_row(vec![
        Cell::new("Peak resident (VmHWM)"),
        Cell::new(""),
        Cell::new(fmt_bytes(summary.vm_hwm_max)).set_alignment(CellAlignment::Right),
        Cell::new(""),
        Cell::new(""),
        Cell::new(""),
    ]);
    if summary.vm_swap_max > 0.0 {
        mem_table.add_row(vec![
            Cell::new("Swap (VmSwap)"),
            Cell::new(""),
            Cell::new(fmt_bytes(summary.vm_swap_max)).set_alignment(CellAlignment::Right),
            Cell::new(""),
            Cell::new(""),
            Cell::new(""),
        ]);
    }
    out.push_str(&format!("\n{mem_table}\n"));

    // CPU + IO + Resources in one compact table
    let mut stats_table = Table::new();
    stats_table
        .load_preset(presets::UTF8_FULL_CONDENSED)
        .set_content_arrangement(ContentArrangement::Dynamic)
        .set_header(vec![
            Cell::new("Metric").add_attribute(Attribute::Bold),
            Cell::new("Min").set_alignment(CellAlignment::Right),
            Cell::new("Max").set_alignment(CellAlignment::Right),
            Cell::new("Avg").set_alignment(CellAlignment::Right),
            Cell::new("P95").set_alignment(CellAlignment::Right),
        ]);
    stats_table.add_row(vec![
        Cell::new("CPU %"),
        Cell::new(fmt_bucket_or_na(summary.cpu_percent.as_ref(), |b| {
            format!("{:.1}%", b.min)
        }))
        .set_alignment(CellAlignment::Right),
        Cell::new(fmt_bucket_or_na(summary.cpu_percent.as_ref(), |b| {
            format!("{:.1}%", b.max)
        }))
        .set_alignment(CellAlignment::Right),
        Cell::new(fmt_bucket_or_na(summary.cpu_percent.as_ref(), |b| {
            format!("{:.1}%", b.avg)
        }))
        .set_alignment(CellAlignment::Right),
        Cell::new(fmt_bucket_or_na(summary.cpu_percent.as_ref(), |b| {
            format!("{:.1}%", b.p95)
        }))
        .set_alignment(CellAlignment::Right),
    ]);
    stats_table.add_row(vec![
        Cell::new("IO Read"),
        Cell::new(""),
        Cell::new(""),
        Cell::new(fmt_bucket_or_na(summary.io_read_rate.as_ref(), |b| {
            format!("{}/s", fmt_bytes(b.avg))
        }))
        .set_alignment(CellAlignment::Right),
        Cell::new(""),
    ]);
    stats_table.add_row(vec![
        Cell::new("IO Write"),
        Cell::new(""),
        Cell::new(""),
        Cell::new(fmt_bucket_or_na(summary.io_write_rate.as_ref(), |b| {
            format!("{}/s", fmt_bytes(b.avg))
        }))
        .set_alignment(CellAlignment::Right),
        Cell::new(""),
    ]);
    stats_table.add_row(vec![
        Cell::new("Threads"),
        Cell::new(format!("{:.0}", summary.num_threads.min)).set_alignment(CellAlignment::Right),
        Cell::new(format!("{:.0}", summary.num_threads.max)).set_alignment(CellAlignment::Right),
        Cell::new(format!("{:.1}", summary.num_threads.avg)).set_alignment(CellAlignment::Right),
        Cell::new(format!("{:.0}", summary.num_threads.p95)).set_alignment(CellAlignment::Right),
    ]);
    stats_table.add_row(vec![
        Cell::new("FDs"),
        Cell::new(fmt_bucket_or_na(summary.num_fds.as_ref(), |b| {
            format!("{:.0}", b.min)
        }))
        .set_alignment(CellAlignment::Right),
        Cell::new(fmt_bucket_or_na(summary.num_fds.as_ref(), |b| {
            format!("{:.0}", b.max)
        }))
        .set_alignment(CellAlignment::Right),
        Cell::new(fmt_bucket_or_na(summary.num_fds.as_ref(), |b| {
            format!("{:.1}", b.avg)
        }))
        .set_alignment(CellAlignment::Right),
        Cell::new(fmt_bucket_or_na(summary.num_fds.as_ref(), |b| {
            format!("{:.0}", b.p95)
        }))
        .set_alignment(CellAlignment::Right),
    ]);
    out.push_str(&format!("\n{stats_table}\n"));

    out
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::schema::{CollectionSource, ProcessState};
    use chrono::Utc;

    fn make_snap(rss: u64, cpu_pct: Option<f64>) -> ProcessSnapshot {
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
            cpu_percent: cpu_pct,
            io_read_bytes: Some(4096),
            io_write_bytes: Some(2048),
            io_syscr: Some(10),
            io_syscw: Some(5),
            num_threads: 4,
            num_fds: Some(20),
            ctx_switches_voluntary: 100,
            ctx_switches_involuntary: 10,
            pss: None,
            uss: None,
            shared_clean: None,
            shared_dirty: None,
            private_clean: None,
            private_dirty: None,
            referenced: None,
            anonymous: None,
            swap_pss: None,
            oom_score: None,
            oom_score_adj: None,
            cgroup: None,
            timestamp: Utc::now(),
            source: CollectionSource::Local,
        }
    }

    #[test]
    fn format_json_roundtrip() {
        let snap = make_snap(1024 * 1024, None);
        let json = format_json(&snap);
        let back: ProcessSnapshot = serde_json::from_str(&json).unwrap();
        assert_eq!(back.pid, 1);
    }

    #[test]
    fn format_table_clean() {
        let snap = make_snap(1024 * 1024, None);
        let table = format_table(&snap);
        assert!(table.contains("Resident (VmRSS)"));
        assert!(table.contains("File-backed (RssFile)"));
        assert!(table.contains("Peak resident (VmHWM)"));
        assert!(table.contains("IO Read"));
        assert!(table.contains("Threads"));
        assert!(table.contains("test"));
        // Clean format should NOT show CPU, virtual-memory rows, or context switches.
        assert!(!table.contains("CPU (user)"));
        assert!(!table.contains("Virtual (VmSize)"));
        assert!(!table.contains("CtxSw"));
    }

    #[test]
    fn format_table_verbose_shows_all() {
        let snap = make_snap(1024 * 1024, None);
        let table = format_table_verbose(&snap);
        assert!(table.contains("Resident (VmRSS)"));
        assert!(table.contains("Virtual (VmSize)"));
        assert!(table.contains("Peak resident (VmHWM)"));
        assert!(table.contains("Peak virtual (VmPeak)"));
        assert!(table.contains("CtxSw"));
        assert!(table.contains("Cmdline"));
    }

    #[test]
    fn compute_summary_basic() {
        let series = SampleSeries {
            process_name: "test".into(),
            pid: 1,
            source: CollectionSource::Local,
            interval_ms: 1000,
            samples: vec![
                make_snap(10 * 1024 * 1024, Some(5.0)),
                make_snap(20 * 1024 * 1024, Some(10.0)),
                make_snap(30 * 1024 * 1024, Some(15.0)),
            ],
            summary: None,
        };
        let s = compute_summary(&series);
        assert_eq!(s.sample_count, 3);
        assert_eq!(s.rss.min, 10.0 * 1024.0 * 1024.0);
        assert_eq!(s.rss.max, 30.0 * 1024.0 * 1024.0);
        assert_eq!(s.cpu_percent.as_ref().unwrap().max, 15.0);
        assert_eq!(s.rss_trend, Trend::Rising);
    }

    #[test]
    fn format_markdown_contains_sections() {
        let series = SampleSeries {
            process_name: "test".into(),
            pid: 1,
            source: CollectionSource::Local,
            interval_ms: 1000,
            samples: vec![make_snap(1024 * 1024, Some(5.0))],
            summary: None,
        };
        let md = format_markdown(&series);
        assert!(md.contains("## Memory"));
        assert!(md.contains("## CPU"));
        assert!(md.contains("## IO"));
    }

    #[test]
    fn trend_detection_in_summary() {
        let series = SampleSeries {
            process_name: "test".into(),
            pid: 1,
            source: CollectionSource::Local,
            interval_ms: 1000,
            samples: vec![
                make_snap(10 * 1024 * 1024, None),
                make_snap(10 * 1024 * 1024, None),
                make_snap(10 * 1024 * 1024, None),
            ],
            summary: None,
        };
        let s = compute_summary(&series);
        assert_eq!(s.rss_trend, Trend::Stable);
    }

    #[test]
    fn compute_summary_preserves_unavailable_optional_metrics() {
        let mut snap = make_snap(10 * 1024 * 1024, None);
        snap.io_read_bytes = None;
        snap.io_write_bytes = None;
        snap.num_fds = None;

        let series = SampleSeries {
            process_name: "test".into(),
            pid: 1,
            source: CollectionSource::Local,
            interval_ms: 1000,
            samples: vec![snap],
            summary: None,
        };

        let summary = compute_summary(&series);
        assert!(summary.cpu_percent.is_none());
        assert!(summary.io_read_rate.is_none());
        assert!(summary.io_write_rate.is_none());
        assert!(summary.num_fds.is_none());
    }

    #[test]
    fn report_formats_unavailable_metrics_as_na() {
        let mut snap = make_snap(10 * 1024 * 1024, None);
        snap.io_read_bytes = None;
        snap.io_write_bytes = None;
        snap.num_fds = None;

        let series = SampleSeries {
            process_name: "test".into(),
            pid: 1,
            source: CollectionSource::Local,
            interval_ms: 1000,
            samples: vec![snap],
            summary: None,
        };

        let md = format_markdown(&series);
        assert!(md.contains("| CPU % | n/a | n/a | n/a | n/a |"));
        assert!(md.contains("| Read | n/a |"));
        assert!(md.contains("| Write | n/a |"));

        let table = format_report_table(&series);
        assert!(table.contains("CPU %"));
        assert!(table.contains("n/a"));
    }
}
