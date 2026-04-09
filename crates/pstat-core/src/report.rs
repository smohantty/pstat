use comfy_table::{Attribute, Cell, CellAlignment, ContentArrangement, Table, presets};

use crate::schema::{
    CollectionSource, DiffReport, DiffSeverity, ProcessSnapshot, SampleSeries, SampleSummary,
    StatBucket, Trend,
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
    md.push_str(&format!("# {} (PID {})\n\n", snapshot.name, snapshot.pid));
    if !snapshot.cmdline.is_empty() {
        md.push_str(&format!("`{}`\n\n", snapshot.cmdline.join(" ")));
    }
    md.push_str(&format!("{source} \u{00b7} {state} \u{00b7} {time}\n\n"));

    md.push_str("| Metric | Value |\n");
    md.push_str("|--------|-------|\n");
    md.push_str(&format!("| RSS | {} |\n", fmt_bytes(snapshot.rss as f64)));
    if let Some(pss) = snapshot.pss {
        md.push_str(&format!("| PSS | {} |\n", fmt_bytes(pss as f64)));
    }
    if let Some(uss) = snapshot.uss {
        md.push_str(&format!("| USS | {} |\n", fmt_bytes(uss as f64)));
    }
    if snapshot.vm_hwm > 0 {
        md.push_str(&format!(
            "| Peak RSS | {} |\n",
            fmt_bytes(snapshot.vm_hwm as f64)
        ));
    }
    if verbose {
        md.push_str(&format!("| VMS | {} |\n", fmt_bytes(snapshot.vms as f64)));
        md.push_str(&format!(
            "| VMS Peak | {} |\n",
            fmt_bytes(snapshot.vm_peak as f64)
        ));
    }
    if snapshot.vm_swap > 0 {
        md.push_str(&format!(
            "| Swap | {} |\n",
            fmt_bytes(snapshot.vm_swap as f64)
        ));
    }
    if verbose {
        md.push_str(&format!(
            "| Shared | {} |\n",
            fmt_bytes(snapshot.shared as f64)
        ));
        if let Some(sc) = snapshot.shared_clean {
            md.push_str(&format!("| Shared Clean | {} |\n", fmt_bytes(sc as f64)));
        }
        if let Some(sd) = snapshot.shared_dirty {
            md.push_str(&format!("| Shared Dirty | {} |\n", fmt_bytes(sd as f64)));
        }
        if let Some(pc) = snapshot.private_clean {
            md.push_str(&format!("| Private Clean | {} |\n", fmt_bytes(pc as f64)));
        }
        if let Some(pd) = snapshot.private_dirty {
            md.push_str(&format!("| Private Dirty | {} |\n", fmt_bytes(pd as f64)));
        }
        if let Some(r) = snapshot.referenced {
            md.push_str(&format!("| Referenced | {} |\n", fmt_bytes(r as f64)));
        }
        if let Some(a) = snapshot.anonymous {
            md.push_str(&format!("| Anonymous | {} |\n", fmt_bytes(a as f64)));
        }
        if let Some(sp) = snapshot.swap_pss {
            md.push_str(&format!("| Swap PSS | {} |\n", fmt_bytes(sp as f64)));
        }
        md.push_str(&format!("| Mem % | {:.2}% |\n", snapshot.mem_percent));
    }
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

    table.set_header(vec![
        Cell::new(format!("{} (PID {})", snapshot.name, snapshot.pid))
            .add_attribute(Attribute::Bold),
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
        Cell::new("RSS"),
        Cell::new(fmt_bytes(snapshot.rss as f64)),
    ]);
    if let Some(pss) = snapshot.pss {
        table.add_row(vec![Cell::new("PSS"), Cell::new(fmt_bytes(pss as f64))]);
    }
    if let Some(uss) = snapshot.uss {
        table.add_row(vec![Cell::new("USS"), Cell::new(fmt_bytes(uss as f64))]);
    }

    if snapshot.vm_hwm > 0 {
        table.add_row(vec![
            Cell::new("Peak RSS"),
            Cell::new(fmt_bytes(snapshot.vm_hwm as f64)),
        ]);
    }

    if verbose {
        table.add_row(vec![
            Cell::new("VMS"),
            Cell::new(fmt_bytes(snapshot.vms as f64)),
        ]);
        table.add_row(vec![
            Cell::new("VMS Peak"),
            Cell::new(fmt_bytes(snapshot.vm_peak as f64)),
        ]);
    }

    if snapshot.vm_swap > 0 {
        table.add_row(vec![
            Cell::new("Swap"),
            Cell::new(fmt_bytes(snapshot.vm_swap as f64)),
        ]);
    }

    if verbose {
        table.add_row(vec![
            Cell::new("Shared"),
            Cell::new(fmt_bytes(snapshot.shared as f64)),
        ]);
        if let Some(sc) = snapshot.shared_clean {
            table.add_row(vec![
                Cell::new("Shared Clean"),
                Cell::new(fmt_bytes(sc as f64)),
            ]);
        }
        if let Some(sd) = snapshot.shared_dirty {
            table.add_row(vec![
                Cell::new("Shared Dirty"),
                Cell::new(fmt_bytes(sd as f64)),
            ]);
        }
        if let Some(pc) = snapshot.private_clean {
            table.add_row(vec![
                Cell::new("Private Clean"),
                Cell::new(fmt_bytes(pc as f64)),
            ]);
        }
        if let Some(pd) = snapshot.private_dirty {
            table.add_row(vec![
                Cell::new("Private Dirty"),
                Cell::new(fmt_bytes(pd as f64)),
            ]);
        }
        if let Some(r) = snapshot.referenced {
            table.add_row(vec![
                Cell::new("Referenced"),
                Cell::new(fmt_bytes(r as f64)),
            ]);
        }
        if let Some(a) = snapshot.anonymous {
            table.add_row(vec![Cell::new("Anonymous"), Cell::new(fmt_bytes(a as f64))]);
        }
        if let Some(sp) = snapshot.swap_pss {
            table.add_row(vec![Cell::new("Swap PSS"), Cell::new(fmt_bytes(sp as f64))]);
        }
        table.add_row(vec![
            Cell::new("Mem %"),
            Cell::new(format!("{:.2}%", snapshot.mem_percent)),
        ]);
    }

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
            Cell::new(&d.name),
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
        "| RSS | {} | {} | {} | {} | {:?} |\n",
        fmt_bytes(summary.rss.min),
        fmt_bytes(summary.rss.max),
        fmt_bytes(summary.rss.avg),
        fmt_bytes(summary.rss.p95),
        summary.rss_trend
    ));
    md.push_str(&format!(
        "| VMS | {} | {} | {} | {} | - |\n",
        fmt_bytes(summary.vms.min),
        fmt_bytes(summary.vms.max),
        fmt_bytes(summary.vms.avg),
        fmt_bytes(summary.vms.p95),
    ));
    md.push_str(&format!(
        "| Peak RSS (all-time) | - | {} | - | - | - |\n",
        fmt_bytes(summary.vm_hwm_max)
    ));
    if summary.vm_swap_max > 0.0 {
        md.push_str(&format!(
            "| Swap (max) | - | {} | - | - | - |\n",
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
        Cell::new("RSS"),
        Cell::new(fmt_bytes(summary.rss.min)).set_alignment(CellAlignment::Right),
        Cell::new(fmt_bytes(summary.rss.max)).set_alignment(CellAlignment::Right),
        Cell::new(fmt_bytes(summary.rss.avg)).set_alignment(CellAlignment::Right),
        Cell::new(fmt_bytes(summary.rss.p95)).set_alignment(CellAlignment::Right),
        Cell::new(format!("{:?}", summary.rss_trend)),
    ]);
    mem_table.add_row(vec![
        Cell::new("Peak RSS"),
        Cell::new(""),
        Cell::new(fmt_bytes(summary.vm_hwm_max)).set_alignment(CellAlignment::Right),
        Cell::new(""),
        Cell::new(""),
        Cell::new("all-time"),
    ]);
    if summary.vm_swap_max > 0.0 {
        mem_table.add_row(vec![
            Cell::new("Swap"),
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
        assert!(table.contains("RSS"));
        assert!(table.contains("Peak RSS"));
        assert!(table.contains("CPU (user)"));
        assert!(table.contains("IO Read"));
        assert!(table.contains("Threads"));
        assert!(table.contains("test"));
        // Clean format should NOT show VMS or context switches
        assert!(!table.contains("VMS"));
        assert!(!table.contains("CtxSw"));
    }

    #[test]
    fn format_table_verbose_shows_all() {
        let snap = make_snap(1024 * 1024, None);
        let table = format_table_verbose(&snap);
        assert!(table.contains("RSS"));
        assert!(table.contains("VMS"));
        assert!(table.contains("Peak RSS"));
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
