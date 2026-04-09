use std::fs;
use std::io::{IsTerminal, Write};
use std::sync::Arc;
use std::sync::atomic::{AtomicBool, Ordering};
use std::thread;
use std::time::Duration;

use anyhow::{Context, Result};
use clap::{Parser, Subcommand, ValueEnum};
use pstat_core::collector::{Collector, DiscoverQuery, ProcessTarget, PstatError};
use pstat_core::diff::compute_diff;
use pstat_core::local::LocalCollector;
use pstat_core::remote::RsdbCollector;
use pstat_core::report;
use pstat_core::schema::{ProcessSnapshot, SampleSeries};

#[derive(Debug, Parser)]
#[command(name = "pstat")]
#[command(
    about = "Process stat collection tool — snapshot, sample, diff, discover, report, schema"
)]
#[command(version)]
struct Cli {
    #[command(subcommand)]
    command: Commands,
}

#[derive(Debug, Subcommand)]
enum Commands {
    /// Take a one-time process snapshot.
    Snapshot {
        #[arg(long)]
        pid: Option<u32>,
        #[arg(long)]
        name: Option<String>,
        #[arg(long)]
        exe: Option<String>,
        #[arg(long, value_name = "ADDR")]
        target: Option<String>,
        #[arg(long, value_enum)]
        format: Option<OutputFormat>,
        #[arg(long, value_name = "PATH")]
        output: Option<String>,
        /// Show all fields including VMS, shared memory, context switches, syscall counts.
        #[arg(long, short)]
        verbose: bool,
    },
    /// Collect N samples at given interval.
    Sample {
        #[arg(long)]
        pid: Option<u32>,
        #[arg(long)]
        name: Option<String>,
        #[arg(long)]
        exe: Option<String>,
        #[arg(long, value_name = "ADDR")]
        target: Option<String>,
        /// Interval between samples (e.g. "1s", "500ms").
        #[arg(long, default_value = "1s")]
        interval: String,
        /// Number of samples to collect.
        #[arg(long, default_value = "60")]
        count: usize,
        #[arg(long, value_enum)]
        format: Option<OutputFormat>,
        #[arg(long, value_name = "PATH")]
        output: Option<String>,
    },
    /// Compare two snapshot files and show deltas.
    Diff {
        file1: String,
        file2: String,
        #[arg(long, value_enum)]
        format: Option<OutputFormat>,
    },
    /// List running processes matching a pattern.
    Discover {
        #[arg(long, value_name = "ADDR")]
        target: Option<String>,
        #[arg(long)]
        filter: Option<String>,
    },
    /// Generate a report from a sample series file.
    Report {
        samples_file: String,
        #[arg(long, value_enum)]
        format: Option<OutputFormat>,
        #[arg(long, value_name = "PATH")]
        output: Option<String>,
    },
    /// Print a terse agent-oriented CLI schema.
    Schema,
}

#[derive(Clone, Debug, ValueEnum)]
enum OutputFormat {
    Json,
    Table,
    Md,
}

fn default_format(explicit: Option<OutputFormat>) -> OutputFormat {
    explicit.unwrap_or_else(|| {
        if std::io::stdout().is_terminal() {
            OutputFormat::Table
        } else {
            OutputFormat::Json
        }
    })
}

fn resolve_target(
    pid: Option<u32>,
    name: Option<String>,
    exe: Option<String>,
) -> Result<ProcessTarget> {
    if let Some(p) = pid {
        Ok(ProcessTarget::Pid(p))
    } else if let Some(n) = name {
        Ok(ProcessTarget::Name(n))
    } else if let Some(e) = exe {
        Ok(ProcessTarget::ExeContains(e))
    } else {
        anyhow::bail!("specify --pid, --name, or --exe to identify the process")
    }
}

fn make_collector(target: Option<String>) -> Box<dyn Collector> {
    match target {
        Some(addr) => Box::new(RsdbCollector::new(addr)),
        None => Box::new(LocalCollector),
    }
}

fn write_output(content: &str, output_path: Option<&str>) -> Result<()> {
    match output_path {
        Some(path) => {
            // Strip ANSI escape codes when writing to file
            let clean = strip_ansi(content);
            let out = if clean.ends_with('\n') {
                clean
            } else {
                format!("{clean}\n")
            };
            fs::write(path, &out).with_context(|| format!("writing to {path}"))?;
            eprintln!("Written to {path}");
        }
        None => {
            print!("{content}");
            std::io::stdout().flush()?;
        }
    }
    Ok(())
}

/// Remove ANSI escape sequences from a string.
fn strip_ansi(s: &str) -> String {
    let mut out = String::with_capacity(s.len());
    let mut chars = s.chars();
    while let Some(c) = chars.next() {
        if c == '\x1b' {
            // Skip until we find the terminating letter
            for c2 in chars.by_ref() {
                if c2.is_ascii_alphabetic() {
                    break;
                }
            }
        } else {
            out.push(c);
        }
    }
    out
}

fn parse_duration(s: &str) -> Result<Duration> {
    let parse_f64_safe = |v: &str| -> Result<f64> {
        let f: f64 = v.parse()?;
        anyhow::ensure!(
            f.is_finite() && f >= 0.0,
            "duration must be a non-negative number, got '{v}'"
        );
        Ok(f)
    };

    if let Some(ms) = s.strip_suffix("ms") {
        let v: u64 = ms.parse()?;
        Ok(Duration::from_millis(v))
    } else if let Some(secs) = s.strip_suffix('s') {
        Ok(Duration::from_secs_f64(parse_f64_safe(secs)?))
    } else if let Some(mins) = s.strip_suffix('m') {
        Ok(Duration::from_secs_f64(parse_f64_safe(mins)? * 60.0))
    } else {
        Ok(Duration::from_secs_f64(parse_f64_safe(s)?))
    }
}

fn cli_schema() -> &'static str {
    r#"pstat
rules:
- prefer explicit json paths for machine use; do not rely on tty defaults
- selector: exactly one of --pid <u32> | --name <str> | --exe <str>
- remote: add --target <addr>
- sample default: NDJSON snapshots, then final summary line
- sample/report json: full SampleSeries json; report recomputes summary
- non-tty errors: stderr json {"error":{"code","message"}}

snapshot [selector] [--target <addr>] [--format json] [--output <path>]
sample [selector] [--target <addr>] [--interval <duration>] [--count <usize>] [--format json] [--output <path>]
discover [--target <addr>] [--filter <glob>]
diff <snapshot1.json> <snapshot2.json> [--format json]
report <samples.json> [--format json] [--output <path>]
"#
}

fn refresh_summary(series: &mut SampleSeries) {
    let summary = report::compute_summary(series);
    series.summary = Some(summary);
}

fn record_or_verify_sample_identity(
    expected_identity: &mut Option<(u32, u64)>,
    snapshot: &ProcessSnapshot,
) -> Result<(), PstatError> {
    match expected_identity {
        Some((expected_pid, expected_start_time))
            if *expected_pid != snapshot.pid || *expected_start_time != snapshot.start_time =>
        {
            Err(PstatError::IdentityMismatch(*expected_pid))
        }
        Some(_) => Ok(()),
        None => {
            *expected_identity = Some((snapshot.pid, snapshot.start_time));
            Ok(())
        }
    }
}

fn run() -> Result<(), PstatError> {
    let cli = Cli::parse();

    match cli.command {
        Commands::Snapshot {
            pid,
            name,
            exe,
            target,
            format,
            output,
            verbose,
        } => {
            let proc_target = resolve_target(pid, name, exe).map_err(|e| PstatError::Other(e))?;
            let collector = make_collector(target);
            let snap = collector.snapshot(&proc_target)?;
            let fmt = default_format(format);
            let text = match fmt {
                OutputFormat::Json => report::format_json(&snap),
                OutputFormat::Table if verbose => report::format_table_verbose(&snap),
                OutputFormat::Table => report::format_table(&snap),
                OutputFormat::Md if verbose => report::format_snapshot_md_verbose(&snap),
                OutputFormat::Md => report::format_snapshot_md(&snap),
            };
            write_output(&text, output.as_deref()).map_err(|e| PstatError::Other(e))?;
            if !text.ends_with('\n') {
                println!();
            }
        }

        Commands::Sample {
            pid,
            name,
            exe,
            target,
            interval,
            count,
            format,
            output,
        } => {
            let proc_target = resolve_target(pid, name, exe).map_err(|e| PstatError::Other(e))?;
            let collector = make_collector(target.clone());
            let interval_dur = parse_duration(&interval).map_err(|e| PstatError::Other(e))?;
            let interval_ms = interval_dur.as_millis() as u64;
            // Sample streams NDJSON by default (no --format). Only use table/md
            // when explicitly requested via --format.
            let explicit_fmt = format.clone();
            let stream_ndjson = explicit_fmt.is_none() && output.is_none();

            // SIGINT handling
            let interrupted = Arc::new(AtomicBool::new(false));
            let int_flag = interrupted.clone();
            ctrlc::set_handler(move || {
                int_flag.store(true, Ordering::SeqCst);
            })
            .map_err(|e| PstatError::Other(anyhow::anyhow!("ctrlc handler: {e}")))?;

            let mut samples = Vec::new();
            let mut prev_cpu: Option<(u64, u64, std::time::Instant)> = None;
            let mut sampled_identity: Option<(u32, u64)> = None;

            let source = match &target {
                Some(addr) => pstat_core::schema::CollectionSource::Remote {
                    target: addr.clone(),
                },
                None => pstat_core::schema::CollectionSource::Local,
            };

            for i in 0..count {
                if interrupted.load(Ordering::SeqCst) {
                    eprintln!("\nInterrupted after {i} samples");
                    break;
                }

                let mut snap = collector.snapshot(&proc_target)?;
                record_or_verify_sample_identity(&mut sampled_identity, &snap)?;

                // Compute cpu_percent from delta
                let now = std::time::Instant::now();
                if let Some((prev_user, prev_sys, prev_time)) = prev_cpu {
                    let wall_ms = now.duration_since(prev_time).as_millis() as f64;
                    if wall_ms > 0.0 {
                        let cpu_delta = (snap.cpu_user_ms + snap.cpu_system_ms)
                            .saturating_sub(prev_user + prev_sys)
                            as f64;
                        snap.cpu_percent = Some((cpu_delta / wall_ms) * 100.0);
                    }
                }
                prev_cpu = Some((snap.cpu_user_ms, snap.cpu_system_ms, now));

                // Stream NDJSON to stdout only in json mode without --output
                if stream_ndjson {
                    let line = report::format_ndjson_line(&snap);
                    println!("{line}");
                    std::io::stdout().flush().ok();
                }

                samples.push(snap);

                // Sleep between samples (skip after last)
                if i + 1 < count && !interrupted.load(Ordering::SeqCst) {
                    thread::sleep(interval_dur);
                }
            }

            let process_name = samples.first().map(|s| s.name.clone()).unwrap_or_default();
            let pid_val = samples.first().map(|s| s.pid).unwrap_or(0);

            let mut series = SampleSeries {
                process_name,
                pid: pid_val,
                source,
                interval_ms,
                samples,
                summary: None,
            };
            refresh_summary(&mut series);

            // Output based on format
            if let Some(ref path) = output {
                // --output: always write full SampleSeries JSON to file
                let json = serde_json::to_string_pretty(&series)
                    .map_err(|e| PstatError::Other(e.into()))?;
                fs::write(path, &json)
                    .map_err(|e| PstatError::Other(anyhow::anyhow!("write {path}: {e}")))?;
                eprintln!("Written {} samples to {path}", series.samples.len());
            } else if let Some(ref f) = explicit_fmt {
                // Explicit --format: show report in that format
                match f {
                    OutputFormat::Json => {
                        let json = serde_json::to_string_pretty(&series)
                            .map_err(|e| PstatError::Other(e.into()))?;
                        println!("{json}");
                    }
                    OutputFormat::Table => {
                        println!("{}", report::format_report_table(&series));
                    }
                    OutputFormat::Md => {
                        println!("{}", report::format_markdown(&series));
                    }
                }
            } else {
                // No --format, no --output: NDJSON was already streamed, print summary
                if let Some(ref summary) = series.summary {
                    println!("{}", report::format_summary_ndjson(summary));
                }
            }
        }

        Commands::Diff {
            file1,
            file2,
            format,
        } => {
            let s1 = fs::read_to_string(&file1)
                .map_err(|e| PstatError::Other(anyhow::anyhow!("{file1}: {e}")))?;
            let s2 = fs::read_to_string(&file2)
                .map_err(|e| PstatError::Other(anyhow::anyhow!("{file2}: {e}")))?;

            let before: ProcessSnapshot = serde_json::from_str(&s1)
                .map_err(|e| PstatError::ParseError(format!("{file1}: {e}")))?;
            let after: ProcessSnapshot = serde_json::from_str(&s2)
                .map_err(|e| PstatError::ParseError(format!("{file2}: {e}")))?;

            let diff = compute_diff(&before, &after);
            let fmt = default_format(format);
            let text = match fmt {
                OutputFormat::Json => {
                    serde_json::to_string_pretty(&diff).map_err(|e| PstatError::Other(e.into()))?
                }
                OutputFormat::Table | OutputFormat::Md => report::format_diff_table(&diff),
            };
            println!("{text}");
        }

        Commands::Discover { target, filter } => {
            let collector = make_collector(target);
            let query = match filter {
                Some(f) => DiscoverQuery::ByPattern(f),
                None => DiscoverQuery::All,
            };
            let procs = collector.discover(&query)?;
            for p in &procs {
                println!("{:>8}  {}", p.pid, p.name);
            }
            eprintln!("{} processes found", procs.len());
        }

        Commands::Report {
            samples_file,
            format,
            output,
        } => {
            let content = fs::read_to_string(&samples_file)
                .map_err(|e| PstatError::Other(anyhow::anyhow!("{samples_file}: {e}")))?;
            let mut series: SampleSeries = serde_json::from_str(&content)
                .map_err(|e| PstatError::ParseError(format!("{samples_file}: {e}")))?;
            refresh_summary(&mut series);
            let fmt = default_format(format);
            let text = match fmt {
                OutputFormat::Json => serde_json::to_string_pretty(&series)
                    .map_err(|e| PstatError::Other(e.into()))?,
                OutputFormat::Table => report::format_report_table(&series),
                OutputFormat::Md => report::format_markdown(&series),
            };
            write_output(&text, output.as_deref()).map_err(|e| PstatError::Other(e))?;
            if !text.ends_with('\n') {
                println!();
            }
        }

        Commands::Schema => {
            print!("{}", cli_schema());
        }
    }

    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;
    use chrono::Utc;
    use pstat_core::schema::{CollectionSource, ProcessState};

    fn make_sample_snapshot(pid: u32, start_time: u64, rss: u64) -> ProcessSnapshot {
        ProcessSnapshot {
            pid,
            ppid: 1,
            name: "test".into(),
            cmdline: vec![],
            state: ProcessState::Running,
            start_time,
            rss,
            vm_hwm: rss,
            vms: rss * 2,
            vm_peak: rss * 2,
            vm_swap: 0,
            shared: 0,
            mem_percent: 0.0,
            pss: None,
            uss: None,
            shared_clean: None,
            shared_dirty: None,
            private_clean: None,
            private_dirty: None,
            referenced: None,
            anonymous: None,
            swap_pss: None,
            cpu_user_ms: 100,
            cpu_system_ms: 50,
            cpu_percent: None,
            io_read_bytes: None,
            io_write_bytes: None,
            io_syscr: None,
            io_syscw: None,
            num_threads: 4,
            num_fds: None,
            ctx_switches_voluntary: 0,
            ctx_switches_involuntary: 0,
            oom_score: None,
            oom_score_adj: None,
            cgroup: None,
            timestamp: Utc::now(),
            source: CollectionSource::Local,
        }
    }

    #[test]
    fn sample_identity_rejects_replaced_process() {
        let mut identity = None;
        let first = make_sample_snapshot(42, 100, 1024);
        record_or_verify_sample_identity(&mut identity, &first).unwrap();

        let replaced = make_sample_snapshot(42, 101, 2048);
        let err = record_or_verify_sample_identity(&mut identity, &replaced).unwrap_err();
        assert!(matches!(err, PstatError::IdentityMismatch(42)));
    }

    #[test]
    fn refresh_summary_recomputes_existing_summary() {
        let first = make_sample_snapshot(42, 100, 1024);
        let second = make_sample_snapshot(42, 100, 2048);

        let mut series = SampleSeries {
            process_name: "test".into(),
            pid: 42,
            source: CollectionSource::Local,
            interval_ms: 1000,
            samples: vec![first],
            summary: None,
        };
        refresh_summary(&mut series);
        let stale = series.summary.clone();

        series.samples.push(second);
        series.summary = stale;
        refresh_summary(&mut series);

        let summary = series.summary.as_ref().unwrap();
        assert_eq!(summary.sample_count, 2);
        assert_eq!(summary.rss.max, 2048.0);
    }

    #[test]
    fn cli_schema_covers_agent_contract() {
        let schema = cli_schema();
        assert!(schema.contains("sample default: NDJSON snapshots"));
        assert!(schema.contains("report recomputes summary"));
        assert!(schema.contains("non-tty errors: stderr json"));
        assert!(schema.contains("snapshot [selector]"));
    }
}

fn main() {
    match run() {
        Ok(()) => {}
        Err(e) => {
            // Structured JSON error to stderr for agents
            if !std::io::stdout().is_terminal() {
                let code = match &e {
                    PstatError::ProcessNotFound(_) => "process_not_found",
                    PstatError::PermissionDenied(_) => "permission_denied",
                    PstatError::TargetUnreachable(_) => "target_unreachable",
                    PstatError::ParseError(_) => "parse_error",
                    PstatError::AmbiguousMatch(..) => "ambiguous_match",
                    PstatError::IdentityMismatch(_) => "identity_mismatch",
                    PstatError::Other(_) => "error",
                };
                eprintln!(
                    "{}",
                    serde_json::json!({"error": {"code": code, "message": e.to_string()}})
                );
            } else {
                eprintln!("error: {e}");
            }

            let exit_code = match &e {
                PstatError::ProcessNotFound(_) => 1,
                PstatError::TargetUnreachable(_) => 2,
                PstatError::PermissionDenied(_) => 3,
                PstatError::ParseError(_) => 4,
                _ => 1,
            };
            std::process::exit(exit_code);
        }
    }
}
