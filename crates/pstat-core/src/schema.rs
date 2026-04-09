use chrono::{DateTime, Utc};
use serde::{Deserialize, Serialize};

/// Process execution state, mapped from /proc/[pid]/stat field 3.
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub enum ProcessState {
    Running,
    Sleeping,
    DiskSleep,
    Stopped,
    TracingStop,
    Zombie,
    Dead,
    Unknown(char),
}

impl ProcessState {
    pub fn from_char(c: char) -> Self {
        match c {
            'R' => Self::Running,
            'S' => Self::Sleeping,
            'D' => Self::DiskSleep,
            'T' => Self::Stopped,
            't' => Self::TracingStop,
            'Z' => Self::Zombie,
            'X' | 'x' => Self::Dead,
            other => Self::Unknown(other),
        }
    }

    pub fn as_char(&self) -> char {
        match self {
            Self::Running => 'R',
            Self::Sleeping => 'S',
            Self::DiskSleep => 'D',
            Self::Stopped => 'T',
            Self::TracingStop => 't',
            Self::Zombie => 'Z',
            Self::Dead => 'X',
            Self::Unknown(c) => *c,
        }
    }
}

/// Where the snapshot was collected from.
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub enum CollectionSource {
    Local,
    Remote { target: String },
}

/// A single point-in-time snapshot of a process's resource usage.
#[derive(Clone, Debug, Serialize, Deserialize)]
pub struct ProcessSnapshot {
    // Identity
    pub pid: u32,
    pub ppid: u32,
    pub name: String,
    pub cmdline: Vec<String>,
    pub state: ProcessState,
    pub start_time: u64,

    // Memory (bytes) — field names match /proc/[pid]/status keys.
    /// VmRSS: current resident set size (physical memory actually used).
    pub rss: u64,
    /// VmHWM: high water mark — peak RSS ever recorded by the kernel.
    pub vm_hwm: u64,
    /// VmSize: total virtual memory.
    pub vms: u64,
    /// VmPeak: peak virtual memory ever.
    pub vm_peak: u64,
    /// VmSwap: swapped-out memory.
    pub vm_swap: u64,
    /// RssShmem: shared memory portion of RSS.
    pub shared: u64,
    /// Derived: rss / MemTotal * 100.
    pub mem_percent: f64,

    // Detailed memory from /proc/[pid]/smaps_rollup (Option, may not be available)
    /// PSS: proportional set size — "true" memory cost accounting for shared pages.
    pub pss: Option<u64>,
    /// USS: unique set size (Private_Clean + Private_Dirty) — freed when process exits.
    pub uss: Option<u64>,
    /// Shared memory (Shared_Clean + Shared_Dirty from smaps_rollup).
    pub shared_clean: Option<u64>,
    pub shared_dirty: Option<u64>,
    pub private_clean: Option<u64>,
    pub private_dirty: Option<u64>,
    /// Referenced: recently accessed pages.
    pub referenced: Option<u64>,
    /// Anonymous memory (heap, stack).
    pub anonymous: Option<u64>,
    /// SwapPss: proportional swap usage.
    pub swap_pss: Option<u64>,

    // CPU (milliseconds of cumulative time)
    pub cpu_user_ms: u64,
    pub cpu_system_ms: u64,
    /// None on a single snapshot; derived from delta between two samples.
    pub cpu_percent: Option<f64>,

    // IO — Option because /proc/[pid]/io may be restricted.
    pub io_read_bytes: Option<u64>,
    pub io_write_bytes: Option<u64>,
    pub io_syscr: Option<u64>,
    pub io_syscw: Option<u64>,

    // Resources
    pub num_threads: u32,
    /// Option because /proc/[pid]/fd may be restricted.
    pub num_fds: Option<u32>,
    pub ctx_switches_voluntary: u64,
    pub ctx_switches_involuntary: u64,

    // OOM
    /// OOM killer score (0-1000). Higher = more likely to be killed.
    pub oom_score: Option<u32>,
    /// OOM score adjustment (-1000 to 1000). Negative = protected.
    pub oom_score_adj: Option<i32>,

    // Cgroup
    /// Primary cgroup path (from /proc/[pid]/cgroup).
    pub cgroup: Option<String>,

    // Metadata
    pub timestamp: DateTime<Utc>,
    pub source: CollectionSource,
}

/// Minimal info returned by process discovery.
#[derive(Clone, Debug, Serialize, Deserialize)]
pub struct ProcessInfo {
    pub pid: u32,
    pub name: String,
    pub start_time: u64,
}

/// Time-series output from `pstat sample`.
#[derive(Clone, Debug, Serialize, Deserialize)]
pub struct SampleSeries {
    pub process_name: String,
    pub pid: u32,
    pub source: CollectionSource,
    pub interval_ms: u64,
    pub samples: Vec<ProcessSnapshot>,
    pub summary: Option<SampleSummary>,
}

/// Statistical summary computed over a SampleSeries.
#[derive(Clone, Debug, Serialize, Deserialize)]
pub struct SampleSummary {
    pub duration_s: f64,
    pub sample_count: usize,
    pub rss: StatBucket,
    pub vms: StatBucket,
    /// VmHWM max across all samples (peak RSS ever).
    pub vm_hwm_max: f64,
    /// Peak swap usage observed across all samples.
    pub vm_swap_max: f64,
    pub cpu_percent: StatBucket,
    pub io_read_rate: StatBucket,
    pub io_write_rate: StatBucket,
    pub num_threads: StatBucket,
    pub num_fds: StatBucket,
    pub rss_trend: Trend,
}

/// Min/max/avg/p50/p95 for one metric.
#[derive(Clone, Debug, Serialize, Deserialize)]
pub struct StatBucket {
    pub min: f64,
    pub max: f64,
    pub avg: f64,
    pub p50: f64,
    pub p95: f64,
}

impl StatBucket {
    /// Compute stats from a slice of values. Returns zeros if empty.
    pub fn from_values(values: &[f64]) -> Self {
        if values.is_empty() {
            return Self { min: 0.0, max: 0.0, avg: 0.0, p50: 0.0, p95: 0.0 };
        }
        let mut sorted = values.to_vec();
        sorted.sort_by(|a, b| a.partial_cmp(b).unwrap_or(std::cmp::Ordering::Equal));
        let n = sorted.len();
        let sum: f64 = sorted.iter().sum();
        Self {
            min: sorted[0],
            max: sorted[n - 1],
            avg: sum / n as f64,
            p50: sorted[n / 2],
            p95: sorted[(n as f64 * 0.95) as usize],
        }
    }
}

/// Direction of a metric over time.
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub enum Trend {
    Rising,
    Falling,
    Stable,
}

impl Trend {
    /// Determine trend from a sequence of values using simple linear regression slope.
    pub fn from_values(values: &[f64]) -> Self {
        if values.len() < 2 {
            return Self::Stable;
        }
        let n = values.len() as f64;
        let x_mean = (n - 1.0) / 2.0;
        let y_mean: f64 = values.iter().sum::<f64>() / n;

        let mut num = 0.0;
        let mut den = 0.0;
        for (i, y) in values.iter().enumerate() {
            let x = i as f64;
            num += (x - x_mean) * (y - y_mean);
            den += (x - x_mean) * (x - x_mean);
        }
        if den == 0.0 {
            return Self::Stable;
        }
        let slope = num / den;
        // Normalize slope relative to mean to determine significance.
        let relative = if y_mean.abs() > f64::EPSILON { slope / y_mean } else { slope };
        if relative > 0.01 {
            Self::Rising
        } else if relative < -0.01 {
            Self::Falling
        } else {
            Self::Stable
        }
    }
}

/// Output from `pstat diff`.
#[derive(Clone, Debug, Serialize, Deserialize)]
pub struct DiffReport {
    pub before: ProcessSnapshot,
    pub after: ProcessSnapshot,
    pub elapsed_s: f64,
    pub deltas: Vec<DiffField>,
}

/// One field's change between two snapshots.
#[derive(Clone, Debug, Serialize, Deserialize)]
pub struct DiffField {
    pub name: String,
    pub before: f64,
    pub after: f64,
    pub delta: f64,
    pub severity: DiffSeverity,
}

/// Thresholds: Minor = <10% change, Moderate = 10-50%, Significant = >50%.
/// For memory, also Significant if absolute delta > 50 MB.
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub enum DiffSeverity {
    Minor,
    Moderate,
    Significant,
}

impl DiffSeverity {
    const FIFTY_MB: f64 = 50.0 * 1024.0 * 1024.0;

    pub fn classify(before: f64, after: f64, is_memory: bool) -> Self {
        let delta = (after - before).abs();
        if is_memory && delta > Self::FIFTY_MB {
            return Self::Significant;
        }
        if before.abs() < f64::EPSILON {
            return if delta > f64::EPSILON { Self::Significant } else { Self::Minor };
        }
        let pct = delta / before.abs();
        if pct > 0.5 {
            Self::Significant
        } else if pct > 0.1 {
            Self::Moderate
        } else {
            Self::Minor
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn process_state_roundtrip() {
        for c in ['R', 'S', 'D', 'T', 't', 'Z', 'X'] {
            let state = ProcessState::from_char(c);
            assert_eq!(state.as_char(), c);
        }
        assert_eq!(ProcessState::from_char('W'), ProcessState::Unknown('W'));
    }

    #[test]
    fn stat_bucket_from_values() {
        let b = StatBucket::from_values(&[10.0, 20.0, 30.0, 40.0, 50.0]);
        assert_eq!(b.min, 10.0);
        assert_eq!(b.max, 50.0);
        assert_eq!(b.avg, 30.0);
        assert_eq!(b.p50, 30.0);
    }

    #[test]
    fn stat_bucket_empty() {
        let b = StatBucket::from_values(&[]);
        assert_eq!(b.min, 0.0);
    }

    #[test]
    fn trend_rising() {
        assert_eq!(Trend::from_values(&[10.0, 20.0, 30.0]), Trend::Rising);
    }

    #[test]
    fn trend_falling() {
        assert_eq!(Trend::from_values(&[30.0, 20.0, 10.0]), Trend::Falling);
    }

    #[test]
    fn trend_stable() {
        assert_eq!(Trend::from_values(&[10.0, 10.0, 10.0]), Trend::Stable);
    }

    #[test]
    fn diff_severity_minor() {
        assert_eq!(DiffSeverity::classify(100.0, 105.0, false), DiffSeverity::Minor);
    }

    #[test]
    fn diff_severity_moderate() {
        assert_eq!(DiffSeverity::classify(100.0, 130.0, false), DiffSeverity::Moderate);
    }

    #[test]
    fn diff_severity_significant() {
        assert_eq!(DiffSeverity::classify(100.0, 200.0, false), DiffSeverity::Significant);
    }

    #[test]
    fn diff_severity_memory_absolute() {
        // 60 MB delta is Significant for memory even if percentage is small.
        let before = 1_000_000_000.0;
        let after = before + 60.0 * 1024.0 * 1024.0;
        assert_eq!(DiffSeverity::classify(before, after, true), DiffSeverity::Significant);
    }

    #[test]
    fn snapshot_serde_roundtrip() {
        let snap = ProcessSnapshot {
            pid: 1234,
            ppid: 1,
            name: "test".into(),
            cmdline: vec!["/usr/bin/test".into(), "--flag".into()],
            state: ProcessState::Running,
            start_time: 12345,
            rss: 1024 * 1024,
            vms: 4 * 1024 * 1024,
            vm_hwm: 2 * 1024 * 1024,
            vm_peak: 5 * 1024 * 1024,
            vm_swap: 0,
            shared: 512 * 1024,
            mem_percent: 0.5,
            cpu_user_ms: 1000,
            cpu_system_ms: 200,
            cpu_percent: None,
            io_read_bytes: Some(4096),
            io_write_bytes: Some(2048),
            io_syscr: Some(100),
            io_syscw: Some(50),
            num_threads: 4,
            num_fds: Some(20),
            ctx_switches_voluntary: 100,
            ctx_switches_involuntary: 10,
            pss: Some(800 * 1024),
            uss: Some(500 * 1024),
            shared_clean: Some(200 * 1024),
            shared_dirty: None,
            private_clean: Some(100 * 1024),
            private_dirty: Some(400 * 1024),
            referenced: Some(900 * 1024),
            anonymous: Some(400 * 1024),
            swap_pss: None,
            oom_score: Some(100),
            oom_score_adj: Some(0),
            cgroup: Some("/user.slice".into()),
            timestamp: Utc::now(),
            source: CollectionSource::Local,
        };
        let json = serde_json::to_string(&snap).unwrap();
        let back: ProcessSnapshot = serde_json::from_str(&json).unwrap();
        assert_eq!(back.pid, 1234);
        assert_eq!(back.name, "test");
        assert_eq!(back.state, ProcessState::Running);
        assert_eq!(back.io_read_bytes, Some(4096));
    }

    #[test]
    fn sample_series_serde_roundtrip() {
        let series = SampleSeries {
            process_name: "test".into(),
            pid: 1234,
            source: CollectionSource::Remote { target: "192.168.0.1".into() },
            interval_ms: 1000,
            samples: vec![],
            summary: None,
        };
        let json = serde_json::to_string(&series).unwrap();
        let back: SampleSeries = serde_json::from_str(&json).unwrap();
        assert_eq!(back.process_name, "test");
        assert_eq!(back.source, CollectionSource::Remote { target: "192.168.0.1".into() });
    }
}
