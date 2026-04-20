use crate::schema::{MemoryMapReport, ProcessInfo, ProcessSnapshot};

/// How to identify the target process.
#[derive(Clone, Debug)]
pub enum ProcessTarget {
    Pid(u32),
    Name(String),
    ExeContains(String),
}

/// Query for process discovery.
#[derive(Clone, Debug)]
pub enum DiscoverQuery {
    /// Exact match on /proc/[pid]/comm.
    ByName(String),
    /// Substring match on cmdline or exe path.
    ByExeContains(String),
    /// Glob pattern match.
    ByPattern(String),
    /// List all processes.
    All,
}

/// Errors that can occur during stat collection.
#[derive(Debug, thiserror::Error)]
pub enum PstatError {
    #[error("process not found: {0}")]
    ProcessNotFound(String),

    #[error("permission denied: {0}")]
    PermissionDenied(String),

    #[error("target unreachable: {0}")]
    TargetUnreachable(String),

    #[error("parse error: {0}")]
    ParseError(String),

    #[error("ambiguous match: {0} processes found for \"{1}\": {2:?}")]
    AmbiguousMatch(usize, String, Vec<ProcessInfo>),

    #[error("process identity mismatch: PID {0} changed during collection")]
    IdentityMismatch(u32),

    #[error("{0}")]
    Other(#[from] anyhow::Error),
}

/// All implementations are synchronous. `RsdbCollector` invokes rsdb via
/// `std::process::Command`.
pub trait Collector {
    fn snapshot(&self, target: &ProcessTarget) -> Result<ProcessSnapshot, PstatError>;
    fn discover(&self, query: &DiscoverQuery) -> Result<Vec<ProcessInfo>, PstatError>;
    fn total_memory(&self) -> Result<u64, PstatError>;
    /// Build a full memory-map report from /proc/[pid]/smaps. Significantly
    /// more expensive than snapshot — reads every VMA.
    fn memory_map(&self, target: &ProcessTarget) -> Result<MemoryMapReport, PstatError>;
}

pub(crate) fn ticks_to_millis(ticks: u64, hz: u64) -> u64 {
    ticks.saturating_mul(1000) / hz
}

#[cfg(test)]
mod tests {
    use super::ticks_to_millis;

    #[test]
    fn ticks_to_millis_uses_runtime_hz() {
        assert_eq!(ticks_to_millis(250, 250), 1000);
        assert_eq!(ticks_to_millis(1000, 1000), 1000);
        assert_eq!(ticks_to_millis(125, 250), 500);
    }
}
