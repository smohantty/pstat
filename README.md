# pstat

Process stat collection tool for Linux. Snapshot, sample, diff, discover, and report
process resource usage locally or on remote Tizen targets via [rsdb](https://github.com/smohantty/rsdb).

Designed for two audiences: **humans** (terminal tables, markdown reports) and
**autonomous AI agents** (structured JSON, NDJSON streaming, machine-parseable errors).

## Install

```bash
cargo install --path crates/pstat
```

Or build from source:

```bash
git clone https://github.com/smohantty/pstat.git
cd pstat
cargo build --release
# Binary at target/release/pstat
```

## Quick Start

```bash
# Snapshot a local process
pstat snapshot --pid 1234
pstat snapshot --name nginx

# Snapshot a process on a remote Tizen target
pstat snapshot --name myapp --target 192.168.0.218

# Sample 60 times at 1s intervals
pstat sample --name myapp --target 192.168.0.218 --interval 1s --count 60

# Compare two snapshots
pstat diff before.json after.json

# Generate a report
pstat sample --name myapp --interval 1s --count 30 --output samples.json
pstat report samples.json --format md --output report.md
```

## Commands

### snapshot

Take a one-time process snapshot.

```
pstat snapshot [--pid <PID> | --name <NAME> | --exe <SUBSTR>]
               [--target <ADDR>] [--format json|table|md] [--output <PATH>]
```

```bash
# Local, table format (default in terminal)
pstat snapshot --name nginx

# Remote target, JSON output
pstat snapshot --name myapp --target 192.168.0.218 --format json

# Save to file
pstat snapshot --pid 5497 --target 192.168.0.218 --output snap.json
```

### sample

Collect N snapshots at a fixed interval. Computes cpu_percent from deltas between samples.

```
pstat sample [--pid <PID> | --name <NAME> | --exe <SUBSTR>]
             [--target <ADDR>] [--interval <DURATION>] [--count <N>]
             [--format json|table|md] [--output <PATH>]
```

- **Stdout**: streams NDJSON (one JSON object per line), final line is the summary tagged `{"type":"summary"}`
- **--output**: writes a single `SampleSeries` JSON file on completion
- **Ctrl+C**: flushes all collected samples and exits cleanly
- **Defaults**: `--interval 1s --count 60`

```bash
# Stream to terminal (NDJSON)
pstat sample --name myapp --target 192.168.0.218 --interval 500ms --count 20

# Save to file for later analysis
pstat sample --name myapp --interval 2s --count 30 --output samples.json
```

### diff

Compare two snapshot JSON files and show what changed.

```
pstat diff <file1.json> <file2.json> [--format json|table|md]
```

Shows per-field deltas with severity markers:
- `+++` significant (>50% change or >50 MB for memory)
- `++` moderate (10-50%)
- `+` minor (<10%)

```bash
pstat snapshot --name myapp --output before.json
sleep 60
pstat snapshot --name myapp --output after.json
pstat diff before.json after.json
```

### discover

List running processes, optionally filtered by name pattern.

```
pstat discover [--target <ADDR>] [--filter <PATTERN>]
```

```bash
# All processes on remote target
pstat discover --target 192.168.0.218

# Filter by name
pstat discover --filter "nginx"
pstat discover --target 192.168.0.218 --filter "zeroclaw"
```

### report

Generate a summary report from a sample series file.

```
pstat report <samples.json> [--format json|table|md] [--output <PATH>]
```

The report includes:
- **Memory**: RSS min/max/avg/p95, Peak RSS (all-time VmHWM), Swap, trend detection
- **CPU**: min/max/avg/p95 with burst detection
- **IO**: average read/write rates, workload characterization
- **Resources**: thread and FD count ranges

```bash
pstat report samples.json --format table
pstat report samples.json --format md --output report.md
```

## Output Formats

| Format | Flag | When | Use case |
|--------|------|------|----------|
| `json` | `--format json` | Default when piped | Agent consumption, scripting |
| `table` | `--format table` | Default in terminal | Human reading |
| `md` | `--format md` | Explicit | Reports, sharing, documentation |

The format auto-detects based on whether stdout is a TTY:
- **TTY** (interactive terminal): table format
- **Piped** (script, agent): JSON format

## Collected Metrics

| Metric | Source | Notes |
|--------|--------|-------|
| PID, PPID, name, cmdline, state | `/proc/[pid]/stat`, `comm`, `cmdline` | |
| RSS, VMS, VM Peak, VM Swap, Shared | `/proc/[pid]/status` | Bytes |
| Memory % | Derived | RSS / MemTotal |
| CPU user, CPU system | `/proc/[pid]/stat` | Cumulative ms |
| CPU % | Derived | Delta between samples, null on single snapshot |
| IO read/write bytes, syscall counts | `/proc/[pid]/io` | Optional, may be restricted |
| Thread count | `/proc/[pid]/status` | |
| Open FDs | `/proc/[pid]/fd/` | Optional, may be restricted |
| Context switches (voluntary/involuntary) | `/proc/[pid]/status` | |
| Start time | `/proc/[pid]/stat` field 22 | Used for PID identity verification |

Fields that may be restricted (`io`, `fd`) gracefully degrade to `null` in the output
with a warning to stderr. The snapshot still succeeds.

## Remote Collection via rsdb

pstat uses [rsdb](https://github.com/smohantty/rsdb) as the transport layer for remote
Tizen targets. No daemon or agent needs to be installed on the target beyond `rsdbd`
(which is already there if you use rsdb).

Remote collection is batched into a single round trip per snapshot:

```
pstat -> rsdb agent exec --target <addr> -> sh -c '
  cat /proc/PID/stat; echo ---PSTAT_SEP---
  cat /proc/PID/status; echo ---PSTAT_SEP---
  cat /proc/PID/io; echo ---PSTAT_SEP---
  ...'
```

Each section includes `PSTAT_OK`/`PSTAT_ERR` markers so failures are attributed
to specific files, not garbled into unparseable output.

Process identity is verified using `starttime` from `/proc/[pid]/stat` to prevent
TOCTOU races from PID reuse between discovery and snapshot.

## Usage by Autonomous Agents

pstat is designed to be invoked by AI coding agents (Claude Code, Codex, etc.)
as a structured data source. Key behaviors for agent integration:

### JSON as default for piped output

When stdout is not a TTY, pstat defaults to JSON. Agents get structured data without
specifying `--format json`:

```bash
# Agent invocation - automatically gets JSON
snapshot=$(pstat snapshot --name myapp --target 192.168.0.218)
echo "$snapshot" | jq '.rss'
```

### Structured error output

Errors are emitted as JSON to stderr when output is piped:

```json
{"error":{"code":"process_not_found","message":"name 'myapp'"}}
```

Error codes: `process_not_found`, `target_unreachable`, `permission_denied`,
`parse_error`, `ambiguous_match`, `identity_mismatch`.

### Exit codes

| Code | Meaning |
|------|---------|
| 0 | Success |
| 1 | Process not found |
| 2 | Target unreachable |
| 3 | Permission denied |
| 4 | Parse error |

### NDJSON streaming for sample

`pstat sample` streams one JSON object per line to stdout. The final line is the
summary, tagged with `"type":"summary"`. Agents can consume samples incrementally:

```bash
pstat sample --name myapp --target 192.168.0.218 --interval 1s --count 10 | while read -r line; do
  type=$(echo "$line" | jq -r '.type // "snapshot"')
  if [ "$type" = "summary" ]; then
    echo "RSS trend: $(echo "$line" | jq -r '.rss_trend')"
  else
    echo "RSS: $(echo "$line" | jq '.rss')"
  fi
done
```

### Agent workflow: detect memory leak

```bash
# 1. Snapshot before workload
pstat snapshot --name myapp --target 192.168.0.218 --output /tmp/before.json

# 2. Run workload...

# 3. Snapshot after
pstat snapshot --name myapp --target 192.168.0.218 --output /tmp/after.json

# 4. Diff - check for significant RSS growth
diff_result=$(pstat diff /tmp/before.json /tmp/after.json --format json)
rss_severity=$(echo "$diff_result" | jq -r '.deltas[] | select(.name=="RSS") | .severity')
if [ "$rss_severity" = "Significant" ]; then
  echo "Potential memory leak detected"
fi
```

### Agent workflow: continuous monitoring

```bash
# Sample for 5 minutes, save structured data
pstat sample --name myapp --target 192.168.0.218 \
  --interval 5s --count 60 --output /tmp/monitoring.json

# Parse the trend
trend=$(jq -r '.summary.rss_trend' /tmp/monitoring.json)
peak=$(jq '.summary.vm_peak_max' /tmp/monitoring.json)
echo "RSS trend: $trend, all-time peak: $peak bytes"
```

### Using pstat-core as a library

For Rust agents or tools that want to avoid shelling out:

```rust
use pstat_core::local::LocalCollector;
use pstat_core::remote::RsdbCollector;
use pstat_core::collector::{Collector, ProcessTarget};

// Local snapshot
let collector = LocalCollector;
let snap = collector.snapshot(&ProcessTarget::Name("nginx".into()))?;
println!("RSS: {} bytes", snap.rss);

// Remote snapshot
let collector = RsdbCollector::new("192.168.0.218".into());
let snap = collector.snapshot(&ProcessTarget::Name("myapp".into()))?;
println!("RSS: {} bytes, CPU user: {}ms", snap.rss, snap.cpu_user_ms);
```

## Architecture

```
                    +----------------------------------+
                    |           pstat CLI               |
                    |  (clap, format selection,         |
                    |   SIGINT handling, TTY detection)  |
                    +--------------+-------------------+
                                   |
                    +--------------v-------------------+
                    |         pstat-core (lib)          |
                    |                                   |
                    |  schema.rs     - All types/enums  |
                    |  collector.rs  - Collector trait   |
                    |  proc_parser.rs- Shared parser    |
                    |  diff.rs       - Snapshot compare  |
                    |  report.rs     - Output formatting |
                    |                                   |
                    |  +-----------+------------------+ |
                    |  | local.rs  |  remote.rs       | |
                    |  | std::fs   |  rsdb agent exec | |
                    |  +-----------+------------------+ |
                    +----------------------------------+
```

Both `LocalCollector` and `RsdbCollector` feed raw `/proc` file content to the same
`proc_parser` module. One parser, two I/O layers.

## License

MIT OR Apache-2.0
