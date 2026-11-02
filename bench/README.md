# Benchmarks

The numbers an EDR is judged by, from the spec in
[`docs/design/benchmarking.md`](../docs/design/benchmarking.md). Every latency
number is a distribution -- **p50 / p99 / max, never a mean** -- because one slow
alert matters more than a fast average.

Two layers:

- **`go test -bench`** (`just bench`), the committed micro-benchmarks for the
  prefilter's rule-count scaling. Amortised mean ns/op; `bench/baseline.txt` is
  the reference `bench-compare` diffs against.
- **`banken-bench`** (`bench/cmd/banken-bench`, driven by `bench/run.sh`), the
  category suite. It records every per-operation sample and reports the
  percentiles the spec asks for, and writes raw JSON to `bench/results/`.

## Run it

```sh
# on hokkaido, in the dev shell:
nix develop ~/wbdev#banken --command bash -lc 'bench/run.sh fast'
```

`run.sh fast` writes one JSON per category to `bench/results/`. `PLATFORM=<name>`
labels the matrix row. The heavy categories (`run.sh heavy` lists them) run
inside [`tests/bench.nix`](../tests/bench.nix) on a quiet pinned VM, scheduled by
the manager after a rebuild -- they need a 24h window, a reboot, the live mimi
sensor, a fork bomb or a competitor install.

## Method (what makes the numbers credible)

- Hardware and kernel are pinned per run in the `host` block of every JSON file
  and in the README Performance table. Compare only runs from the same row.
- The matrix runs every bench once per platform (`-platform <distro>`), reusing
  the distro images in `tests/distros/distros.json`: one Run JSON per distro.
- The script and the raw JSON are published together, the same way the ATT&CK
  loop publishes `results.ndjson`.
- Honesty: a file holds only numbers that were measured. A category the current
  environment cannot run is a `"pending"` section with a note saying what it
  needs -- never an invented or estimated number.

## JSON schema (`banken-bench/1`)

```
Run      { schema, tool, generated, platform, host, sections[] }
host     { hostname, os, arch, numCpu, cpu, kernel, goVersion }
Section  { category, status: "measured"|"pending", note, metrics[] }
Metric   { name, unit, stat?, value?, extra{} }
stat     { samples, minNs, p50Ns, p99Ns, maxNs, meanNs, timerOverheadNs }
```

`stat` is a latency distribution; `value` is a scalar (events/sec, bytes, a
count). `timerOverheadNs` is the measured cost of the `time.Now` pair that
brackets each sample -- reported, not subtracted, so a sub-microsecond number
can be read honestly.

## Category -> how it is measured

| Spec category | Subcommand | Runs now? |
| --- | --- | --- |
| Detection latency t3 normalise / t4 match / t5 OCSF+write, e2e | `latency` | yes |
| Detection latency t1 sensor capture / t2 transport | (mimi) | pending: live sensor |
| Throughput (sustained eps) + explicit drop counting | `throughput` | yes (in-process) |
| Backpressure: ring-buffer drops under a fork bomb, burst clear | (mimi) | pending: live sensor |
| Resource cost: RSS+CPU of the daemon | `sample` | yes (short); 24h pending |
| Resource cost under a kernel build, with/without banken | `run.sh kernelbuild` | pending: VM |
| Memory as a function of rule count (211/2k/10k) | `ruleload` | yes |
| Sensor overhead: us/exec, probe detached (baseline) | `forkexec` | yes |
| Sensor overhead: us/exec with the probe attached; real-job slowdown | (mimi) | pending: live sensor |
| Rule scaling: match time per event vs rule count | `rulescale` + `just bench` | yes |
| Rule load + compile time; bytes per rule | `ruleload` | yes |
| Startup: cold start to first finding | `coldstart` | yes |
| Startup: boot to first finding after reboot; backlog replay | `tests/bench.nix` | pending: VM reboot |
| Detection quality: ATT&CK coverage | `tests/attackrange.nix` | (separate harness) |
| Detection quality: false positives/host/day by rule; per-rule eval cost | `tests/bench.nix` | pending: benign corpus |
| Footprint: static stripped binary size; deps + source bytes | `footprint` + `run.sh` | yes |
| Competitor comparison (auditd/Falco/Wazuh/osquery) | `tests/bench.nix` | pending: installs |

`bench/results/` holds the raw JSON from the most recent published run; its
`host` block says which machine and kernel produced it.
