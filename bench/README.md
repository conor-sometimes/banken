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

## Rule-scaling stress (`just stress`)

`just stress` answers the question a buyer asks after the 10k row: *what if I
load every SigmaHQ rule plus a vendor feed?* It pads the shipped tree with
synthetic rules (`benchlib.PadTo`, the same unique-literal shape the prefilter
is built for) up to **hundreds of thousands** and records the curve as the set
scales:

- **matcher compile time** -- building the Aho-Corasick automaton from the rule
  set (`sigma.NewMatcher`), a distribution over a few builds;
- **per-event match latency** -- p50 / p99 / max, the number that matters;
- **sustained single-core throughput** -- events/sec through prefilter + match;
- **the automaton's resident bytes** -- the isolated heap the compiled matcher
  adds, forced-GC on both sides, and bytes/rule from it.

```sh
just stress                         # 100k, 250k, 500k (default)
just stress 100000,200000,400000    # a custom sweep
PLATFORM=rocky-9 just stress        # label the matrix row
```

The curve prints to stderr as it runs; the raw JSON lands in
`bench/results/stress.json` (the `rule-scaling-stress` section, `banken-bench/1`
schema). It is **heavy**: minutes of wall time and multi-GB RSS at 500k rules
(roughly 2 GB of automaton plus the rule objects), so run it on a box with
headroom, not in the fast suite.

## Profiling (`just profile`)

`just profile` profiles the detection hot path -- `BenchmarkDetectionLatency`,
the parse -> prefilter + match pipeline -- and writes CPU and heap/allocation
profiles to an output dir (`bench/profiles` by default, gitignored):

```sh
just profile                      # -> bench/profiles, 3s per sub-benchmark
just profile bench/profiles 10s   # longer run = more CPU samples
```

It emits, into that dir:

| File | What it is |
| --- | --- |
| `cpu.pprof` | CPU profile (raw) |
| `mem.pprof` | heap profile (raw; carries both inuse and alloc views) |
| `detlat.test` | the symbolized test binary `go tool pprof` reads |
| `cpu-top.txt`, `cpu-tree.txt` | CPU hot functions, flat + cumulative, as text |
| `heap-inuse.txt` | live heap by function (`-inuse_space`) |
| `heap-alloc.txt` | total bytes ever allocated by function (`-alloc_space`) |
| `cpu.svg`, `heap-inuse.svg` | call-graph SVGs, **only if graphviz (`dot`) is on PATH** |

### Reading the profiles

- **Flame graph (CPU).** Open the raw profile in pprof's web UI and pick *View ->
  Flame Graph*:

  ```sh
  go tool pprof -http=:8080 bench/profiles/detlat.test bench/profiles/cpu.pprof
  ```

  Each bar is a function; width is time spent in it and everything it called. A
  wide bar near the top is where the CPU goes -- for banken that is the
  Aho-Corasick scan (`internal/sigma`), the JSON parse (`internal/parser`) and,
  under load, the garbage collector.
- **Static SVG (no browser).** If graphviz is present `just profile` already
  wrote `cpu.svg`; otherwise render it on demand:

  ```sh
  nix shell nixpkgs#graphviz -c go tool pprof -svg \
    bench/profiles/detlat.test bench/profiles/cpu.pprof > bench/profiles/cpu.svg
  ```

  It is a weighted call graph: box and edge thickness are cost, so the thick
  path from the benchmark down to a leaf is the hot path. (This is the "SVG via
  `go tool pprof`" the spec names; the interactive flame graph is the same data,
  laid out as stacks.)
- **Heap: inuse vs alloc.** `heap-inuse.txt` is memory *live at the end* -- what
  the daemon holds resident (a leak shows here as a function that keeps growing
  across longer runs). `heap-alloc.txt` is *total bytes ever allocated* -- GC
  pressure, the thing that drives the CPU time GC takes. A function high in
  `alloc` but absent from `inuse` is a churn source (per-event garbage), the
  right target for an allocation cut. Flip either view yourself with:

  ```sh
  go tool pprof -alloc_space -top bench/profiles/detlat.test bench/profiles/mem.pprof
  ```
- **Text first.** `cpu-top.txt` / `heap-*.txt` are enough to read the hot path
  from a terminal with no graphviz and no browser; the SVG and flame graph are
  for when you need to see the call structure, not just the leaves.

## Per-commit history (`history.ndjson`)

`baseline.txt` is the benchstat reference for a delta; `history.ndjson` is the longitudinal log,
one JSON line per measured commit, so performance is a time series across commits. Produced by
`bench/cmd/benchhist` from `go test -bench -benchmem` output:

```
{"commit":"<sha>","date":"<RFC 3339 UTC>","goos":"linux","goarch":"amd64","cpu":"<model>",
 "count":6,"binaryBytes":7438498,
 "benchmarks":{"internal/sigma.BenchmarkMatcher1000":{"ns/op":1700,"B/op":364,"allocs/op":4}, ...}}
```

Each benchmark is the MEDIAN of its `count` repetitions per unit. `binaryBytes` is the stripped
release binary (`just build`). A `-dirty` commit suffix means the tree had uncommitted changes.
Rows are only comparable within the same `goos`/`goarch`/`cpu`, exactly as for `baseline.txt`;
a shared CI runner row and a hokkaido row are different series.

- `just bench-history` runs the benchmarks and appends a line for the current commit. Commit the
  result from a machine you trust (hokkaido). The first line is the seed: measured on hokkaido
  (AMD Ryzen 5 3400G, linux/amd64) on 2026-11-02 at 856c896, before this tooling landed (the
  tooling does not touch product code, so the numbers are that commit's).
- The CI `bench` job appends the same line on every push/PR and uploads the file in the
  `benchmarks` artifact (CI does not commit back to the repo).

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
| Rule scaling at extreme scale (100k-500k): compile, match, throughput, RSS | `stress` / `just stress` | yes (heavy) |
| Profiling: CPU + heap/alloc of the detection hot path | `just profile` | yes |
| Startup: cold start to first finding | `coldstart` | yes |
| Startup: boot to first finding after reboot; backlog replay | `tests/bench.nix` | pending: VM reboot |
| Detection quality: ATT&CK coverage | `tests/attackrange.nix` | (separate harness) |
| Detection quality: false positives/host/day by rule; per-rule eval cost | `tests/bench.nix` | pending: benign corpus |
| Footprint: static stripped binary size; deps + source bytes | `footprint` + `run.sh` | yes |
| Competitor comparison (auditd/Falco/Wazuh/osquery) | `tests/bench.nix` | pending: installs |

`bench/results/` holds the raw JSON from the most recent published run; its
`host` block says which machine and kernel produced it.
