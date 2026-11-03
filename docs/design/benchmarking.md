# Benchmarking: the numbers an EDR is judged by

A performance spec (work-claude), grouped by the question each number answers.
EDR here means endpoint detection and response. Starred (*) items are what a
buyer or reviewer asks first.

One method rule runs throughout. Every benchmark runs inside the live distro
matrix (tests/distros), so each platform gets its own row. The hardware and
kernel are pinned. Results are published as a script plus raw JSON, the same way
the ATT&CK loop is.

## Detection latency (the headline) *

Time from the event in the kernel to the finding written. It is broken into
stages, so a regression shows where it landed. Report p50, p99 and max, never
the mean. One slow alert matters more than a fast average.

```
exec() in kernel
  |-- sensor capture (tracepoint -> ring buffer)      t1  *
  |-- transport (mimi -> banken, JSON over the pipe)  t2
  |-- normalise to Event                              t3
  |-- prefilter + rule match                          t4  (already measured: just bench)
  |-- OCSF build + write to journal/webhook           t5
finding on disk / on the wire
end to end = t1..t5                                       *
```

## Throughput and backpressure

- Events per second sustained before the ring buffer drops anything. Count drops
  explicitly. A sensor that silently loses events under a fork bomb is the
  classic EDR failure.
- Burst behaviour. Take a compile job or `find /` at full speed. Measure how
  long until the queue clears and whether any event was lost.

## Resource cost on the host *

- Idle CPU and RSS over 24 hours on a quiet box. This is the number people
  compare to the commercial agents, which sit at hundreds of MB.
- CPU and RSS under a known workload (a kernel build), with and without banken
  running.
- Memory as a function of rule count, at 211 rules, 2,000 and 10,000. Flat or
  linear tells the story.

## Overhead the sensor adds to the workload *

- Added latency per exec, probe attached versus detached. Measure microseconds
  per exec with a tight fork-exec loop.
- Wall time of a real job with and without mimi. Use a kernel build, an npm
  install and a test suite. The honest number is the percentage slowdown.

## Scaling with rules

- Match time per event versus rule count (already measured). Add rule load time,
  compile time, and hot reload time if supported.
- Memory per rule for the automaton.
- Stress the rule set past the shipped tree into the hundreds of thousands
  (every SigmaHQ rule plus a vendor feed). Track four curves as the count
  climbs:
  - compile time
  - per-event match latency (p50/p99/max)
  - sustained throughput
  - resident bytes

  `banken-bench stress` / `just stress` records it. Synthetic rules
  (benchlib.PadTo) pad the real tree, so the automaton is exercised the way a
  real large set would be. This is where a near-flat per-event cost bends. The
  number is measured, not modelled.

## Profiling

This shows where the CPU and the allocations go. A regression in the numbers
above then has a cause, not just a symptom. `just profile` profiles the
detection hot path (parse -> prefilter + match) and writes:

- a CPU profile, read as a flame graph (`go tool pprof -http`) or a call-graph
  SVG (`go tool pprof -svg`, graphviz), plus the text top for a terminal
- a heap profile in both views: `-inuse_space` (what the daemon holds resident,
  where a leak grows) and `-alloc_space` (total churn, what drives GC's share of
  the CPU)

The raw `.pprof` files are the artifact. They are published the same way as the
JSON. See `bench/README.md` ("Profiling") for how to read them.

## Startup and recovery

- Cold start to first event captured, and boot to first finding after a reboot.
  This matters for the "install in one line" pitch.
- Time to replay a backlog after banken was stopped for an hour while the box
  kept logging.

## Detection quality, as numbers that move

- ATT&CK techniques on merit (already measured: tests/attackrange.nix).
- False positives per host per day on a baseline workload, by rule. The one
  everyone asked for.
- Per-rule evaluation cost, so you can show which rules are expensive and
  whether the prefilter catches them.

## Footprint

- Binary size, static, stripped. One number, one line in the README.
- Transitive dependency count and total source bytes under audit. cargo-deny
  already runs, so this is nearly free.

## Method points that make the numbers credible

- Pin the hardware and kernel in the README table. Same VM image each run.
- Compare against something people know. The peers are auditd plus ausearch,
  Falco, Wazuh agent and osquery (Sysmon on Windows later). A number without a
  peer has no scale.
- Run every benchmark inside the distro matrix, so each platform gets its own
  row. The harness already boots the images.
- Publish the script, hyperfine where it fits, and the raw JSON, the same way
  the ATT&CK loop is published.
