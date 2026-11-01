# Benchmarking: the numbers an EDR is judged by

A performance spec (work-claude), grouped by the question each number answers. Starred (*) items are
what a buyer or reviewer asks first. The method rule throughout: every benchmark runs inside the
live distro matrix (tests/distros) so each platform gets its own row, with the hardware and kernel
pinned, published as a script plus raw JSON the same way the ATT&CK loop is.

## Detection latency (the headline) *

Time from the event in the kernel to the finding written, broken into stages so a regression shows
where it landed. Report p50, p99 and max, never the mean: one slow alert matters more than a fast
average.

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

- Events per second sustained before the ring buffer drops anything. Count drops explicitly: a
  sensor that silently loses events under a fork bomb is the classic EDR failure.
- Burst behaviour: a compile job or `find /` at full speed, how long until the queue clears and
  whether any event was lost.

## Resource cost on the host *

- Idle CPU and RSS over 24 hours on a quiet box. This is the number people compare to the commercial
  agents, which sit at hundreds of MB.
- CPU and RSS under a known workload (a kernel build), with and without banken running.
- Memory as a function of rule count: 211 rules, 2,000, 10,000. Flat or linear tells the story.

## Overhead the sensor adds to the workload *

- Added latency per exec with the probe attached versus detached. Microseconds per exec, measured
  with a tight fork-exec loop.
- Wall time of a real job with and without mimi: kernel build, npm install, a test suite. The honest
  number is the percentage slowdown.

## Scaling with rules

- Match time per event versus rule count (already measured). Add rule load and compile time, and hot
  reload time if supported.
- Memory per rule for the automaton.

## Startup and recovery

- Cold start to first event captured, and boot to first finding after a reboot. Matters for the
  "install in one line" pitch.
- Time to replay a backlog after banken was stopped for an hour while the box kept logging.

## Detection quality, as numbers that move

- ATT&CK techniques on merit (already measured: tests/attackrange.nix).
- False positives per host per day on a baseline workload, by rule. The one everyone asked for.
- Per-rule evaluation cost, so you can show which rules are expensive and whether the prefilter
  catches them.

## Footprint

- Binary size, static, stripped. One number, one line in the README.
- Transitive dependency count and total source bytes under audit. cargo-deny already runs, so this
  is nearly free.

## Method points that make the numbers credible

- Pin the hardware and kernel in the README table. Same VM image each run.
- Compare against something people know: auditd plus ausearch, Falco, Wazuh agent, osquery (Sysmon
  on Windows later). A number without a peer has no scale.
- Run every benchmark inside the distro matrix so each platform gets its own row: the harness
  already boots the images.
- Publish the script, hyperfine where it fits, and the raw JSON, the same way the ATT&CK loop is
  published.
