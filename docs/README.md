# banken documentation

Start with the [project README](../README.md) for the overview. These pages go deeper.

- **[Architecture](architecture.md)** - how a scan works end to end. Covers the log sources, the
  single normalised event, the rule matcher, the cursor, and the alert sinks. Read this to
  understand or extend the internals.
- **[Writing rules](writing-rules.md)** - the exact Sigma subset banken evaluates, with worked
  examples. Also covers indicator lists and how the built-in baseline combines with your own rules.
  Read this to add detections.
- **[Deployment](deployment.md)** - getting it running: the zero-config default, the systemd timer,
  the NixOS module, the log it reads, and the sandbox it runs in. Read this to install it.
- **[Log sources](log-sources.md)** - how banken stays extensible across operating systems. Covers
  the single parser interface, the generic-JSONL adapter, and the per-OS source roadmap. Read this
  to add a source.
- **[Security model](security-model.md)** - why a root daemon that ingests rules is not a trojan.
  Rules and logs are inert data, there is no kernel component, and the guarantee is layered. Read
  this for the threat model.
- **[Performance](performance.md)** - the prefilter, the measured scaling and latency numbers, and
  the binary and memory footprint. Read this for the benchmarks.
- **[Testing](testing.md)** - the test surface: table tests, never-die contracts, the fuzz
  campaign, the emulation VM test, and CI. Read this for how claims are gated.

Task-shaped walkthroughs live under `scenarios/`.

- **[New threat detected](scenarios/new-threat.md)** - write a rule for a threat you just read
  about and have the whole fleet detecting it within minutes, with no binary redeploy. Walks the
  runtime rule-refresh loop end to end: `refreshDirs`, the puller, `banken reload`, `banken status`.
  The design behind it is [rule-refresh](design/rule-refresh.md).

Everything here describes the current code. If a page and the code disagree, the code wins - please
open an issue.
