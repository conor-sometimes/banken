# banken documentation

Start with the [project README](../README.md) for the overview. These pages go deeper:

- **[Architecture](architecture.md)** - how a scan works end to end: the log sources, the one
  normalised event, the rule matcher and its Aho-Corasick prefilter, the cursor, and the alert
  sinks. Read this to understand or extend the internals.
- **[Writing rules](writing-rules.md)** - the exact Sigma subset banken evaluates, with worked
  examples, plus IOC lists and how the embedded baseline and your own rules combine. Read this to
  add detections.
- **[Deployment](deployment.md)** - getting it running: the zero-config default, the systemd
  timer, the NixOS module, the log source it reads, and the sandbox it runs in. Read this to
  install it.
- **[Log sources](log-sources.md)** - how banken stays extensible across OSes: the one-interface
  seam, the generic-JSONL adapter, and the per-OS (Linux/macOS/Windows) source roadmap. Read this to
  add a source.
- **[Security model](security-model.md)** - why a root daemon that ingests rules is not a trojan:
  rules and logs as inert data, no kernel component, the layered guarantee. Read this for the
  threat model.
- **[Performance](performance.md)** - the Aho-Corasick prefilter, the measured prefilter-scaling
  and staged-latency numbers, and the binary/memory footprint. Read this for the benchmarks.
- **[Testing](testing.md)** - the test surface: table tests, never-die contracts, the fuzz
  campaign, the emulation VM test, and CI. Read this for how claims are gated.

Everything here describes the current code. If a page and the code disagree, the code wins - please
open an issue.
