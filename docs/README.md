# banken documentation

Start with the [project README](../README.md) for the overview. These pages go deeper:

- **[Architecture](architecture.md)** — how a scan works end to end: the log sources, the one
  normalised event, the rule matcher and its Aho-Corasick prefilter, the cursor, and the alert
  sinks. Read this to understand or extend the internals.
- **[Writing rules](writing-rules.md)** — the exact Sigma subset banken evaluates, with worked
  examples, plus IOC lists and how the embedded baseline and your own rules combine. Read this to
  add detections.
- **[Deployment](deployment.md)** — getting it running: the zero-config default, the systemd
  timer, the NixOS module, the log source it reads, and the sandbox it runs in. Read this to
  install it.

Security model (why a root daemon that ingests rules is not a trojan) lives in the
[README's Security model section](../README.md#security-model); the threat model is short enough to
keep in one place.

Everything here describes the current code. If a page and the code disagree, the code wins — please
open an issue.
