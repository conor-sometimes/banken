# Standards and integrations to support (banken + mimi)

Grouped by purpose. (*) = do first. Status marked where known as of 2026-11-01.

TOP FOUR THIS MONTH: OTLP export (DONE), Navigator layer export (DONE), signed releases with
provenance, YARA sidecar. Each is a day or two; each is a word a hiring manager recognises on sight.

## Output and transport

- OpenTelemetry OTLP log exporter. (*) DONE (internal/alert/otlp.go). OCSF is the schema, OTLP the
  pipe; any collector takes findings with no glue.
- OCSF telemetry classes, not just findings: Process Activity (1007), File System Activity (1001),
  Network Activity (4001). Ships raw events to a lake, not only alerts.
- Elastic Common Schema (ECS) as a second output mapping. Half the SOCs run Elastic.
- Syslog RFC 5424 and CEF. Ten lines each; lets any legacy SIEM ingest.
- Prometheus / OpenMetrics endpoint on the daemon: events/sec, ring-buffer drops, rule-eval p99,
  RSS. The same numbers as the benchmark table, live; ties the benchmarks to operations.

## Rules and intelligence in

- Sigma v2 correlation rules (event_count, value_count, temporal). Almost no OSS engine implements
  them; run the pySigma differential on them too.
- Sigma pipelines / field mappings per logsource, so SigmaHQ rules load unmodified per sensor. DONE
  (internal/sigma/pipeline.{yml,go}; docs/design/sigma-pipelines.md). Declarative logsource ->
  sensor-Source routing; field renames supported (identity for today's sensors, by design).
- YARA via yara-x. (*) Needed the day quarantine lands ("what is this file"). Rust sidecar, not CGO.
- STIX 2.1 bundles over TAXII 2.1 for indicators (hashes, IPs, domains); MISP export as a 2nd input.
- ATT&CK Navigator layer JSON export of coverage. (*) DONE (tools/attack-layer). Recognisable heatmap.
- MITRE D3FEND mapping of banken's own controls (what each response action counters). Docs, cheap.

## Response (when it lands)

- OpenC2 (OASIS) as the command language for kill / quarantine / isolate. The standard way to drive
  an actuator; an orchestrator can call banken without a bespoke API.
- Process: cgroup freeze before kill so the analyst can inspect; kill by pid + start-time (no reuse).
- Network isolation: nftables table banken owns and rolls back atomically; allow-list the SIEM/webhook.
- Quarantine: move + chmod 000 + sidecar JSON (sha256, rule, time, original path) so restore works.

## Telemetry sources

- Linux: auditd raw and Laurel (DONE), eBPF via mimi (DONE, PoC), Sysmon for Linux (same XML shape
  as Windows Sysmon; half the Windows source for free), fanotify for file events (non-eBPF fallback).
- Windows: ETW providers (Kernel-Process/Network/File/Registry/Image), Sysmon event log, Windows
  Event Log channels Sigma targets (Security 4688, PowerShell 4104).
- macOS: Endpoint Security framework (ES_EVENT_TYPE_NOTIFY_EXEC etc.), Unified Logging fallback.
- mimi: CO-RE with BTF (DONE) so one probe binary runs on every kernel.

## Trust in the artefact

- Signed releases: Sigstore cosign + SLSA provenance via GitHub artifact attestations. (*)
- SBOM per release, CycloneDX or SPDX (cargo-deny / cargo-cyclonedx; syft for the Go side).
- OpenSSF Scorecard badge (pinned actions, signed commits, fuzzing, branch protection: mostly true).
- Reproducible build via Nix; publish the hash and the command that reproduces it.
- SECURITY.md with a disclosure policy and a PGP/age key; signed tags.
- Packaging signed per platform: deb/rpm repos with a signing key, Homebrew tap (mac), MSI
  Authenticode or winget manifest (Windows).

## Visibility and comparison

- EDR Telemetry Project categories (github.com/tsale/EDR-Telemetry): map banken's captured event
  types to its matrix, then ask to be listed. The field's standard "what does this agent see" compare.
- Atomic Red Team (DONE) plus CALDERA adversary profiles for chained emulation, scored the same way.
- Compliance mapping in docs: which NIST 800-53 (SI-4, AU-*), CIS Controls v8 (8, 13) and PCI DSS
  (10, 11) requirements banken evidences. One table, large credibility for small effort.

## Additional candidates (capability research, 2026-11-02)

A fresh sweep of the current landscape for a Go host EDR (Sigma + IOCs over Linux telemetry;
OCSF/ECS/OTLP out), picking items NOT already above. Facts web-checked 2026-11-02. (*) = seeded as a
Taskwarrior task (project as noted, tag +capability-research); the 8-char UUID is given.

### Worth doing

- DeTT&CT (rabobank-cdc, GPL-3.0, v1.4.x). (*) 26de46bc, project:banken.coverage.attack. Score
  banken's telemetry VISIBILITY and detection coverage against ATT&CK's ~50 data-source categories --
  the recognised blue-team way to answer "what can this agent even see". It is a different artifact
  from the Navigator coverage layer (which shows which rules exist) and the natural complement to the
  EDR Telemetry Project mapping already listed. Its companion Dettectinator reads detections from a
  SIEM/EDR to fill the YAML, so banken's attack.* rule tags can auto-populate the techniques file.
  Effort: ~1 day (generate the techniques-admin YAML from rule tags; the data-source YAML is partly
  manual scoring).

- OTRF Security Datasets / Mordor (OTRF, MIT). (*) 8c2f322e, project:banken.testing. Replay their
  pre-recorded Linux attack telemetry (JSON events mapped to Sigma/Atomic/MITRE CAR, and crucially
  carrying the benign events that co-occur with each attack) through banken's existing generic JSONL
  parser, scoring rules against real labeled known-bad data in CI with no KVM. Complements the live
  Atomic Red Team range: fast, deterministic, runs anywhere. Effort: ~1 day (a shape adapter from
  their event JSON to event.Event, plus a CI job).

- Tetragon (Cilium) / Tracee (Aqua) as sources. (*) f50850bc, project:banken.sources. Both are widely
  deployed eBPF runtime sensors with documented JSON event exports (process lifecycle, exec, k8s
  identity). A thin parser maps their exec JSON onto event.Event, so an operator already running one
  gets banken detections with no new probe -- the same additive-sensor shape as mimi and Sysmon.
  Tetragon's JSON export (export-stdout, with rotation/rate-limit/allow-deny filters) is stable and
  well documented; Tracee emits JSON events similarly. Effort: ~1-2 days per sensor.

### Considered, not seeded (for honesty)

- OpenTelemetry security-event semantic conventions. banken already exports OTLP, but OTel's event
  model (the event.name namespacing) and any security-specific convention are still marked
  Experimental as of 2026-11, so aligning field names to it now would chase a moving target. Revisit
  when it stabilises; low effort then.
- Kubernetes API-server audit log as a source. Credible and on-theme for the agentic/container story,
  but a scope step beyond host EDR (cluster control-plane events, not host syscalls). Park until the
  agent-detection niche pulls for it.
- OpenVEX / CycloneDX VEX. Adjacent to the SBOM/SLSA line already listed, but it is supply-chain
  vuln-exploitability metadata, not runtime detection -- out of banken's lane.
- Falco rules / Falco as a source. Subsumed by the Tetragon/Tracee adapter above (same generic-JSONL
  intake), so no separate task.
