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
- Sigma pipelines / field mappings per logsource, so SigmaHQ rules load unmodified per sensor.
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
