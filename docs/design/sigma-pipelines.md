# Sigma pipelines: logsource routing and field mappings

banken implements the Sigma standard so SigmaHQ rules load and evaluate
unmodified. A rule declares a `logsource:` (category / product / service)
naming the telemetry it was written for; banken ingests several sensors, each
tagging its events with a `Source`. The pipeline is the declarative bridge
between the two.

## Why

Without routing, every rule is evaluated against every event. That is wrong in
two directions:

- A Windows / Sysmon rule (`logsource.product: windows`) could coincidentally
  match a Linux auditd event and fire a false positive.
- A rule scoped to one sensor's raw fields is noise on another's.

pySigma solves this with *processing pipelines* that attach to a backend and
rewrite rules per logsource. banken's pipeline is the same idea, kept small and
data-driven.

## How it works

`internal/sigma/pipeline.yml` is an ordered table. Each entry has:

- `when`: a logsource condition. An omitted key is a wildcard; a set key must
  equal the rule's value (case-insensitive).
- `sources`: the banken `event.Source` tags the rule applies to. An explicit
  empty list means "no live sensor yet" (e.g. macOS): the rule still loads and
  still answers a source-agnostic `banken check`.
- `rename`: field-name aliases (rule field -> banken event field) for this
  logsource.

At compile time (`internal/sigma/load.go`), a rule's logsource is matched
top-to-bottom; the first matching entry sets `Rule.Sources` and applies its
renames. A rule whose logsource matches no entry - or that has no logsource -
is left unrestricted (`Sources == nil`) and runs against every source. banken
never silently drops a rule.

At match time (`Rule.Match` / the prefilter `Matcher`), a rule is skipped for an
event whose `Source` is not in `Rule.Sources`. Two escape hatches keep this
sound and non-disruptive:

- An event with an empty `Source` (an ad-hoc `banken check`, a replay with no
  provenance) always matches, so routing never changes a source-agnostic
  verdict - including the pySigma conformance differential, which feeds
  source-less events.
- A `nil` `Sources` (unrestricted) always matches.

## Shipped routing

| logsource                         | banken sources                              |
| --------------------------------- | ------------------------------------------- |
| `product: windows`                | `sysmon`                                    |
| `product: macos`                  | (none live yet)                             |
| `product: linux` + `service: auditd` | `auditd`, `laurel`, `mimi`, `generic`    |
| `product: linux`                  | `auditd`, `laurel`, `mimi`, `sysmon`, `generic` |
| `category: process_creation`      | `auditd`, `laurel`, `mimi`, `sysmon`, `generic` |

Sysmon-for-Linux events carry `product: linux` semantics, so they are routed by
the `linux` entry - which is why `sysmon` is listed there and a `product: linux`
reverse-shell rule fires on a Sysmon ProcessCreate record.

## Field mappings are identity today, by design

banken's `event.Event` deliberately uses Sigma's own field names (`Image`,
`CommandLine`, `ParentImage`, `TargetFilename`, `User`, `CurrentDirectory`, and
the raw auditd names `type` / `syscall` / `comm` / `exe` / `a0..aN` / `name` in
`Raw` / `Multi`). So for every sensor banken has today, the rename maps are
identity and are shipped empty. The mechanism is in place, declaratively, for
the day a sensor exposes a datum under a name that diverges from the rule's -
then it is a one-line table edit, not a code change. This keeps the design
simple and free of per-rule special-casing.
