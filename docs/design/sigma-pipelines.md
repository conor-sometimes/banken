# Sigma pipelines: logsource routing and field mappings

banken implements the Sigma standard so SigmaHQ rules load and evaluate
unmodified. A rule declares a `logsource:` (its category, product, or service).
That names the telemetry the rule was written for. banken ingests several
sensors. Each one tags its events with a `Source`. The pipeline is the bridge
between the two.

## Why

Without routing, every rule is evaluated against every event. That is wrong in
two ways:

- A Windows / Sysmon rule (`logsource.product: windows`) could coincidentally
  match a Linux auditd event and fire a false positive.
- A rule scoped to one sensor's raw fields is noise on another's.

pySigma solves this with *processing pipelines*. They attach to a backend and
rewrite rules per logsource. banken's pipeline is the same idea, kept small and
data-driven.

## How it works

`internal/sigma/pipeline.yml` is an ordered table. Each entry has:

- `when`: a logsource condition. An omitted key is a wildcard. A set key must
  equal the rule's value (case-insensitive).
- `sources`: the banken `event.Source` tags the rule applies to. An explicit
  empty list means there is no live sensor yet (e.g. macOS). The rule still
  loads, and still answers a source-agnostic `banken check`.
- `rename`: field-name aliases (rule field -> banken event field) for this
  logsource.

At compile time (`internal/sigma/load.go`), a rule's logsource is matched top to
bottom. The first matching entry sets `Rule.Sources` and applies its renames. A
rule may match no entry, or have no logsource at all. It is then left
unrestricted (`Sources == nil`) and runs against every source. banken never
silently drops a rule.

At match time (`Rule.Match` and the prefilter `Matcher`), a rule is skipped for
an event whose `Source` is not in `Rule.Sources`. Two escape hatches keep this
safe:

- An event with an empty `Source` always matches. That covers an ad-hoc `banken
  check` or a replay with no provenance. So routing never changes a
  source-agnostic verdict. This includes the pySigma conformance differential,
  which feeds source-less events.
- A `nil` `Sources` (unrestricted) always matches.

## Shipped routing

| logsource                         | banken sources                              |
| --------------------------------- | ------------------------------------------- |
| `product: windows`                | `sysmon`                                    |
| `product: macos`                  | (none live yet)                             |
| `product: linux` + `service: auditd` | `auditd`, `laurel`, `mimi`, `generic`    |
| `product: linux`                  | `auditd`, `laurel`, `mimi`, `sysmon`, `generic` |
| `category: process_creation`      | `auditd`, `laurel`, `mimi`, `sysmon`, `generic` |

Sysmon-for-Linux events carry `product: linux` semantics. So they are routed by
the `linux` entry. That is why `sysmon` is listed there, and why a
`product: linux` reverse-shell rule fires on a Sysmon ProcessCreate record.

## Field mappings are identity today, by design

banken's `event.Event` deliberately uses Sigma's own field names:

- the typed fields `Image`, `CommandLine`, `ParentImage`, `TargetFilename`,
  `User`, `CurrentDirectory`
- the raw auditd names `type` / `syscall` / `comm` / `exe` / `a0..aN` / `name`,
  held in `Raw` / `Multi`

So for every sensor banken has today, the rename maps are identity and ship
empty. The mechanism is still in place, declaratively. The day a sensor exposes
a datum under a name that diverges from the rule's, it becomes a one-line table
edit, not a code change. This keeps the design simple and free of per-rule
special-casing.
