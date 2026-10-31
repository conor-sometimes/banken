# Architecture

banken is one Go binary that, on each run, reads the host's logs since a saved point, matches them
against rules, and emits alerts. It is one-shot by design — a systemd timer owns the schedule — with
an optional `--watch` loop for hosts without a timer.

```
 log source            parser            event            matcher                 sinks
┌───────────┐      ┌────────────┐    ┌──────────┐    ┌──────────────────┐    ┌──────────────┐
│ auditd /  │ ───► │ normalise  │ ─► │ one flat │ ─► │ Sigma rules +    │ ─► │ journal /    │
│ Laurel    │      │ to Event   │    │  Event   │    │ IOC set          │    │ jsonl /      │
└───────────┘      └────────────┘    └──────────┘    └──────────────────┘    │ webhook      │
      ▲                                                        │              └──────────────┘
   cursor (byte offset per file, persisted between runs)       └─► Dispatcher ─► (Responder hook)
```

## The one event

Every parser produces the same `event.Event` (`internal/event`): `Image`, `CommandLine`,
`ParentImage`, `TargetFilename`, `User`, `CurrentDirectory`, a `Time`, a `Source` tag, and a `Raw`
map for anything extra. The field names deliberately match the Sigma field names, so the matcher
looks a field up by its rule name with no translation table. Every field is best-effort: a parser
never fails an event because one field was missing — a dropped event is a dropped detection.

## Parsers (`internal/parser`)

One parser per log source, all behind a single `Parser` interface and a registry keyed by type
name. Implemented: **auditd** (raw multi-line `SYSCALL`/`EXECVE`/`PATH`/`CWD`/`PROCTITLE` records
stitched into one event, hex-decoded argv) and **Laurel** (auditd→JSON, one event per line).
Stubbed behind the same interface: **journald**, **syslog**. A new source is a new parser and
nothing else changes. Parsers eat untrusted bytes, so they are the most heavily fuzzed part of the
tree (see the README's Testing section).

## Rules and the matcher (`internal/sigma`, `internal/ioc`)

Rules are [Sigma](https://github.com/SigmaHQ/sigma) YAML; banken evaluates a subset (see
[writing-rules.md](writing-rules.md)). Bulk indicator feeds are plain `ioc/*.txt` lists matched by
set membership — the fast path for thousands of flat values.

Matching does **not** loop every rule over every event. `NewMatcher` compiles every string literal
across every rule into one Aho-Corasick automaton (`ahocorasick.go`) plus an inverted
literal→rule index. For an event, one pass per field finds the literals present anywhere in it
(cost independent of the rule count), and only rules that *could* match — judged by a sound
per-rule upper bound where a `not` subtree counts as true — get the authoritative `Rule.Match`.

It is a **prefilter in front of the unchanged `Rule.Match`, never a replacement**: a skipped rule
provably could not have matched, so `Rule.Match` stays the source of truth and the clever part can
only ever save work, never change a verdict. `FuzzMatcherEquivalence` asserts the two agree on
millions of random rule+event pairs. This is the one piece of non-obvious machinery in the codebase,
and it earns its place only because the rule count is meant to grow to the full SigmaHQ set; it is
isolated behind `Matcher` so the rest of the code never sees it.

## Cursor (`internal/engine/cursor.go`)

Per input file, the cursor stores the byte offset read up to, persisted as JSON so each timer run
reads only what is new. It is atomic (write-temp-then-rename) and **never fatal**: a missing, empty
or corrupt cursor recovers to a fresh start rather than halting (at worst one log is re-read, a
self-healing duplicate). A file shorter than the stored offset (rotated/truncated) is re-read from
zero so no events are missed.

## Engine (`internal/engine`)

The engine wires parser → matcher → dispatcher and holds no I/O of its own beyond an `io.Reader`,
so it is trivially testable with in-memory inputs. Both the parse and each event's match run under a
panic guard: a crafted record takes out at most that one source or event, never the whole scan
(blinding the detector with one bad line is the attack this prevents).

## Alerts (`internal/alert`)

Every hit flows through one `Dispatcher` to any combination of sinks — **journal** (syslog),
**jsonl** (one file per day, retention by file delete), **webhook** (generic/Slack/Discord/ntfy;
the URL is read from a file path, never inline). Because everything funnels through one dispatch
point, future **response actions** (kill, quarantine) slot in behind the `Responder` hook without a
redesign — and they are operator policy keyed off a rule tag, never embedded in a rule.

## Config and zero-fiddle (`internal/config`, `main.go`)

Config is YAML with flag overrides on top; the NixOS module renders the same YAML from its options.
With no config and no flags, banken loads its **embedded baseline ruleset** (compiled into the
binary with `//go:embed`, so detection works with nothing on disk), **auto-detects** the host log
source (Laurel then raw auditd), and alerts to the journal — the zero-fiddle default. On-disk rule
trees are loaded on top of the baseline and win on a name clash.
