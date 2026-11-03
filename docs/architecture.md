# Architecture

banken is one Go binary. On each run it reads the host's logs since a saved point, matches them
against rules, and emits alerts. It is one-shot by design: a systemd timer owns the schedule. For
hosts without a timer, an optional `--watch` loop keeps it running.

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

Every parser produces the same `event.Event` (`internal/event`). Its fields are:

- `Image`, `CommandLine`, `ParentImage`
- `TargetFilename`, `User`, `CurrentDirectory`
- a `Time` and a `Source` tag
- a `Raw` map for anything extra

The field names deliberately match the Sigma field names. So the matcher looks a field up by its
rule name, with no translation table. Every field is best-effort. A parser never fails an event
because one field was missing - a dropped event is a dropped detection.

## Parsers (`internal/parser`)

One parser per log source. All sit behind a single `Parser` interface and a registry keyed by type
name.

Two are implemented:

- **auditd** - raw multi-line `SYSCALL`/`EXECVE`/`PATH`/`CWD`/`PROCTITLE` records stitched into one
  event, with hex-decoded argv.
- **Laurel** - auditd converted to JSON, one event per line.

Two more are stubbed behind the same interface: **journald** and **syslog**. A new source is a new
parser and nothing else changes. Parsers eat untrusted bytes, so they are the most heavily fuzzed
part of the tree (see the README's Testing section).

## Rules and the matcher (`internal/sigma`, `internal/ioc`)

Rules are [Sigma](https://github.com/SigmaHQ/sigma) YAML. banken evaluates a subset (see
[writing-rules.md](writing-rules.md)). Bulk indicator feeds are plain `ioc/*.txt` lists - the bulk
path for thousands of flat values. IPs match by exact set; domains and paths are being folded into
the rule matcher.

Matching does **not** loop every rule over every event. `NewMatcher` compiles every string literal
across every rule into one Aho-Corasick automaton (`ahocorasick.go`) - a classic multi-string search
that finds all literals in one pass. It also builds an inverted literal-to-rule index. For an event,
one pass per field finds the literals present anywhere in it, at a cost independent of the rule
count. Only rules that *could* match then get the authoritative `Rule.Match`. Whether a rule could
match is judged by a sound per-rule upper bound, where a `not` subtree counts as true.

This is a **prefilter in front of the unchanged `Rule.Match`, never a replacement**. A skipped rule
provably could not have matched. So `Rule.Match` stays the source of truth, and the prefilter can
only ever save work, never change a verdict. `FuzzMatcherEquivalence` asserts the two agree on
millions of random rule-and-event pairs. This is the one piece of non-obvious machinery in the
codebase. It earns its place only because the rule count is meant to grow to the full SigmaHQ set,
and it is isolated behind `Matcher` so the rest of the code never sees it.

## Cursor (`internal/engine/cursor.go`)

For each input file, the cursor stores the byte offset read up to. It is persisted as JSON, so each
timer run reads only what is new. Writes are atomic (write-temp-then-rename).

The cursor is **never fatal**. A missing, empty or corrupt cursor recovers to a fresh start rather
than halting. At worst one log is re-read, a self-healing duplicate. A file shorter than the stored
offset (rotated or truncated) is re-read from zero, so no events are missed.

## Engine (`internal/engine`)

The engine wires parser to matcher to dispatcher. It holds no I/O of its own beyond an `io.Reader`,
so it is trivially testable with in-memory inputs. Both the parse and each event's match run under a
panic guard. A crafted record takes out at most that one source or event, never the whole scan.
Blinding the detector with one bad line is the attack this prevents.

## Alerts (`internal/alert`)

Every hit flows through one `Dispatcher` to any combination of sinks:

- **journal** (syslog)
- **jsonl** - one file per day, retention by file delete
- **webhook** - generic, Slack, Discord or ntfy; the URL is read from a file path, never inline

Because everything funnels through one dispatch point, future **response actions** (kill,
quarantine) slot in behind the `Responder` hook without a redesign. Those actions are operator
policy keyed off a rule tag, never embedded in a rule.

## Config and zero-fiddle (`internal/config`, `main.go`)

Config is YAML with flag overrides on top. The NixOS module renders the same YAML from its options.

With no config and no flags, banken runs its zero-fiddle default:

- it loads its **embedded baseline ruleset**, compiled into the binary with `//go:embed`, so
  detection works with nothing on disk;
- it **auto-detects** the host log source (Laurel, then raw auditd);
- it alerts to the journal.

On-disk rule trees are loaded on top of the baseline and win on a name clash.
