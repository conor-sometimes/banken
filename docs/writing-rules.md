# Writing rules

banken detects with two things: **Sigma rules** (behaviour) and **IOC lists** (bulk indicators).
Both live in a rule tree; the binary ships an embedded baseline tree, and your own trees load on top.

## The rule tree

```
rules/
  credential-access/   persistence/   execution/   command-and-control/   ...   # Sigma, by ATT&CK tactic
  malware/<family>/                                                              # family-specific Sigma
  ioc/*.txt                                                                      # bulk indicator lists
```

A rule's directory is just organisation — banken loads every `*.yml`/`*.yaml` under the tree (except
`ioc/`). Put a behavioural rule under the tactic it detects, a family signature under
`malware/<family>/`, and flat indicator feeds in `ioc/`.

The embedded baseline is compiled into the binary, so detection works with nothing on disk. Any
on-disk tree (`-rules DIR` or `rules:` in the config) is loaded on top; a rule whose filename
matches a baseline rule's **replaces** it, so you extend or override the defaults without losing them.

## Sigma: the supported subset

A rule is standard [Sigma](https://github.com/SigmaHQ/sigma): a `detection:` block of named
*selections* plus a `condition`. banken evaluates this subset (anything outside it is a load-time
error naming the file and reason — a malformed rule is never silently dropped):

**Fields** (they map to the normalised event): `Image`, `CommandLine`, `ParentImage`,
`TargetFilename`, `User`, `CurrentDirectory`, and anything a parser put in `Raw`.

**Field modifiers:**

| Form | Matches when the field… |
| --- | --- |
| `Field: value` | equals value (case-insensitive) |
| `Field\|contains: value` | contains value |
| `Field\|startswith: value` | starts with value |
| `Field\|endswith: value` | ends with value |
| `Field\|re: pattern` | matches the RE2 regexp (case per the pattern) |
| `Field\|...\|all: [a, b]` | matches *every* listed value, not just one |

A value may be a scalar or a list; a list is OR (any) unless `|all` is added. String comparisons are
case-insensitive (Sigma's default); a regexp honours its own casing.

**Selections and conditions.** A selection is a mapping of `field: matcher` (AND across its fields),
or a list of such mappings (OR across them). The `condition` combines selection names with
`and` / `or` / `not`, parentheses, and the quantifiers `N of them` / `all of them` / `1 of sel*`.

### Examples

A behaviour — a shell opening a reverse shell (two selections, AND):

```yaml
title: Reverse shell spawned
id: reverse_shell
level: critical
detection:
  shell:
    Image|endswith: [/bash, /sh, /dash]
  net:
    CommandLine|contains: ['/dev/tcp/', 'nc -e', 'ncat --exec']
  condition: shell and net
```

An allow-list carve-out, using `not`:

```yaml
title: curl to an unexpected host
detection:
  curl:
    CommandLine|contains: curl
  allowed:
    CommandLine|contains: 'https://updates.internal/'
  condition: curl and not allowed
```

Several weak signals together, using a quantifier:

```yaml
detection:
  dl:   { CommandLine|contains: wget }
  exec: { CommandLine|contains: chmod }
  run:  { CommandLine|contains: '+x' }
  condition: 2 of them
```

> Note: shell built-ins and redirection (`>`, `|`) do not spawn a process, so they produce no
> `execve` and won't appear in `CommandLine`. Detect those via the file they touch
> (`TargetFilename`) instead.

## IOC lists

For bulk indicators — thousands of filenames, IPs, or domains — a Sigma file each would be absurd.
Put one value per line in `rules/ioc/*.txt` (blank lines and `#` comments ignored):

```
# rules/ioc/evil-c2.txt
192.0.2.44
c2.evil.test
/usr/share/.hidden/miner
```

banken classifies each by shape — IP (token match), domain (exact or dot-suffix, so `evil.test`
matches `c2.evil.test` but not `notevil.test`), otherwise a filename/path (substring/basename) — and
checks them against the event's fields. Which field an indicator hit is recorded on the alert.
(IP lookups are O(1); domain/path matching is being folded into the same matcher the rules use.) File, process and command-line indicators work against the audit sources
today; hash and network indicators arrive with the eBPF / network sources.

## Testing a rule

Add a fixture: a normalised event JSON under `tests/fixtures/`. `NAME.expect-<rule>.json` must fire
that rule; `NAME.expect-none.json` must fire nothing. `go test ./...` runs them, so a rule ships
with proof it does (and doesn't) fire. A `banken check`/repl fast path for one-off
command/log-line checks is on the roadmap.
