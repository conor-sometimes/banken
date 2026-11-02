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

A rule's directory is just organisation - banken loads every `*.yml`/`*.yaml` under the tree (except
`ioc/`). Put a behavioural rule under the tactic it detects, a family signature under
`malware/<family>/`, and flat indicator feeds in `ioc/`.

The embedded baseline is compiled into the binary, so detection works with nothing on disk. Any
on-disk tree (`-rules DIR` or `rules:` in the config) is loaded on top; a rule whose filename
matches a baseline rule's **replaces** it, so you extend or override the defaults without losing them.
Every such baseline override is logged at load and recorded in the refresh status file (see below), so
a rule that shadows a baseline detection is never silent; `refresh.protectBaseline` forbids it outright.

## Sigma: the supported subset

A rule is standard [Sigma](https://github.com/SigmaHQ/sigma): a `detection:` block of named
*selections* plus a `condition`. banken evaluates this subset (anything outside it is a load-time
error naming the file and reason - a malformed rule is never silently dropped):

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
| `Field\|cidr: 10.0.0.0/8` | the field's IP is within the CIDR range (needs a network source to populate the field) |
| `Field\|...\|all: [a, b]` | matches *every* listed value, not just one |

**Keyword selections.** A selection whose value is a bare list of strings (not field mappings) is a
*keyword* match: it fires if any string appears in any of the event's text fields - e.g.
`keywords:\n  - /etc/shadow\n  - id_rsa`. A single scalar works too, and a modifier-only key makes
it stricter: `'|all':\n  - truncate\n  - ' -s'` requires every string to appear (each in some field).
Wildcards inside a keyword are substring (unanchored) matches.

A value may be a scalar or a list; a list is OR (any) unless `|all` is added. String comparisons are
case-insensitive (Sigma's default); a regexp honours its own casing.

**Wildcards.** In an *unmodified* value, `*` matches any run of characters and `?` matches exactly
one, matched against the whole field - so `CommandLine: '*whoami*'` is contains, `'sudo *'` is
startswith, `'*/python3'` is endswith, and `'f?o'` matches `fXo`. Escape a literal with a backslash
(`\*`, `\?`, `\\`). A `Field: null` is rejected at load (it would never match) rather than silently
becoming a dead rule. (`logsource` routing and Sigma's null = "field absent" are not yet
implemented - see the roadmap.)

**Selections and conditions.** A selection is a mapping of `field: matcher` (AND across its fields),
or a list of such mappings (OR across them). The `condition` combines selection names with
`and` / `or` / `not`, parentheses, and the quantifiers `N of them` / `all of them` / `1 of sel*`.

### Examples

A behaviour - a shell opening a reverse shell (two selections, AND):

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

For bulk indicators - thousands of filenames, IPs, or domains - a Sigma file each would be absurd.
Put one value per line in `rules/ioc/*.txt` (blank lines and `#` comments ignored):

```
# rules/ioc/evil-c2.txt
192.0.2.44
c2.evil.test
/usr/share/.hidden/miner
```

banken classifies each by shape - IP (token match), domain (exact or dot-suffix, so `evil.test`
matches `c2.evil.test` but not `notevil.test`), otherwise a filename/path (substring/basename) - and
checks them against the event's fields. Which field an indicator hit is recorded on the alert.
(IP lookups are O(1); domain/path matching is being folded into the same matcher the rules use.) File, process and command-line indicators work against the audit sources
today; hash and network indicators arrive with the eBPF / network sources.

## Testing a rule

Two ways:

- **`banken check`** - the fast path. Describe one event and see which rules fire, no log needed:

  ```sh
  banken check -image /usr/bin/cat 'cat /etc/shadow'          # -> credential_file_read
  banken check -json '{"image":"/bin/bash","commandLine":"...dev/tcp..."}'
  ```

  It's faithful to the rule logic - if a rule needs `TargetFilename`, set `-target`; a command line
  alone won't satisfy it. Perfect for tuning ("does my change still fire?") and purple-teaming.

- **A fixture** for regression: a normalised event JSON under `tests/fixtures/`.
  `NAME.expect-<rule>.json` must fire that rule; `NAME.expect-none.json` must fire nothing.
  `go test ./...` runs them (and the coverage gate requires every rule to have one), so a rule ships
  with proof it does - and doesn't - fire.

## Refreshing rules at runtime (no redeploy)

Rules do not have to be baked into the binary or the config. A directory listed under `refreshDirs:`
is read live: a running daemon rebuilds its whole rule set on a reload, and a one-shot run reads it on
its next scan. The loop:

```sh
banken check /var/lib/banken-rules   # preflight: compile the tree, non-zero exit on any bad rule
banken reload                        # SIGHUP the daemon -> validate-all-then-swap (no restart)
banken status                        # confirm: last refresh, outcome, rules loaded, failures
```

A refresh is safe by construction: a bad rule file is reported and skipped (the good rules load), and
a whole-set failure -- an empty tree, or one over the resource-guard caps (`refresh.maxRules`,
`refresh.maxPatternBytes`) -- keeps the previously-good set rather than blinding the host. The full
fleet workflow (a git rules repo, the puller, provenance) is the [new-threat
scenario](scenarios/new-threat.md), designed in [rule-refresh](design/rule-refresh.md).
