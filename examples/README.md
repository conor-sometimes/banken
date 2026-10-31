# Example rules

A capability showcase: each file under `rules/` demonstrates one feature of the Sigma subset banken
evaluates, with a comment saying what it shows. They double as a learning resource — copy one and
adapt it. See [../docs/writing-rules.md](../docs/writing-rules.md) for the full reference.

These are **not** loaded automatically. banken's live baseline is the tree embedded in the binary
(the top-level `rules/`); this `examples/` tree is reference material. To run them against a log:

```sh
banken -rules examples/rules -source laurel:/path/to/audit.log
```

| File | Capability shown |
| --- | --- |
| `contains_list_and_selections.yml` | a list value = OR; two named selections = AND |
| `all_modifier.yml` | `\|contains\|all` — every value must be present |
| `regex.yml` | `\|re` — an RE2 regular expression |
| `not_allowlist.yml` | `and not` allow-list carve-out (the standard FP tune-out) |
| `quantifier.yml` | `N of them` — combine several weak signals |
| `multi_field_equals.yml` | several fields AND'd in one selection; bare value = equals |
| `wildcard.yml` | Sigma `*`/`?` wildcards in an unmodified value |
| `rules/ioc/sample-indicators.txt` | a bulk IOC feed (IP / domain / path), one value per line |

A compile test (`examples_test.go`) loads this whole tree on every `go test`, so an example that
stops compiling fails CI — the showcase can't drift from what the engine accepts.

Sigma `*`/`?` wildcards work in an unmodified value (`CommandLine: '*whoami*'`), matched
case-insensitively against the whole field; `\*` / `\?` are literal. A `Field: null` is rejected at
load (it would never match) rather than silently doing nothing.
