# Performance

The rule count is not supposed to be something you worry about, so matching does **not** scan every
rule against every event. At load time every string literal across every rule
(`|contains`/`|startswith`/`|endswith`/equality) is compiled into one
[Aho-Corasick](https://en.wikipedia.org/wiki/Aho%E2%80%93Corasick_algorithm) automaton. For each
event, one pass per field finds the set of literals present anywhere in it - in time proportional
to the event length, *independent of how many rules exist* - and only the rules that could match
that set get the authoritative per-rule check (an inverted literal->rule index plus a sound
upper-bound test on the rule's condition). Regexp and negation rules that no literal can gate are
kept in a small always-evaluated set.

It is a pure prefilter in front of the unchanged per-rule matcher, never a replacement, so a rule
it skips provably could not have matched (the found-literal set is always a superset of the true
literals). That property is fuzzed: `FuzzMatcherEquivalence` asserts the compiled matcher returns
the exact same verdict as the naive "check every rule" matcher on arbitrary rules and events.

All numbers below were measured, not estimated. The full benchmark suite, its
[spec](design/benchmarking.md) and the raw JSON are in [`bench/`](../bench/); latency is reported
as p50 / p99 / max (never a mean, because one slow alert matters more than a fast average). The
hardware and kernel are pinned, because a number without them has no scale:

| Field | This run |
| --- | --- |
| Host | hokkaido |
| CPU | AMD Ryzen 5 3400G (4C/8T) |
| Kernel | Linux 6.18.59 |
| Go | 1.26.8 |
| Load during run | ~2.5-3.0 (a shared host, not idle) |

**Prefilter scaling** (`go test -bench`, matching one event against a synthetic tree of distinct,
regex-free rules, mean ns/op):

| Rules | Naive (every rule) | Compiled matcher | Compiled allocs/op |
| ---: | ---: | ---: | ---: |
| 100 | 79 us | 3.2 us | 6 |
| 1,000 | 932 us | 4.8 us | 6 |
| 10,000 | 11,900 us | 24.9 us | 6 |

Naive matching grows linearly with the rule count (and so do its allocations: 500 / 5,000 /
50,000); the compiled matcher stays flat enough to carry the whole SigmaHQ Linux set, and its
allocations per event are **constant** regardless of rule count. (Parallelising across events with
a goroutine pool is a later, complementary lever - the matcher is read-only and so trivially
parallel - but the algorithm is what makes rule count cheap.)

**IOC match scaling** (`go test -bench BenchmarkIOCMatch`, matching one event against a feed of N
domain plus N filename/path indicators, on the host in the table above). The bulk IOC path is held
to the same promise as the Sigma prefilter: indicator count is free. A domain indicator resolves by
a label-suffix lookup in an exact map (host, then each parent domain), and a filename/path
indicator by one Aho-Corasick pass over the field - the same literal-set automaton the Sigma
prefilter uses (`internal/acmatch`), built once at load. Neither test is a per-event scan of the
feed, and indicator values are folded to lower case once at load, not per event:

| Indicators (domains + files) | ns/op | B/op | allocs/op |
| ---: | ---: | ---: | ---: |
| 1,000 + 1,000 | 11,834 | 955 | 17 |
| 100,000 + 100,000 | 9,573 | 944 | 17 |

A hundredfold more indicators does not raise the per-event cost (the two rows sit in the same
~10-15 us band, which is the shared host's load noise, not the feed size - repeated runs of each
row span that band), and allocations per event are **constant** at 17, set by the event's fields
and hits, never by the feed. The one-time compile of the automaton and the map is paid at load and
excluded from the loop (a reload builds a fresh set and swaps it in atomically). This replaces the
previous linear scan, which lower-cased every indicator on every event and grew the per-event cost
with the feed.

**Detection latency, staged.** The headline number, broken into stages so a regression shows where
it landed. Measured against the *real* shipped rule tree (not the synthetic regex-free set above),
on the shared host in the table, so these are honest upper bounds - the representative quiet-box
run (lower p99/max) is pending on the pinned VM via `tests/bench.nix`. p50 / p99 / max per stage,
threat event:

| Stage | p50 | p99 | max |
| --- | ---: | ---: | ---: |
| t3 normalise (mimi JSON -> Event) | 47 us | 307 us | 5.3 ms |
| t4 prefilter + rule match | 47 us | 138 us | 696 us |
| t5 OCSF build + write | 22 us | 83 us | 4.6 ms |
| **end to end (t3..t5)** | **134 us** | **699 us** | **19 ms** |

The t4 floor is dominated by the rules the prefilter cannot gate: ~30 of the 40 baseline rules
carry a regexp, which runs on every event in the always-evaluated set. That is the real per-event
cost a deployment pays, and it is why the synthetic (regex-free) prefilter numbers above are a best
case, not the headline. t3 is JSON-heavy (mimi's nested schema is read defensively, field by
field). t1 (sensor capture) and t2 (mimi -> banken transport) need the live sensor and are pending.
One match engine core sustains **~25,000 events/sec**; past that a bounded queue drops, and the
harness counts the drops explicitly (silent loss under load is the classic EDR failure).

**Footprint and startup.** Static stripped binary **7.0 MiB** (7,352,482 bytes). It links **one**
third-party package into the production binary (`gopkg.in/yaml.v3`; 3 transitive modules, ~321 KiB
of third-party source under audit - `rapid` is test-only). Cold start to the first finding on disk:
**p50 12 ms** (12/12 runs fired). Resident memory with the baseline ruleset loaded: **~14 MiB**
(short idle sample; the 24h idle CPU+RSS soak is pending - commercial agents sit at hundreds of
MB). Compiling the rule tree into the matcher costs ~1.3 ms at 40 rules, ~31 ms at 2,000, ~157 ms
at 10,000 (p50), at roughly 4.5 KiB of matcher memory per rule.

End-to-end latency in the one-shot deployment model is the compute above plus at most one timer
interval, which `--watch` or a shorter interval shrinks; so the interval, not the matching, is the
latency knob. The pending categories (24h idle soak, resource cost under a kernel build, sensor
overhead with the probe attached, backpressure under a fork bomb, boot-to-finding after reboot,
false positives per host per day, and the auditd / Falco / Wazuh / osquery peer comparison) are all
wired in the harness and run by the matrix after the next rebuild; see
[`bench/README.md`](../bench/README.md).
