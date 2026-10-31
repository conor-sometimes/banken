# Sigma conformance harness (banken's "Test262")

A browser proves itself on web-platform-tests; a JS engine on Test262. banken
implements the Sigma *standard*, so its conformance is measured against the
reference implementation, **pySigma**.

`conformance.py` is a differential test. pySigma is the reference *parser*:
`.parse()` returns a fully-expanded condition tree (identifiers inlined, every
modifier and value-list turned into AND/OR/NOT over field/keyword leaves). The
harness adds a small, faithful *evaluator* over that tree, synthesises an event
that should fire each rule (and uses the empty event as the negative), and
checks that **banken's verdict agrees with the pySigma-derived evaluator**. A
disagreement is a conformance bug — in banken, or (rarely) in the evaluator.

## Result (SigmaHQ `rules/linux` at release `r2026-07-01`, 210 rules)

- **Eval differential: 182/182 checks agree (100%), zero divergences.**
- process_creation subset: 128/128 (100%).

Checks are skipped — counted, never hidden — when they are out of this
harness's scope, not because banken failed: a field banken doesn't model yet
(raw-auditd `type`/`a0`/…), a value the generator can't synthesise (regexp,
cidr, number), or a condition shape (`or`/`of`) the generator doesn't cover.
Those are harness limits and a roadmap (improve generation; model more fields),
not banken divergences.

This complements [`tools/sigmacov`](../tools/sigmacov) (which measures the
*load* rate — 210/210 = 100%): sigmacov says the rules *compile*, this says
they *evaluate the same as the reference*.

## Run

```sh
git clone --depth 1 https://github.com/SigmaHQ/sigma /tmp/sigma
go build -o /tmp/banken .                 # from the repo root
uv run conformance.py /tmp/sigma/rules/linux /tmp/banken
```
