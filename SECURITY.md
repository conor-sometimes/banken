# Security policy

banken is maintained by one person, in his spare time, and takes security
seriously because it is a security tool: a bug here can blind a detector or,
worst case, be turned against the host it runs on. Reports are genuinely
welcome and will be read.

## Reporting a vulnerability

Please report privately, not in a public issue:

- Use GitHub's **private vulnerability reporting** — the repository's **Security**
  tab → **Report a vulnerability**. That opens a private thread with the
  maintainer.

Include what you need to: what you found, how to reproduce it, and the impact
as you see it. A proof of concept helps but is not required.

There is **no bug bounty** — this is a personal project, not a company — but
credit in the fix and the release notes is offered gladly to anyone who wants
it.

## What counts

In scope, and most interesting:

- Anything that makes a parser crash, hang, or mis-normalise on crafted log
  input (a way to blind the detector by writing one bad line).
- Any path by which rule or log *content* leads to code execution, a file
  read/write, or a network call it should not (the log4j class of bug).
- A detection that can be trivially evaded, or one that fires on clearly benign
  activity often enough to be useless.

Out of scope: findings that require already being root on the host (banken does
not defend a machine whose root is already owned — no host agent can), and
issues in pinned third-party tools used only for testing (report those upstream).

## Expectations

Best-effort, honestly: there is no SLA. A reporter should expect an
acknowledgement within a week or so, and a fix on a timeline that matches the
severity and the maintainer's available evenings. For something actively
dangerous, say so and it will be prioritised.

## How banken is built to limit this

The repository documents its own defenses so a reviewer can check them: rules
and logs are treated as inert data (no eval, exec, template expansion, XXE, or
ReDoS — see the README's *Security model*, and `TestRuleValuesAreInertData`,
`TestRuleRegexCannotReDoS`, `TestSysmonNoXXE`), every parser is fuzzed, commits
are signed, dependencies and CI actions are pinned, and the whole thing is one
static binary with no kernel component.
