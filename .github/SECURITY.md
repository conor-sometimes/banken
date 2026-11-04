# Security policy

banken is a security tool, so a bug here is serious. It can blind a detector. Worst
case, it can be turned against the host it runs on. banken is maintained by one
person in his spare time. He takes security seriously, and reports are genuinely
welcome. They will be read.

## Reporting a vulnerability

Please report privately, not in a public issue.

Use GitHub's **private vulnerability reporting**. Go to the repository's **Security**
tab, then **Report a vulnerability**. That opens a private thread with the maintainer.

Include what you need to:

- what you found
- how to reproduce it
- the impact as you see it

A proof of concept helps but is not required.

There is **no bug bounty** - this is a personal project, not a company. But credit in
the fix and the release notes is offered gladly to anyone who wants it.

## What counts

In scope, and most interesting:

- Anything that makes a parser crash, hang, or mis-normalise on crafted log input.
  That is a way to blind the detector by writing one bad line.
- Any path by which rule or log *content* leads to code execution, a file
  read/write, or a network call it should not. This is the log4j class of bug.
- A detection that can be trivially evaded. Or one that fires on clearly benign
  activity often enough to be useless.

Out of scope:

- Findings that require already being root on the host. banken does not defend a
  machine whose root is already owned - no host agent can.
- Issues in pinned third-party tools used only for testing. Report those upstream.

## Expectations

Best-effort, and honestly there is no SLA. Expect an acknowledgement within a week or
so. A fix comes on a timeline that matches the severity and the maintainer's available
evenings. For something actively dangerous, say so and it will be prioritised.

## How banken is built to limit this

The repository documents its own defenses so a reviewer can check them:

- Rules and logs are inert data. None of the following happens:
  - eval
  - exec
  - template expansion
  - XXE
  - ReDoS

  This is proven by `TestRuleValuesAreInertData`, `TestRuleRegexCannotReDoS`, and
  `TestSysmonNoXXE`. See the README's *Security model*.
- Every parser is fuzzed.
- Commits are signed.
- Dependencies and CI actions are pinned.
- The whole thing is one static binary with no kernel component.
