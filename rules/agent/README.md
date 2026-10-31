# Agentic AI detection rules

Detections written for the behaviour of an autonomous AI agent (a coding agent like Claude Code,
a CI/build agent) running under its own account. This is a rule class **SigmaHQ does not cover**:
its rules target classic threats and catch an agent only incidentally (a reverse shell is a reverse
shell whoever spawns it). These rules instead ask a question only the agent's *identity* makes
meaningful — "should this account be doing this at all?" — which is how you detect an agent that has
been prompt-injected, has gone off its task, or is being driven by an attacker who got into its
session.

The mechanism is **account scoping**: each rule names the agent accounts in a `User` selection, so a
behaviour that is noise on a human login (reading `~/.ssh/config`, running `sudo`, reaching the
network) is a clean signal when *the agent* does it. Edit the `User` list to match your accounts;
the companion [nixos-agent-containment](https://github.com/conor-sometimes/nixos-agent-containment)
gives each agent its own uid and audits it, which is where the account names come from.

## Rules here

- `agent_ssh_access` — an agent account touched an SSH file (private key, authorized_keys, config,
  known_hosts): theft, a backdoor, or lateral-movement recon.

## Design notes

- **Scope, don't guess.** A rule here fires on a named account doing something it has no business
  doing, never on a heuristic about "looking like an AI". It is auditable and has a near-zero false
  positive rate by construction.
- **Upstream candidate.** Once this set is solid it is a candidate to contribute to SigmaHQ as a new
  category (agent / service-account abuse), which would be among the first detections written *for*
  AI agents. Until then it lives here and ships in banken's baseline.
