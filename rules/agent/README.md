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
- `agent_ssh_outbound` — the agent *ran* ssh/scp/sshpass or git-over-ssh (it has no host to reach).
- `agent_exfil_to_code_host` — pushed to a gist/release/new repo, published or uploaded (T1567.001).
- `agent_proxy_bypass` — unset/overrode the egress proxy, `--noproxy`, proxychains.
- `agent_git_config_persistence` — a git config or hook that runs code or steals credentials.
- `agent_self_config_modification` — wrote its own harness config: settings, hooks, skills, CLAUDE.md.
- `agent_decode` — the agent decoded encoded data (base64/base32/xxd/uudecode/openssl -d): unpacking
  an obfuscated payload (T1140). `deobfuscate_and_run` catches a decode piped into a shell host-wide.
- `agent_ai_enabled_exfil` - the agent ran a bulk transfer to external storage (rclone/aws s3/gsutil/
  curl --upload-file ...): **T1700 AI-Enabled Exfiltration** (new in ATT&CK v20). Owns object-storage
  and generic file-upload; `agent_exfil_to_code_host` owns the git/gist/release channel.
- `agent_impair_autonomous_defenses` - the agent stopped/killed/rewrote a security or EDR tool
  (Falcon, osquery, Wazuh, auditd, ClamAV, mdatp ...): **T1685.007 Impair Autonomous Defenses** (new in
  ATT&CK v20). The account-scoped framing of `tamper_banken` / the `disable_*` rules.
- `honeytoken_access` - any process opened a planted decoy credential (host-wide, critical).

## ATT&CK v20 AI techniques - what banken can and cannot see

ATT&CK v20 (Oct 2026) added the first AI/agent techniques. banken keys on **host process telemetry**,
so it detects an AI technique only when that technique has a host-observable footprint:

- **T1700 AI-Enabled Exfiltration** - detected (`agent_ai_enabled_exfil`). The injected prompt is
  invisible, but the agent *executing* the transfer is a process event, which is exactly what the
  technique's analytics (AN2079/AN2080) key on.
- **T1685.007 Impair Autonomous Defenses** - detected (`agent_impair_autonomous_defenses`). banken
  can't read the "fake system message" in the malware, but it sees the agent taking the defense tool
  down, which is the realised effect.
- **T1698 Indirect / T1699 Direct Prompt Injection** - **not** detected as such, and no rule pretends
  to. The injection lives in LLM-conversation content (a web page, a document, the prompt box), which
  is invisible to a host EDR by design - the harness transcript is the source, not banken. What banken
  *can* catch is the injection's downstream **effect** (the agent then exfiltrating, impairing a
  defense, reaching the network, touching a secret), which the rules above and the rest of this set
  already cover. Writing a "prompt injection detector" over process telemetry would be a false claim.
- **T1608.007 AI Result Poisoning** - out of scope (a PRE/resource-development technique about seeding
  web content attackers control; nothing executes on the host).

More ideas, ranked and grounded in banken's telemetry, are in
[docs/design/agentic-detection-ideas.md](../../docs/design/agentic-detection-ideas.md).

## Design notes

- **Scope, don't guess.** A rule here fires on a named account doing something it has no business
  doing, never on a heuristic about "looking like an AI". It is auditable and has a near-zero false
  positive rate by construction.
- **Upstream candidate.** Once this set is solid it is a candidate to contribute to SigmaHQ as a new
  category (agent / service-account abuse), which would be among the first detections written *for*
  AI agents. Until then it lives here and ships in banken's baseline.
