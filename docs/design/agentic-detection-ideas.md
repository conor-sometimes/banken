# Agentic detection - rule roadmap

Ideas for `rules/agent/`, the detection class for autonomous-agent misbehaviour
(see `rules/agent/README.md`). Every idea is grounded in banken's real
telemetry. Each event carries:

- `Image`, `CommandLine`, `ParentImage`, `TargetFilename`
- `User`, `CurrentDirectory`, `ProcessId`, `ParentProcessId`
- whatever a parser puts in `Raw`

Every idea is account-scoped: it keys on a `User` list of agent accounts. So a
behaviour that is noise on a human login is clean signal from the agent.

Status as of 2026-10-31. Three detections have shipped: `agent_ssh_access`, and
host-wide `credential_search` and `history_tamper`.

These come from a Fable brainstorm, filtered to what banken can actually see.
Each entry below names, in order:

- what it catches
- its key telemetry
- the MITRE ATT&CK technique
- a false-positive (FP) note

## Build first (in order)

1. **agent_self_config_modification** - the agent rewrites its own harness
   config. This is the purest prompt-injection persistence: the next session
   re-reads the file as policy. Targets:
   - `~/.claude/settings*.json` or `.claude.json`
   - a hook or an MCP server
   - `CLAUDE.md` or a skill

   Needs a `-w …/.claude/settings.json -p wa` watch, plus siblings, with an
   exec fallback on the repo-level `.claude/settings.json` / `.mcp.json`.
   **Exclude** auto-memory writes (`projects/*/memory/*`). No clean ATT&CK
   technique fits (roughly T1546 hooks, T1098 permission-widening). A false
   positive is possible when the harness writes `settings.local.json` on an
   "always allow" click. That is near-zero on headless or worker runs.

2. **agent_exfil_to_code_host** - a push to somewhere other than the task repo.
   The shapes to catch:
   - `gh gist/release/repo create`
   - `git remote add` / `push <url>` / `--mirror`
   - `twine/npm/cargo publish`
   - `curl -F @file api.github.com`
   - `nix copy --to`

   Exec only. ATT&CK **T1567.001 (exfil to code repo)** is an exact fit, and
   SigmaHQ has nothing on Linux. This is the strongest upstream candidate.

3. **agent_proxy_bypass** and **agent_ssh_outbound** - two related detections.
   agent_proxy_bypass catches unsetting or overriding the proxy:
   - `--noproxy '*'`
   - `env -u https_proxy`
   - `NO_PROXY=*`
   - `git -c http.proxy=`
   - `proxychains`

   agent_ssh_outbound catches any `ssh/scp/sftp/sshpass`, or `git clone
   git@…`. Both are exec only. ssh_outbound is about 5 lines and has zero false
   positives for a coding agent. ATT&CK T1090 / T1562, and T1021.004.

4. **agent_honeytoken_access** - anything opens a planted credential file:
   - `~/.aws/credentials`
   - `~/.kube/config`
   - `/srv/backup/prod-db.sql.gz`
   - `~/notes/passwords.txt`

   Zero false positives by construction. It is also the only *proactive* catch:
   it sees an attacker-in-session before they act. Needs one `-w <path> -p r -k
   honeytoken` watch per file. Keep the files **not** under `~/repos`, or
   ripgrep would read them. Severity `critical`. ATT&CK T1552.001 / D3FEND decoy
   file.

5. **agent_git_config_persistence** - git config that runs code or steals
   credentials:
   - `core.hooksPath` / `fsmonitor` / `sshCommand` / `pager`
   - `credential.helper`
   - `include.path`
   - `filter.*.clean/smudge`
   - `alias.*` with `!`
   - writing `.git/hooks/*`

   This fires on *Conor's* next pull. Exec only. ATT&CK T1546 / T1574 / T1556.
   Exclude the false positives `pre-commit install` and husky. It is
   **genuinely new to SigmaHQ** and useful beyond agents.

Then **agent_destructive_git_or_fs** - the harm that happens most. It catches:

- force-push, `reflog expire`, `filter-repo`
- `rm -rf` a repo
- `git clean -fdx`
- `DROP DATABASE`

Carve out `worker/` branches.

## The rest, by theme (one-liners)

### Self-tampering / escape

- `agent_tamper_wall_or_proxy` - iptables -F, stop agent-proxy, edit /etc/audit.
- `agent_namespace_or_privilege_probe` - nsenter/unshare/chroot, `podman
  --privileged -v /:/host`, chmod u+s, setcap.
- `agent_unlisted_host_fetch` - a network client names a host not on the egress
  allow-list. Mirror of the proxy's refusal.

### Exfil / collection

- `agent_bulk_archive_staging` - tar/zip/rsync of `~`, `/home`, `/etc`, or
  another user's dir -> /tmp or stdout.
- `agent_secret_in_argv` - ghp_/sk-ant-/AKIA/xox tokens, `Authorization:
  Bearer`, or `sshpass -p` on the command line. Note that the alert itself
  needs redaction.
- `agent_reads_own_api_credential` - `~/.claude/.credentials.json` read by
  something other than the harness, `printenv ANTHROPIC`, `/proc/<pid>/environ`.

### Data-access drift

- `agent_outside_own_home` - reads/writes/cds into another home, /root, or a
  system config dir.
- `agent_process_attach_or_proc_dump` - gdb/strace `-p`,
  `/proc/<pid>/mem|maps|environ`.

### Persistence / supply-chain

- `agent_package_source_redirect` - `pip config set index-url`, `npm config set
  registry`, edit `~/.npmrc`/`nix.conf` substituters.
- `agent_path_shadow_binary` - writes `~/.local/bin/git` etc., a tool name in a
  writable PATH dir.
- `agent_account_manipulation` - useradd/usermod/passwd/chsh. All fail unpriv,
  so the attempt is the tell.

### Covering tracks

- `agent_history_or_transcript_wipe` - history plus its own
  `~/.claude/projects/*.jsonl` transcripts, agent-job logs.
- `agent_timestomp_or_immutable` - `touch -d/-t/-r`, `chattr +i`.

### Suspicious automation / discovery

- `agent_encoded_or_obfuscated_command` - base64/hex/eval-to-shell, beyond
  `pipe_to_shell`'s curl|sh.
- `agent_inline_interpreter_network` - `python -c`/`node -e` opening
  sockets/HTTP.
- `agent_offensive_tool_via_nix` - `nix run nixpkgs#nmap`, `pip install
  mitmproxy`. The `/nix/store/*-nmap-*/bin` image-path trick names the package.
- `agent_network_scan` - nmap/`nc -z`/RFC1918 targets.
- `agent_security_tool_discovery` - auditctl -l, `systemctl status banken`,
  `sudo -l`, read the containment nix. **Noisy on hokkaido because verify.sh
  does this; low/informational.**
- `agent_detach_from_session` - nohup/setsid/disown/`screen -dm` outside
  agent-job. Highest FP here, agents love nohup; `low`.
- `agent_tunnel_or_listener` - ssh -R/-L/-D, socat LISTEN, `http.server` on
  0.0.0.0, ngrok/cloudflared/chisel.

## Two parser enablers (do alongside - small change, big reach)

- **Stash auditd `key` and `success` into `Event.Raw`.** Then `Key: honeytoken`
  matches a watch key directly. And every "attempt" rule above can carry two
  levels: tried to write /etc/shadow with `success=no`, versus did. Neither
  parser fills Raw today. This is the highest-leverage telemetry upgrade.
- **Verify once on hokkaido** that Claude Code's Bash tool runs `bash -c '<whole
  command>'`, so shell builtins appear in the exec's `CommandLine`:
  - `unset http_proxy`
  - `history -c`
  - `export HISTFILE=/dev/null`

  Several rules lean on this. One `agent-audit` lookup confirms it. If the
  harness ever uses a persistent shell, those branches go blind.

## Great ideas banken CANNOT see today (and what each needs)

- **Memory or instruction poisoning** - an injected imperative written into
  `CLAUDE.md` / `MEMORY.md` / a skill. banken sees the *write* (idea 1), not the
  *content*. Needs a content hook: a post-write diff scan, or a harness
  `PostToolUse` hook.
- **Script-file payloads** - `python exfil.py` is opaque, only the filename
  shows. Needs file-content hashing or a write-time body log. One partial catch
  is worth adding: `agent_exec_from_tmp`, an interpreter running
  `/tmp|/dev/shm|/var/tmp/*`.
- **Proxy refusals and kernel-wall drops** - the best egress signal. But it is
  journal-only and invisible to auditd. Needs the journald parser (a stub
  today), or a shim tailing `journalctl -u agent-proxy-* -o json` into the
  `generic` source.
- **Temporal correlation** - the attacker-in-session is mostly a *burst*, and
  banken's matcher is per-event. Two examples: a discovery burst `id; uname -a;
  cat /etc/passwd; ps aux` in 60s, or "honeytoken read THEN network client" in 5
  min. This is the biggest structural gap. Sigma v2 correlation rules express
  it, or a stateful recent-events-by-uid window in the engine.
- **Supply-chain postinstall** - a chain like `npm install` -> `node-gyp` ->
  `bash -c curl …`. Needs the grandparent or `ParentCommandLine`. Laurel can
  enrich it into `Raw`; raw auditd cannot.
- **LLM-traffic content** - what prompt drove it. Invisible by design: the
  harness transcript is the source, not banken.
