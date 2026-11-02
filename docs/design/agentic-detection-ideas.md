# Agentic detection - rule roadmap

Ideas for `rules/agent/` (the detection class for autonomous-agent misbehaviour; see
`rules/agent/README.md`). Grounded in banken's real telemetry: per-event `Image`, `CommandLine`,
`ParentImage`, `TargetFilename`, `User`, `CurrentDirectory`, `ProcessId`, `ParentProcessId`, plus
whatever a parser puts in `Raw`. Every idea is account-scoped (a `User` list of agent accounts), so a
behaviour that is noise on a human login is clean signal from the agent. Status 2026-10-31: shipped so
far are `agent_ssh_access` and (host-wide) `credential_search`, `history_tamper`.

From a Fable brainstorm, filtered to what banken can actually see. Each entry: what it catches · key
telemetry · ATT&CK · FP note.

## Build first (in order)
1. **agent_self_config_modification** - the agent rewrites its own harness config: `~/.claude/settings*.json`,
   `.claude.json`, a hook, an MCP server, `CLAUDE.md`, a skill. The purest prompt-injection persistence
   (next session re-reads it as policy). Needs a `-w …/.claude/settings.json -p wa` watch (+ siblings);
   exec fallback on repo-level `.claude/settings.json`/`.mcp.json`. **Exclude** auto-memory writes
   (`projects/*/memory/*`). No clean ATT&CK (≈T1546 hooks, T1098 permission-widening). FP: the harness
   writes `settings.local.json` on an "always allow" click - near-zero on headless/worker runs.
2. **agent_exfil_to_code_host** - a push to somewhere other than the task repo: `gh gist/release/repo create`,
   `git remote add`/`push <url>`/`--mirror`, `twine/npm/cargo publish`, `curl -F @file api.github.com`,
   `nix copy --to`. Exec only. **T1567.001 (exfil to code repo)** - exact fit, SigmaHQ has nothing on Linux.
   Strongest upstream candidate.
3. **agent_proxy_bypass** + **agent_ssh_outbound** - unsetting/overriding the proxy (`--noproxy '*'`,
   `env -u https_proxy`, `NO_PROXY=*`, `git -c http.proxy=`, `proxychains`), and any `ssh/scp/sftp/sshpass`
   or `git clone git@…`. Exec only; ssh_outbound is ~5 lines, zero FP for a coding agent. T1090/T1562, T1021.004.
4. **agent_honeytoken_access** - anything opens a planted credential file (`~/.aws/credentials`,
   `~/.kube/config`, `/srv/backup/prod-db.sql.gz`, `~/notes/passwords.txt`). Zero-FP by construction, and the
   only *proactive* catch (an attacker-in-session before they act). Needs one `-w <path> -p r -k honeytoken`
   per file; **not** under `~/repos` (ripgrep would read it). `critical`. T1552.001 / D3FEND decoy file.
5. **agent_git_config_persistence** - git config that runs code or steals creds: `core.hooksPath`/`fsmonitor`/
   `sshCommand`/`pager`, `credential.helper`, `include.path`, `filter.*.clean/smudge`, `alias.*` with `!`,
   or writing `.git/hooks/*`. Fires on *Conor's* next pull. Exec only. T1546/T1574/T1556. FP: `pre-commit install`,
   husky - exclude. **Genuinely new to SigmaHQ**, useful beyond agents.

Then **agent_destructive_git_or_fs** (force-push / `reflog expire` / `filter-repo` / `rm -rf` a repo / `git clean -fdx` / `DROP DATABASE`) - the harm that happens most; carve out `worker/` branches.

## The rest, by theme (one-liners)
**Self-tampering / escape:** `agent_tamper_wall_or_proxy` (iptables -F, stop agent-proxy, edit /etc/audit) ·
`agent_namespace_or_privilege_probe` (nsenter/unshare/chroot, `podman --privileged -v /:/host`, chmod u+s, setcap) ·
`agent_unlisted_host_fetch` (a network client names a host not on the egress allow-list - mirror of the proxy's refusal).

**Exfil / collection:** `agent_bulk_archive_staging` (tar/zip/rsync of `~`, `/home`, `/etc`, another user's dir → /tmp or stdout) ·
`agent_secret_in_argv` (ghp_/sk-ant-/AKIA/xox tokens, `Authorization: Bearer`, `sshpass -p` on the command line -
note the alert itself needs redaction) · `agent_reads_own_api_credential` (`~/.claude/.credentials.json` read by
something other than the harness, `printenv ANTHROPIC`, `/proc/<pid>/environ`).

**Data-access drift:** `agent_outside_own_home` (reads/writes/cds into another home, /root, a system config dir) ·
`agent_process_attach_or_proc_dump` (gdb/strace `-p`, `/proc/<pid>/mem|maps|environ`).

**Persistence / supply-chain:** `agent_package_source_redirect` (`pip config set index-url`, `npm config set registry`,
edit `~/.npmrc`/`nix.conf` substituters) · `agent_path_shadow_binary` (writes `~/.local/bin/git` etc. - a tool name in a
writable PATH dir) · `agent_account_manipulation` (useradd/usermod/passwd/chsh - all fail unpriv, the attempt is the tell).

**Covering tracks:** `agent_history_or_transcript_wipe` (history + its own `~/.claude/projects/*.jsonl` transcripts,
agent-job logs) · `agent_timestomp_or_immutable` (`touch -d/-t/-r`, `chattr +i`).

**Suspicious automation / discovery:** `agent_encoded_or_obfuscated_command` (base64/hex/eval-to-shell, beyond
`pipe_to_shell`'s curl|sh) · `agent_inline_interpreter_network` (`python -c`/`node -e` opening sockets/HTTP) ·
`agent_offensive_tool_via_nix` (`nix run nixpkgs#nmap`, `pip install mitmproxy` - the `/nix/store/*-nmap-*/bin`
image-path trick names the package) · `agent_network_scan` (nmap/`nc -z`/RFC1918 targets) ·
`agent_security_tool_discovery` (auditctl -l, `systemctl status banken`, `sudo -l`, read the containment nix - **noisy on
hokkaido because verify.sh does this; low/informational**) · `agent_detach_from_session` (nohup/setsid/disown/`screen -dm`
outside agent-job - highest FP here, agents love nohup; `low`) · `agent_tunnel_or_listener` (ssh -R/-L/-D, socat LISTEN,
`http.server` on 0.0.0.0, ngrok/cloudflared/chisel).

## Two parser enablers (do alongside - small change, big reach)
- **Stash auditd `key` and `success` into `Event.Raw`.** Then `Key: honeytoken` matches a watch key directly, and every
  "attempt" rule above can carry two levels (tried to write /etc/shadow with `success=no` vs did). Neither parser fills
  Raw today; this is the highest-leverage telemetry upgrade.
- **Verify once on hokkaido** that Claude Code's Bash tool runs `bash -c '<whole command>'`, so shell builtins
  (`unset http_proxy`, `history -c`, `export HISTFILE=/dev/null`) appear in the exec's `CommandLine`. Several rules lean
  on this; one `agent-audit` lookup confirms it. If the harness ever uses a persistent shell, those branches go blind.

## Great ideas banken CANNOT see today (and what each needs)
- **Memory/instruction poisoning** (an injected imperative written into `CLAUDE.md`/`MEMORY.md`/a skill): banken sees the
  *write* (idea 1), not the *content*. Needs a content hook (a post-write diff scan, or a harness `PostToolUse` hook).
- **Script-file payloads** (`python exfil.py` is opaque - only the filename shows): needs file-content hashing or a
  write-time body log. Partial catch worth adding: `agent_exec_from_tmp` (interpreter running `/tmp|/dev/shm|/var/tmp/*`).
- **Proxy refusals / kernel-wall drops** - the best egress signal, but journal-only, invisible to auditd. Needs the
  journald parser (a stub today) or a shim tailing `journalctl -u agent-proxy-* -o json` into the `generic` source.
- **Temporal correlation** (a discovery burst `id; uname -a; cat /etc/passwd; ps aux` in 60s; "honeytoken read THEN
  network client" in 5 min) - the attacker-in-session is mostly a *burst*, and banken's matcher is per-event. Biggest
  structural gap; Sigma v2 correlation rules express it, or a stateful recent-events-by-uid window in the engine.
- **Supply-chain postinstall** (`npm install` → `node-gyp` → `bash -c curl …`): needs the grandparent or
  `ParentCommandLine`; Laurel can enrich it into `Raw`, raw auditd cannot.
- **LLM-traffic content** (what prompt drove it): invisible by design - the harness transcript is the source, not banken.
