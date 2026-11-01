# Own rule → emulation script map

Every one of banken's **own** Sigma rules (under `rules/`, each `status: experimental` with a
`falsepositives:` block) has a benign emulation script here that trips it - a "here's how to set it
off" script. The ~211 vendored SigmaHQ upstream rules are deliberately **not** covered.

Each script name matches the fixture family prefix in `tests/fixtures/<name>.expect-<rule>.json`, so
`tests/vm.nix` discovers the script, runs it, and asserts exactly the listed rule(s) fire. The safety
contract (dummy data, TEST-NET addresses, `/tmp` scratch, `trap  EXIT` cleanup, unprivileged-only for
anything that would touch the live host) is documented in `./README.md` and in each script header.

| Rule (file) | Emulation script | ATT&CK | How it sets the rule off (benign) |
| --- | --- | --- | --- |
| `rules/agent/agent_decode.yml` | `agentdecode.sh` | T1140 | Decode a dummy base64 blob (`base64 -d`, `xxd -r`) in scratch; result discarded. |
| `rules/agent/agent_destructive_action.yml` | `destructive.sh` | T1485 / T1070 | `git branch -D` a nonexistent branch + `reflog expire --all` inside a throwaway scratch repo. |
| `rules/agent/agent_exfil_to_code_host.yml` | `exfil.sh` | T1567.001 | `git remote add` to a TEST-NET URL (scratch repo) + `curl -F` a dummy file to TEST-NET. |
| `rules/agent/agent_git_config_persistence.yml` | `gitpersist.sh` | T1546 / T1574 | `git config --file <scratch> core.hooksPath ` - never the real `~/.gitconfig`. |
| `rules/agent/agent_proxy_bypass.yml` | `proxybypass.sh` | T1562.001 / T1090 | `curl --noproxy '*'` to TEST-NET + `env -u HTTPS_PROXY` strip. |
| `rules/agent/agent_self_config_modification.yml` | `selfconfig.sh` | T1546 | `tee` a dummy `settings.json` into a scratch `.claude/` dir. |
| `rules/agent/agent_ssh_access.yml` | `agentssh.sh` | T1552.004 / T1018 | `cat` dummy `.ssh/{config,known_hosts,id_rsa}` in scratch. |
| `rules/agent/agent_ssh_outbound.yml` | `sshout.sh` | T1021.004 | `ssh` to a TEST-NET host (BatchMode, short timeout - never connects). |
| `rules/agent/honeytoken_access.yml` | `honeytoken.sh` | T1552.001 | Read-only `cat` of the watched decoy paths (needs the decoy planted + a read watch - see below). |
| `rules/collection/data_staged_for_exfil.yml` | `stage.sh` | T1560.001 | `openssl enc -aes-256-cbc` (and `zip -P`) over dummy scratch data. |
| `rules/command-and-control/download_ip_to_tmp.yml` | `amos.sh`, `xmrig.sh` | T1105 | `curl` a bare TEST-NET IP into `/tmp` (pre-existing). |
| `rules/command-and-control/remote_file_copy.yml` | `remotecopy.sh` | T1105 | `scp` a dummy file to a TEST-NET `user@host:path` (BatchMode, short timeout). |
| `rules/command-and-control/reverse_shell.yml` | `revshell.sh` | T1059.004 | bash `/dev/tcp`, python socket, `nc -e` to TEST-NET (pre-existing). |
| `rules/command-and-control/tunnel_tool.yml` | `tunnel.sh` | T1572 | Named tunnel tool `--version` if present, else `ssh -L` port-forward to TEST-NET. |
| `rules/credential-access/credential_file_read.yml` | `amos.sh` | T1552.001 | `cat`/`base64` dummy creds in scratch (pre-existing). |
| `rules/credential-access/credential_search.yml` | `credsearch.sh` | T1552.001 | `find <scratch> -name .aws/credentials` + `grep -ri password <scratch>`. |
| `rules/defense-evasion/deobfuscate_and_run.yml` | `deobfuscate.sh` | T1140 / T1059.004 | `echo <b64> \| base64 -d \| sh` where the blob decodes to the no-op `true`. |
| `rules/defense-evasion/disable_firewall.yml` | `killfw.sh` | T1562.004 | `iptables -F` / `ufw disable` / `nft flush ruleset`, **unprivileged-only** (kernel refuses them). |
| `rules/defense-evasion/disable_logging.yml` | `killlog.sh` | T1562.001 | `sed Storage=none` on a scratch `journald.conf` + `systemctl stop` a nonexistent `-emul-dummy` unit. |
| `rules/defense-evasion/history_tamper.yml` | `histclear.sh` | T1070.003 | `rm`/`ln -sf /dev/null` dummy `.bash_history` / `.zsh_history` in scratch. |
| `rules/defense-evasion/tamper_banken.yml` | `tamper.sh` | T1562 | stop/kill/rm a nonexistent `banken-emul-dummy`, unprivileged `auditctl -D` (pre-existing). |
| `rules/defense-evasion/timestomp.yml` | `stomp.sh` | T1070.006 | `touch -t <past>` and `touch -r /bin/sh` on dummy scratch files. |
| `rules/discovery/network_sniffing.yml` | `sniff.sh` | T1040 | Invoke `tcpdump`/`tshark`/ with `--version` only - no capture. |
| `rules/execution/pipe_to_shell.yml` | `xmrig.sh` | T1059.004 | `curl  \| sh` from TEST-NET (pre-existing). |
| `rules/optional/netcat.yml` | `netcat.sh` | T1095 | `nc -z` connect probe to TEST-NET with a short timeout. |
| `rules/optional/password_cracker.yml` | `johncrack.sh` | T1110 | Invoke `john`/`hashcat`/ with `--version` only - cracks nothing. |
| `rules/persistence/account_creation.yml` | `newuser.sh` | T1136.001 | `useradd banken-emul-dummy`, **unprivileged-only** (cannot write `/etc/passwd`). |
| `rules/persistence/persistence.yml` | `persist.sh` | T1053.003 / T1543.002 | systemd user unit + shell rc, all in a scratch `$HOME` (pre-existing). |
| `rules/persistence/trap_persistence.yml` | `trap.sh` | T1546.005 | `bash -c 'trap "true" EXIT; true'`. |
| `rules/privilege-escalation/privilege_escalation_attempt.yml` | `sudo_probe.sh` | T1548.003 | non-interactive `sudo -n` / `doas -n` probe (pre-existing). |
| `rules/privilege-escalation/setuid_bit_set.yml` | `setuid.sh` | T1548.001 | `chmod u+xs` / `chmod 4755` on a dummy scratch file. |

## Caveats (dependencies outside `tests/emulations/`)

- **Agent-account scoping.** The eight `agent_*` scripts (`agentdecode`, `agentssh`, `destructive`,
  `exfil`, `gitpersist`, `proxybypass`, `selfconfig`, `sshout`) only fire when run **as an agent
  account** - their rules key on `User` in `{claude,redteam,lab}`. The commands themselves match the
  selections; the `User` comes from the runner. `tests/vm.nix` currently runs emulations as `alice`
  via `runuser`, so these need the harness to run them as an agent account (or `alice` added to the
  `agent_user` list) to fire in the VM.
- **`honeytoken.sh`** matches only on `TargetFilename` (the exact decoy paths), so it fires only where
  the decoy files are planted at those paths **and** a read watch is set on each
  (`-w <path> -p r -k honeytoken`). On a stock box it finds nothing and fires nothing - by design.
- **Tool availability.** Some scripts invoke tools that must be in the test VM's
  `environment.systemPackages` to fire: `openssh` (`agentssh` tee / `sshout` / `remotecopy` / `tunnel`),
  `openssl` + `zip` (`stage`), `tcpdump`/`tshark` (`sniff`), `john`/`hashcat` (`johncrack`),
  `cloudflared`/`ngrok` (`tunnel`), `git` (`destructive`/`exfil`/`gitpersist`), `shadow`'s `useradd`
  (`newuser`). Each is `command -v`-guarded and no-ops harmlessly when absent.
