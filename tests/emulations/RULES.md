# Own rule -> emulation script map

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
| `rules/optional/netcat.yml` | `netcat.sh` | T1095 | Plain `nc` connect (no `-z`) to TEST-NET with a short timeout. |
| `rules/optional/password_cracker.yml` | `johncrack.sh` | T1110 | Invoke `john`/`hashcat`/etc. with `--version` only - cracks nothing. |
| `rules/persistence/account_creation.yml` | `newuser.sh` | T1136.001 | `useradd banken-emul-dummy`, **unprivileged-only** (cannot write `/etc/passwd`). |
| `rules/persistence/persistence.yml` | `persist.sh` | T1053.003 / T1543.002 | systemd user unit + shell rc, all in a scratch `$HOME` (pre-existing). |
| `rules/persistence/trap_persistence.yml` | `trap.sh` | T1546.005 | `bash -c 'trap "true" EXIT; true'`. |
| `rules/privilege-escalation/privilege_escalation_attempt.yml` | `sudo_probe.sh` | T1548.003 | non-interactive `sudo -n` / `doas -n` probe (pre-existing). |
| `rules/privilege-escalation/setuid_bit_set.yml` | `setuid.sh` | T1548.001 | `chmod u+xs` / `chmod 4755` on a dummy scratch file. |
| `rules/defense-evasion/audit_config_tamper.yml` | `auditconf.sh` | T1562.006 | `cp` the real `/etc/audit/auditd.conf` + `/etc/rsyslog.conf` to scratch (read-only); edit lands only on the scratch copy. |
| `rules/defense-evasion/disable_mac.yml` | `setenforce0.sh` | T1562.001 | `sed SELINUX=disabled` on a scratch selinux config + `systemctl stop` a nonexistent `apparmor-emul-dummy`; `setenforce 0` only if present and unprivileged. |
| `rules/defense-evasion/masquerading.yml` | `masqdaemon.sh` | T1036.005 | Copy `true` into a `/tmp` scratch dir as `crond` and into a `...` dir, then exec (both just exit 0). |
| `rules/defense-evasion/permission_modification.yml` | `permtamper.sh` | T1222.002 | `chmod 777` + `chattr -i` on a dummy scratch file. |
| `rules/discovery/network_service_scan.yml` | `portscan.sh` | T1046 | Invoke `nmap`/`masscan`/etc. with `--version` only - no scan (the `nc -z` form is avoided to not cross-fire `netcat`). |
| `rules/persistence/kernel_module_load.yml` | `insmodload.sh` | T1547.006 / T1014 | `modprobe` / `insmod` a nonexistent dummy module - loads nothing. |
| `rules/privilege-escalation/ld_preload_hijack.yml` | `ldpreload.sh` | T1574.006 | `env LD_PRELOAD=/nonexistent.so true` + `cp` the real `/etc/ld.so.preload` to scratch (read-only). |
| `rules/privilege-escalation/sudoers_modification.yml` | `sudoersedit.sh` | T1548.003 | `cp` the real `/etc/sudoers` to scratch (read-only); NOPASSWD edit lands only on a scratch drop-in (`visudo -c`). |
| `rules/impact/data_destruction.yml` | `diskwipe.sh` | T1485 | `rm -rf --no-preserve-root` a scratch dir; `dd`/`mkfs.ext4` to a nonexistent `/dev/sdz`, unprivileged-only, `count=0`. |
| `rules/impact/service_stop.yml` | `servicestop.sh` | T1489 | `systemctl stop` a nonexistent `cups-emul-dummy` unit (defense services are carved out; this fires on a non-defense stop). |
| `rules/defense-evasion/system_log_cleared.yml` | `syslogclear.sh` | T1070.002 | `truncate -s0`/`rm` DUMMY files in a scratch `.../var/log/` tree; an app log under `/var/log` is not matched, only named system logs. |
| `rules/credential-access/pam_config_modification.yml` | `pammod.sh` | T1556.003 | `cp` a real `/etc/pam.d` file to scratch (read-only); `sed` a `pam_succeed_if.so` rule into a scratch file. |
| `rules/defense-evasion/root_ca_installed.yml` | `rootca.sh` | T1553.004 | `cp` a DUMMY cert into a scratch `.../etc/pki/ca-trust/source/anchors/` tree (never the real store; rebuild tool not run). |
| `rules/persistence/rc_script_persistence.yml` | `rcpersist.sh` | T1037.004 | `tee -a` a no-op line into a scratch `.../etc/rc.local` (never the real boot script). |
| `rules/discovery/security_software_discovery.yml` | `edrdiscover.sh` | T1518.001 | `pgrep`/`grep -E` for EDR/AV agent names (`falcond`/`osqueryd`/`wazuh-agent`...); matches nothing on a clean box. |
| `rules/credential-access/shell_history_read.yml` | `histread.sh` | T1552.003 | `cat` a DUMMY `.bash_history` in scratch (reading it; wiping is `history_tamper`). |
| `rules/defense-evasion/masquerade_extension.yml` | `masqext.sh` | T1036.008 / T1036.007 | `sh` a scratch `image.png` script, and exec a scratch `report.pdf.sh` (each just echoes). |
| `rules/command-and-control/tor_usage.yml` | `torstart.sh` | T1090.003 | `systemctl start` a nonexistent `tor-emul` unit (starts nothing; the `tor`+start argv is the signal). |
| `rules/credential-access/browser_credential_access.yml` | `browsercred.sh` | T1555.003 / T1217 | `cat` a DUMMY `logins.json` under a scratch `.mozilla/firefox` profile. |
| `rules/exfiltration/public_paste_exfil.yml` | `pasteexfil.sh` | T1567.004 / T1048.002 | `curl -F` to `file.io`/a Discord webhook HOSTNAME, pinned to TEST-NET with `--resolve` (nothing leaves). |
| `rules/credential-access/proc_memory_dump.yml` | `procmemdump.sh` | T1003.007 | `dd` one byte of the script's OWN `/proc/<pid>/maps` to scratch (nothing of consequence dumped). |
| `rules/execution/gtfobin_shell_spawn.yml` | `gtfoshell.sh` | T1059.004 / T1202 / T1218 | `find <scratch> -exec /bin/sh -c true`, `awk 'BEGIN{system("true")}'`, `busybox sh -c true` - the GTFOBins shell-spawn recipe, running `true`. |
| `rules/privilege-escalation/gtfobin_sudo_breakout.yml` | `gtfosudo.sh` | T1548.003 / T1202 | `sudo -n find /nonexistent -exec /bin/sh -c true` (sudo -n never escalates); also fires `privilege_escalation_attempt` (sudo ran). |
| `rules/execution/gtfobin_pager_escape.yml` | `gtfopager.sh` | T1059 / T1202 | invokes a harmless scratch stand-in named `vim` with the real `-c ':!true'` escape argv (and a real vim if present). |
| `rules/execution/gtfobin_interpreter_exec.yml` | `gtfointerp.sh` | T1059.006 / T1202 | `python3 -c 'os.system("true")'`, `perl -e 'exec "/bin/true"'` - inline command-exec idioms (no socket/revshell). |
| `rules/impact/gtfobin_file_write_sink.yml` | `gtfowrite.sh` | T1565.001 / T1574.006 | `tee`/`dd` into a SCRATCH `.../etc/ld.so.preload` and `.../etc/profile.d/` (the sink path is in the argv; the real sinks are untouched). |
| `rules/agent/agent_ai_enabled_exfil.yml` | `aiexfil.sh` | T1700 | agent-scoped: `rclone copy` / `curl --upload-file` of dummy data to a TEST-NET drop (nothing leaves). Agent-account only (see caveat). |
| `rules/agent/agent_impair_autonomous_defenses.yml` | `aidefense.sh` | T1685.007 | agent-scoped: `systemctl stop` / `pkill` of nonexistent `-emul-dummy` names that look like EDR tools. Agent-account only (see caveat). |
| `rules/agent/agent_anti_automation_evasion.yml` | `antiautomation.sh` | T1696 / T1696.001 | agent-scoped: `curl` a CAPTCHA-solver name (`2captcha`) and a stealth-toolkit name (`undetected-chromedriver`) under `.invalid` (never resolves). Agent-account only (see caveat). |
| `rules/agent/agent_steal_app_password.yml` | `appasswd.sh` | T1697 | agent-scoped: `cat` DUMMY application-specific password stores (`.msmtprc`, `.authinfo`, `.netrc`) in scratch. Agent-account only (see caveat). |

## Caveats (dependencies outside `tests/emulations/`)

- **Agent-account scoping.** The `agent_*` scripts (`agentdecode`, `agentssh`, `destructive`,
  `exfil`, `gitpersist`, `proxybypass`, `selfconfig`, `sshout`, `aiexfil`, `aidefense`,
  `antiautomation`, `appasswd`) only fire
  when run **as an agent account** - their rules key on `User` in `{claude,redteam,lab}`. The
  commands themselves match the selections; the `User` comes from the runner. `tests/vm.nix` runs
  emulations as `alice`, so it drops every `agent_*` family from the live expectation and proves
  them with the engine golden/replay tests (`internal/engine` TestFixtures) instead.
- **`honeytoken.sh`** matches only on `TargetFilename` (the exact decoy paths), so it fires only where
  the decoy files are planted at those paths **and** a read watch is set on each
  (`-w <path> -p r -k honeytoken`). On a stock box it finds nothing and fires nothing - by design.
- **Tool availability.** Some scripts invoke tools that must be in the test VM's
  `environment.systemPackages` to fire: `openssh` (`agentssh` tee / `sshout` / `remotecopy` / `tunnel`),
  `openssl` + `zip` (`stage`), `tcpdump`/`tshark` (`sniff`), `john`/`hashcat` (`johncrack`),
  `cloudflared`/`ngrok` (`tunnel`), `git` (`destructive`/`exfil`/`gitpersist`), `shadow`'s `useradd`
  (`newuser`), `nmap` or another scanner (`portscan`), `e2fsprogs`'s `mkfs.ext4` and `kmod`'s
  `modprobe`/`insmod` (`diskwipe` / `insmodload`). Each is `command -v`-guarded and no-ops harmlessly
  when absent.
- **`nc -z` trips two rules.** The new `network_service_scan` rule matches `nc -z` / `ncat -z`, the same
  as the optional `netcat` rule. So `netcat.sh` deliberately uses a plain `nc` connect (no `-z`) to
  fire only `netcat`, and `portscan.sh` uses scanner binaries (not `nc`) to fire only
  `network_service_scan`. If both the `netcat` optional rule and `network_service_scan` are active, a
  single `nc -z` would fire both; keep the two scripts off that overlap.
- **Unprivileged-only scripts.** `killfw`, `newuser`, `diskwipe`, and the `setenforce` branch of
  `setenforce0` run their dangerous verb only when `id -u != 0` (and against nonexistent targets where
  possible), so the exec is logged but nothing real is changed. Run as root they would do real harm, so
  they self-skip - the VM runs emulations unprivileged (`alice`), which is exactly where they fire.
