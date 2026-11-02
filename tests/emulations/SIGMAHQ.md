# SigmaHQ Linux coverage / skip ledger

Sibling to `RULES.md`. Where `RULES.md` maps banken's **own** rules (under `rules/`) to the
emulations that trip them in `tests/vm.nix`, this file is the ledger for the **vendored upstream
SigmaHQ Linux ruleset** that banken measures coverage against: the pinned release
(`justfile` `sigma_release`, currently `r2026-07-01`, 210 Linux rules) that
`tests/sigmahq-emul.nix` loads on top of banken's baseline and proves banken detects.

For a rule marked **supported** here there is a benign `sigmahq_<name>.sh` in this directory whose
run (as an unprivileged user, on a stock NixOS test host) makes exactly that named SigmaHQ rule
fire, proven by `nix-build tests/sigmahq-emul.nix` (needs KVM; run on hokkaido).

## Source of truth for the supported set

The authoritative, machine-checked list of supported rules is the **`expected` map in
`tests/sigmahq-emul.nix`** (family -> the SigmaHQ rule name(s) its emulation must fire, and no other
process_creation rule). This file does NOT re-list every supported rule - read `expected`. This
ledger exists to record what is **deferred** and what is **permanently skipped**, with reasons, and
to summarise the counts.

**This file is maintained by the grind.** When a batch adds a `sigmahq_<name>.sh` + its `expected`
entry and proves it, move that rule from a "pending/deferred" line here to the supported count (and
drop any matching note). When a batch finds a rule genuinely unemulatable, record it here with the
reason rather than leaving it silent.

## Summary (as of batch 4, r2026-07-01)

| SigmaHQ Linux category | Total | Supported here | Notes |
| --- | --- | --- | --- |
| `process_creation/` | 122 | ~73 (see `expected`) | the grind's main layer |
| `file_event/` | 8 | 6 (see `expected`) | reached via `audit.watchPaths` scratch files |
| `network_connection/` | 5 | 0 | deferred - auditd-network-fields engine gap |
| `auditd/` | 53 | 0 gated | auditd-logsource layer; some fire as bonus twins, none gated here yet |
| `builtin/` | 22 | 0 | service-log / syslog message rules; see category note |
| **total** | **210** | **~79 distinct rules** | |

Supported jumped from 54 (batches 1-3) to ~79 with batch 4 (+21 process_creation, +4 file_event;
the `nohup`/`mkfifo` base rules were already supported and fire as twins of the new
`_susp`/`_susp_location` refinements).

## Deferred to the distro matrix (task `d468b494`)

Tool exists on a real distro but is not in nixpkgs, so the benign emulation cannot run on this
NixOS harness. These are matrix work (every-rule-x-every-distro north-star), **not** skips.

| Rule (file) | Needs / distro |
| --- | --- |
| `process_creation/proc_creation_lnx_disable_ufw.yml` | `ufw` -> Ubuntu/Debian |
| `process_creation/proc_creation_lnx_iptables_flush_ufw.yml` | `ufw` (and iptables) -> Ubuntu/Debian |
| `process_creation/proc_creation_lnx_ssm_agent_abuse.yml` | AWS SSM agent -> Amazon Linux |
| `process_creation/proc_creation_lnx_remote_access_tools_teamviewer_incoming_connection.yml` | `teamviewer` -> Ubuntu |
| `process_creation/proc_creation_lnx_pua_trufflehog.yml` | `trufflehog` -> installable OSS, any distro |
| `process_creation/proc_creation_lnx_susp_script_interpretor_spawn_credential_scanner.yml` | gitleaks/trufflehog-style credential scanner -> installable OSS, any distro |
| `process_creation/proc_creation_lnx_susp_hktl_execution.yml` | named hacktools / nuclei -> installable OSS, any distro |
| `process_creation/proc_creation_lnx_omigod_scx_runasprovider_executescript.yml` | OMI/SCX agent -> niche (OMIGOD) |
| `process_creation/proc_creation_lnx_omigod_scx_runasprovider_executeshellcommand.yml` | OMI/SCX agent -> niche (OMIGOD) |
| `process_creation/proc_creation_lnx_dd_file_overwrite.yml` | rule matches an **exact** `Image: /bin/dd` or `/usr/bin/dd`; NixOS store paths differ so it never matches here - fires on a real distro where `dd` lives at `/usr/bin/dd` |
| `process_creation/proc_creation_lnx_gcc_shell_execution.yml` | NixOS `gcc` is a cc-wrapper script, so the execve `Image` resolves to the interpreter, not `.../gcc`; needs a real-distro `gcc` binary |

### Deferred - privileged write to a real /etc path (file_event)

These file_event rules anchor `TargetFilename` to a real system path (`startswith` `/etc/...`), so
the filename trick the other file_event emulations use (create the indicator in a watched scratch
dir) cannot satisfy them - the file must actually live under `/etc`, which needs root. The
unprivileged NixOS harness runs the emulations as `alice`; these need a root-run path (a real host,
or a privileged file_event variant) and are deferred.

| Rule (file) | Needs |
| --- | --- |
| `file_event/file_event_lnx_persistence_sudoers_files.yml` | write under `/etc/sudoers.d/` (root) |
| `file_event/file_event_lnx_susp_cron_file_created.yml` | write under `/etc/cron.d/`, `/etc/cron.*/`, `/var/spool/cron/...` (root) |

### Deferred - auditd-network-fields engine gap (network_connection)

All five `network_connection/` rules key on the auditd network fields (the connect/sendto address +
port) that banken's engine does not yet surface. Blocked on that engine work, not emulatable here.

- `net_connection_lnx_back_connect_shell_dev.yml`
- `net_connection_lnx_crypto_mining_indicators.yml`
- `net_connection_lnx_domain_localtonet_tunnel.yml`
- `net_connection_lnx_ngrok_tunnel.yml`
- `net_connection_lnx_susp_malware_callback_port.yml`

## Permanent skips

Targets the distro matrix will never carry (a hypervisor CLI, or a proprietary product), so no
benign Linux-distro emulation is possible.

### ESXi (esxcli) x9 - VMware ESXi hypervisor, not a Linux distro

`esxcli` is the VMware ESXi management CLI; ESXi is a hypervisor, not a distro in the matrix.

- `process_creation/proc_creation_lnx_esxcli_network_discovery.yml`
- `process_creation/proc_creation_lnx_esxcli_permission_change_admin.yml`
- `process_creation/proc_creation_lnx_esxcli_storage_discovery.yml`
- `process_creation/proc_creation_lnx_esxcli_syslog_config_change.yml`
- `process_creation/proc_creation_lnx_esxcli_system_discovery.yml`
- `process_creation/proc_creation_lnx_esxcli_user_account_creation.yml`
- `process_creation/proc_creation_lnx_esxcli_vm_discovery.yml`
- `process_creation/proc_creation_lnx_esxcli_vm_kill.yml`
- `process_creation/proc_creation_lnx_esxcli_vsan_discovery.yml`

### Proprietary product

- `process_creation/proc_creation_lnx_av_kaspersky_av_disabled.yml` - keys on the Kaspersky
  Endpoint Security binary, a licensed proprietary AV; not in nixpkgs or any FOSS matrix distro.

## Pending - emulatable, future grind batches (process_creation)

Still unsupported but have no blocker beyond not-yet-written; good next-batch targets (rule names
shown without the `proc_creation_lnx_` prefix): `netcat_reverse_shell`, `ssh_shell_execution`
(fail-closed `LocalCommand`), `apt_shell_execution`, `curl_wget_exec_tmp`,
`install_root_certificate`, `install_suspicious_packages`, `security_tools_disabling`,
`clipboard_collection`, `susp_git_clone`, `susp_shell_script_exec_from_susp_location`,
`susp_shell_child_process_from_parent_tmp_folder`, `malware_gobrat_grep_payload_discovery`,
`pnscan_binary_cli_pattern`, `susp_network_utilities_execution`, `susp_recon_indicators`,
`triple_cross_rootkit_execve_hijack`, `triple_cross_rootkit_install`, `xterm_reverse_shell`,
`dd_process_injection`.

### Pending - harder (process_creation)

Need a specific parent process, interpreter runtime, or shell topology that is awkward to stage
benignly; doable but fiddly, not blocked:

- `rsync_shell_spawn.yml` / `rsync_shell_execution.yml` - rsync as PARENT spawning a shell, with the
  normal ` -e ` form explicitly filtered out.
- `git_shell_execution.yml` - parent `git -p help` with a shell pager.
- `susp_interactive_bash.yml` - requires `ParentCommandLine` exactly `bash -i`.
- `webshell_detection.yml` - shell child of a web-server user (apache/nginx/www-data).
- `susp_java_children.yml` - JVM spawning a shell.
- `chroot_execution.yml` - keys on `sudo --chroot`; running `sudo` risks tripping the
  privilege-escalation path the harness deliberately avoids (`runuser`, never `su`/`sudo`).

## Pending categories (not process_creation)

- **`auditd/` (53):** this harness proves the **process_creation + file_event** layers. The
  auditd-logsource rules key on raw auditd syscall records; some already fire as non-gated "twin"
  coverage alongside a process_creation hit (e.g. `lnx_auditd_coinminer` with the crypto_mining
  rule - see the `tests/sigmahq-emul.nix` header), but none is gated/proven here. A dedicated
  auditd-logsource proving path is separate future work.
- **`builtin/` (22):** syslog / service-log message rules. The command-shaped ones
  (`lnx_shell_clear_cmd_history`, `lnx_shell_susp_commands`, `lnx_shell_susp_rev_shells`,
  `lnx_susp_dev_tcp`, `lnx_clear_syslog`, `lnx_file_copy`, `lnx_symlink_etc_passwd`,
  `lnx_privileged_user_creation`, `lnx_ldso_preload_injection`, `lnx_shellshock`,
  `lnx_susp_jexboss`, `lnx_apt_equationgroup_lnx`, `lnx_buffer_overflows`) are future grind
  candidates. The daemon-error-message ones (`lnx_sshd_susp_ssh`, `lnx_vsftpd_susp_error_messages`,
  `lnx_syslog_susp_named`, `lnx_clamav_relevant_message`, `lnx_guacamole_susp_guacamole`,
  `lnx_syslog_security_tools_disabling_syslog`, `lnx_shell_susp_log_entries`,
  `lnx_potential_susp_ebpf_activity`, `lnx_cron_crontab_file_modification`) need the specific
  service's log source ingested and the service emitting the error, which is beyond this harness.
