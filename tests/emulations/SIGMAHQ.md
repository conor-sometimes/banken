# SigmaHQ Linux coverage / skip ledger

This file is a sibling to `RULES.md`. `RULES.md` maps banken's **own** rules (under `rules/`) to
the emulations that trip them in `tests/vm.nix`. This file is the ledger for the **vendored
upstream SigmaHQ Linux ruleset** that banken measures coverage against. That is the pinned release
(`justfile` `sigma_release`, currently `r2026-07-01`, 210 Linux rules). `tests/sigmahq-emul.nix`
loads it on top of banken's baseline and proves banken detects it.

For a rule marked **supported** here there is a benign `sigmahq_<name>.sh` in this directory. Run as
an unprivileged user on a stock NixOS test host, it makes exactly that named SigmaHQ rule fire. This
is proven by `nix-build tests/sigmahq-emul.nix` (needs KVM; run on hokkaido).

## Source of truth for the supported set

The authoritative, machine-checked list of supported rules is the **`expected` map in
`tests/sigmahq-emul.nix`**. It maps each family to the SigmaHQ rule name(s) its emulation must
fire, and no other process_creation rule. This file does NOT re-list every supported rule - read
`expected` for that. This ledger records two things, with reasons: what is **deferred** and what is
**permanently skipped**. It also summarises the counts.

**This file is maintained by the grind.** When a batch adds a `sigmahq_<name>.sh` plus its
`expected` entry and proves it, move that rule from a "pending/deferred" line here to the supported
count, and drop any matching note. When a batch finds a rule genuinely unemulatable, record it here
with the reason rather than leaving it silent.

## Summary (as of batch 6, r2026-07-01)

| SigmaHQ Linux category | Total | Supported here | Notes |
| --- | --- | --- | --- |
| `process_creation/` | 122 | ~94 (see `expected`) | the grind's main layer |
| `file_event/` | 8 | 6 (see `expected`) | reached via `audit.watchPaths` scratch files |
| `network_connection/` | 5 | 0 | deferred - auditd-network-fields engine gap |
| `auditd/` | 53 | 0 gated | auditd-logsource layer; some fire as bonus twins, none gated here yet |
| `builtin/` | 22 | 0 | service-log / syslog message rules; see category note |
| **total** | **210** | **~100 distinct rules** | |

The supported count grew batch by batch:

- Batches 1-3: 54.
- Batch 4: to ~79 (+21 process_creation, +4 file_event). The `nohup`/`mkfifo` base rules were
  already supported and fire as twins of the new `_susp`/`_susp_location` refinements.
- Batch 5: to ~97 (+18 process_creation). The new rules were `netcat_reverse_shell`,
  `ssh_shell_execution`, `curl_wget_exec_tmp`, `install_root_certificate`,
  `install_suspicious_packages`, `security_tools_disabling`, `clipboard_collection`,
  `malware_gobrat_grep_payload_discovery`, `pnscan_binary_cli_pattern`,
  `triple_cross_rootkit_execve_hijack`, `triple_cross_rootkit_install`, `dd_process_injection`,
  `xterm_reverse_shell`, `bpftrace_unsafe_option_usage`, `bpf_kprob_tracing_enabled`,
  `susp_recon_indicators`, `susp_shell_script_exec_from_susp_location`, and
  `susp_network_utilities_execution`. The already-supported `curl_usage`,
  `services_stop_and_disable` and `file_and_directory_discovery` fire as twins of the new rules.

Batch 6 added the last three Image/CommandLine-only process_creation rules (+3, to ~100):

- `susp_git_clone`: clone of a nonexistent local repo whose path carries 'CVE-'/'proxyshell'.
- `rsync_shell_execution`: `true` copied as 'rsync', run with ' -e '/'/bin/sh '.
- `chroot_execution`: `sudo -n --chroot` refused for the unprivileged user.

Batch 6 also drew the line under the layer. The six remaining pending process_creation rules all
key on a PARENT field this harness's source does not carry. They are recorded below as deferred
(never faked).

## Deferred to the distro matrix (task `d468b494`)

For each rule here the tool exists on a real distro but is not in nixpkgs. So the benign emulation
cannot run on this NixOS harness. These are matrix work (the every-rule-x-every-distro north-star),
**not** skips.

| Rule (file) | Needs / distro |
| --- | --- |
| `process_creation/proc_creation_lnx_disable_ufw.yml` | `ufw` -> Ubuntu/Debian |
| `process_creation/proc_creation_lnx_iptables_flush_ufw.yml` | `ufw` (and iptables) -> Ubuntu/Debian |
| `process_creation/proc_creation_lnx_ssm_agent_abuse.yml` | AWS SSM agent -> Amazon Linux |
| `process_creation/proc_creation_lnx_remote_access_tools_teamviewer_incoming_connection.yml` | `teamviewer` -> Ubuntu |
| `process_creation/proc_creation_lnx_apt_shell_execution.yml` | `apt`/`apt-get` (not in nixpkgs) -> Ubuntu/Debian |
| `process_creation/proc_creation_lnx_pua_trufflehog.yml` | `trufflehog` -> installable OSS, any distro |
| `process_creation/proc_creation_lnx_susp_script_interpretor_spawn_credential_scanner.yml` | gitleaks/trufflehog-style credential scanner -> installable OSS, any distro |
| `process_creation/proc_creation_lnx_susp_hktl_execution.yml` | named hacktools / nuclei -> installable OSS, any distro |
| `process_creation/proc_creation_lnx_omigod_scx_runasprovider_executescript.yml` | OMI/SCX agent -> niche (OMIGOD) |
| `process_creation/proc_creation_lnx_omigod_scx_runasprovider_executeshellcommand.yml` | OMI/SCX agent -> niche (OMIGOD) |
| `process_creation/proc_creation_lnx_dd_file_overwrite.yml` | rule matches an **exact** `Image: /bin/dd` or `/usr/bin/dd`; NixOS store paths differ so it never matches here - fires on a real distro where `dd` lives at `/usr/bin/dd` |
| `process_creation/proc_creation_lnx_gcc_shell_execution.yml` | NixOS `gcc` is a cc-wrapper script, so the execve `Image` resolves to the interpreter, not `.../gcc`; needs a real-distro `gcc` binary |

### Deferred - privileged write to a real /etc path (file_event)

These file_event rules anchor `TargetFilename` to a real system path (`startswith` `/etc/...`). So
the filename trick the other file_event emulations use - create the indicator in a watched scratch
dir - cannot satisfy them. The file must actually live under `/etc`, which needs root. The
unprivileged NixOS harness runs the emulations as `alice`. These need a root-run path instead (a
real host, or a privileged file_event variant), so they are deferred.

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

### Deferred - parent-field source gap (process_creation)

These six rules key on a field describing the PARENT process that this harness's log source does
not carry. This harness auto-detects the raw auditd source (`/var/log/audit/audit.log`). An auditd
EXECVE/SYSCALL record gives the parent's PID (`ppid=`), but neither the parent's executable path
nor its command line. So banken's auditd parser leaves `ParentImage` empty and never sets
`ParentCommandLine`. A batch-6 run confirmed this. A benign emulation that forks the right child IS
captured as a child execve, but the parent-field selection does not match, so the rule does not
fire. (The forked child was a copied `bash` named `java`/`nginx`/`rsync`, or a `/tmp`-resident
parent, spawning `/bin/sh` or `whoami`.) These are not faked or skipped silently. They become
emulatable once the harness ingests a Laurel source, since Laurel enriches `ParentImage` from
`SYSCALL.PPID.exe`. That is future harness work, not a rule-writing task.

| Rule (file) | Parent field needed |
| --- | --- |
| `process_creation/proc_creation_lnx_susp_java_children.yml` | `ParentImage` endswith `/java` |
| `process_creation/proc_creation_lnx_webshell_detection.yml` | `ParentImage` endswith a web-server name (`/nginx`, `/apache2`, ...) |
| `process_creation/proc_creation_lnx_rsync_shell_spawn.yml` | `ParentImage` endswith `/rsync` |
| `process_creation/proc_creation_lnx_susp_shell_child_process_from_parent_tmp_folder.yml` | `ParentImage` startswith `/tmp/` |
| `process_creation/proc_creation_lnx_git_shell_execution.yml` | `ParentCommandLine` contains ` -p ` + `help` (not carried by auditd OR Laurel) |
| `process_creation/proc_creation_lnx_susp_interactive_bash.yml` | `ParentCommandLine` exactly `bash -i` (not carried by auditd OR Laurel) |

## Permanent skips

These target things the distro matrix will never carry: a hypervisor CLI, or a proprietary
product. So no benign Linux-distro emulation is possible.

### ESXi (esxcli) x9 - VMware ESXi hypervisor, not a Linux distro

`esxcli` is the VMware ESXi management CLI. ESXi is a hypervisor, not a distro in the matrix.

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

None. The gated `process_creation` layer is exhausted. Every SigmaHQ Linux `process_creation` rule
is now in one of three states:

- supported (see `expected`)
- deferred with a reason above (the distro matrix `d468b494`; the parent-field source gap; the
  root-only `/etc` file_event paths; the network_connection engine gap)
- a permanent skip (ESXi x9, Kaspersky)

The `file_event` layer is likewise exhausted: 6 supported, 2 deferred for needing a root write
under `/etc`.

Batch 6 proved the last three Image/CommandLine-only rules: `susp_git_clone`,
`rsync_shell_execution`, and `chroot_execution`. A batch-6 run then confirmed the six parent-field
rules cannot fire under the raw-auditd source, so they moved to the parent-field deferred table.
Those six are `susp_java_children`, `webshell_detection`, `rsync_shell_spawn`,
`susp_shell_child_process_from_parent_tmp_folder`, `git_shell_execution`, and
`susp_interactive_bash`. The next coverage gains come from the auditd/builtin layers (below), or
from a Laurel-source harness that would unlock the four `ParentImage` rules.

## Pending categories (not process_creation)

- **`auditd/` (53).** This harness proves the **process_creation + file_event** layers. The
  auditd-logsource rules key on raw auditd syscall records. Some already fire as non-gated "twin"
  coverage alongside a process_creation hit (e.g. `lnx_auditd_coinminer` with the crypto_mining
  rule - see the `tests/sigmahq-emul.nix` header), but none is gated/proven here. A dedicated
  auditd-logsource proving path is separate future work.
- **`builtin/` (22).** These are syslog / service-log message rules. They split in two.

  The command-shaped ones are future grind candidates:
  - `lnx_shell_clear_cmd_history`
  - `lnx_shell_susp_commands`
  - `lnx_shell_susp_rev_shells`
  - `lnx_susp_dev_tcp`
  - `lnx_clear_syslog`
  - `lnx_file_copy`
  - `lnx_symlink_etc_passwd`
  - `lnx_privileged_user_creation`
  - `lnx_ldso_preload_injection`
  - `lnx_shellshock`
  - `lnx_susp_jexboss`
  - `lnx_apt_equationgroup_lnx`
  - `lnx_buffer_overflows`

  The daemon-error-message ones are beyond this harness. Each needs the specific service's log
  source ingested and the service emitting the error:
  - `lnx_sshd_susp_ssh`
  - `lnx_vsftpd_susp_error_messages`
  - `lnx_syslog_susp_named`
  - `lnx_clamav_relevant_message`
  - `lnx_guacamole_susp_guacamole`
  - `lnx_syslog_security_tools_disabling_syslog`
  - `lnx_shell_susp_log_entries`
  - `lnx_potential_susp_ebpf_activity`
  - `lnx_cron_crontab_file_modification`
