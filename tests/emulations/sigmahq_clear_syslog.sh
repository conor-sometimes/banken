#!/usr/bin/env bash
# sigmahq_clear_syslog.sh - benign SigmaHQ emulation (see sigmahq_nohup.sh header).
#
# What an attacker does: purge the journal to destroy evidence (T1070.002), e.g.
# `journalctl --rotate` / `--vacuum-*`. Harmless analogue: run `journalctl
# --rotate` as an unprivileged user - systemd refuses it (access denied) and
# nothing is rotated, but the execve carrying 'journalctl --rotate', which the
# rule keys on (selection_unique_journalctl), is real.
#
# Imitates (SigmaHQ): proc_creation_lnx_clear_syslog.yml - ATT&CK T1070.002
# Expected rule: proc_creation_lnx_clear_syslog
set -u

command -v journalctl >/dev/null 2>&1 || { echo "BANKEN-EMUL-SKIP: no journalctl"; exit 0; }

journalctl --rotate >/dev/null 2>&1 || true

exit 0
