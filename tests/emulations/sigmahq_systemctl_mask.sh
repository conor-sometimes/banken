#!/usr/bin/env bash
# sigmahq_systemctl_mask.sh - benign SigmaHQ emulation (see sigmahq_nohup.sh header).
#
# What an attacker does: mask the power/sleep targets with systemctl so the host
# cannot suspend or hibernate, keeping a long-running payload alive (T1653-style
# power-management tampering). Harmless analogue: attempt the mask as an
# unprivileged user: polkit denies it (needs root), so nothing is masked - but
# the execve of systemctl carrying ' mask' and 'suspend.target', which is what
# the rule keys on, is real.
#
# Imitates (SigmaHQ): proc_creation_lnx_systemctl_mask_power_settings.yml
# Expected rule: proc_creation_lnx_systemctl_mask_power_settings
set -u

command -v systemctl >/dev/null 2>&1 || { echo "BANKEN-EMUL-SKIP: no systemctl"; exit 0; }

systemctl mask suspend.target >/dev/null 2>&1 || true

exit 0
