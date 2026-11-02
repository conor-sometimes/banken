#!/usr/bin/env bash
# sigmahq_mount_hidepid.sh - benign SigmaHQ emulation (see sigmahq_nohup.sh header).
#
# What an attacker does: remount /proc with hidepid=2 so other users' processes
# are hidden - an anti-forensics / defense-evasion move (T1564). Harmless
# analogue: attempt the mount as an unprivileged user against a non-existent
# mountpoint: it is refused (only root can mount) and changes nothing - but the
# execve of mount carrying ' -o ' and 'hidepid=2', which is what the rule keys
# on, is real.
#
# Imitates (SigmaHQ): proc_creation_lnx_mount_hidepid.yml - ATT&CK T1564
# Expected rule: proc_creation_lnx_mount_hidepid
set -u

command -v mount >/dev/null 2>&1 || { echo "BANKEN-EMUL-SKIP: no mount"; exit 0; }

mount -o hidepid=2 proc /sigmaemul_nomountpoint >/dev/null 2>&1 || true

exit 0
