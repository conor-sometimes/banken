#!/usr/bin/env bash
# sigmahq_usermod_group.sh - benign SigmaHQ emulation (see sigmahq_nohup.sh header).
#
# What an attacker does: add an account to a privileged group (root / sudoers)
# to escalate or persist (T1098 Account Manipulation). Harmless analogue: run
# `usermod -aG root` against a user that does not exist, as an unprivileged
# user: it is refused (no privilege, no such user) and changes nothing - but the
# execve carrying the "-aG root" indicator the rule keys on is real.
#
# Imitates (SigmaHQ): proc_creation_lnx_usermod_susp_group.yml - ATT&CK T1098
# Expected rule: proc_creation_lnx_usermod_susp_group
set -u

command -v usermod >/dev/null 2>&1 || { echo "BANKEN-EMUL-SKIP: no usermod"; exit 0; }

usermod -aG root sigmaemul_nouser >/dev/null 2>&1 || true

exit 0
