#!/usr/bin/env bash
# sigmahq_userdel.sh - benign SigmaHQ emulation (see sigmahq_nohup.sh header).
#
# What an attacker does: delete a user account with userdel to remove a defender
# or cover tracks (T1531 Account Access Removal). Harmless analogue: run userdel
# against a user that does not exist, as an unprivileged user: it is refused (no
# privilege / no such user) and changes nothing - but the execve of userdel,
# which is all the rule keys on, is real.
#
# Imitates (SigmaHQ): proc_creation_lnx_userdel.yml - ATT&CK T1531
# Expected rule: proc_creation_lnx_userdel
set -u

command -v userdel >/dev/null 2>&1 || { echo "BANKEN-EMUL-SKIP: no userdel"; exit 0; }

userdel sigmaemul_nouser >/dev/null 2>&1 || true

exit 0
