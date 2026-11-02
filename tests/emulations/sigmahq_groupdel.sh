#!/usr/bin/env bash
# sigmahq_groupdel.sh - benign SigmaHQ emulation (see sigmahq_nohup.sh header).
#
# What an attacker does: delete a group with groupdel to disrupt access or cover
# tracks (T1531 Account Access Removal). Harmless analogue: run groupdel against
# a group that does not exist, as an unprivileged user: it is refused (no
# privilege / no such group) and changes nothing - but the execve of groupdel,
# which is all the rule keys on, is real.
#
# Imitates (SigmaHQ): proc_creation_lnx_groupdel.yml - ATT&CK T1531
# Expected rule: proc_creation_lnx_groupdel
set -u

command -v groupdel >/dev/null 2>&1 || { echo "BANKEN-EMUL-SKIP: no groupdel"; exit 0; }

groupdel sigmaemul_nogroup >/dev/null 2>&1 || true

exit 0
