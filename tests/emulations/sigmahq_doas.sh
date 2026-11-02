#!/usr/bin/env bash
# sigmahq_doas.sh - benign SigmaHQ emulation (see sigmahq_nohup.sh header).
#
# What an attacker does: use doas (an OpenBSD-style sudo) to run a command as
# another user, often root, for privilege escalation (T1548). Harmless analogue:
# invoke doas on a stock host with no doas.conf - it refuses (no rule / no config)
# and runs nothing, but the execve of doas, which is all the rule keys on, is real.
#
# Imitates (SigmaHQ): proc_creation_lnx_doas_execution.yml - ATT&CK T1548
# Expected rule: proc_creation_lnx_doas_execution
set -u

command -v doas >/dev/null 2>&1 || { echo "BANKEN-EMUL-SKIP: no doas"; exit 0; }

doas true >/dev/null 2>&1 || true

exit 0
