#!/usr/bin/env bash
# sigmahq_getcap.sh - benign SigmaHQ emulation (see sigmahq_nohup.sh header).
#
# What an attacker does: enumerate file capabilities to find a binary with
# cap_setuid/cap_dac_override etc. to abuse for privilege escalation (T1083 /
# capability discovery). Harmless analogue: `getcap -r` over a small read-only
# directory. Read-only; it only lists capabilities.
#
# Imitates (SigmaHQ): proc_creation_lnx_capa_discovery.yml - ATT&CK T1083
# Expected rule: proc_creation_lnx_capa_discovery
set -u

command -v getcap >/dev/null 2>&1 || { echo "BANKEN-EMUL-SKIP: no getcap"; exit 0; }

getcap -r /etc >/dev/null 2>&1 || true

exit 0
