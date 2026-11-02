#!/usr/bin/env bash
# sigmahq_secsoftware_discovery.sh - benign SigmaHQ emulation (see sigmahq_nohup.sh header).
#
# What an attacker does: grep the process list (or configs) for the names of EDR
# and logging agents to learn what defenses are present before disabling them
# (T1518.001 Security Software Discovery). Harmless analogue: grep for a known
# agent name ('falcond', CrowdStrike Falcon) in /dev/null - it reads nothing and
# finds nothing, but the execve of grep carrying 'falcond', which is what the
# rule keys on, is real.
#
# Imitates (SigmaHQ): proc_creation_lnx_security_software_discovery.yml - ATT&CK T1518.001
# Expected rule: proc_creation_lnx_security_software_discovery
set -u

command -v grep >/dev/null 2>&1 || { echo "BANKEN-EMUL-SKIP: no grep"; exit 0; }

grep falcond /dev/null >/dev/null 2>&1 || true

exit 0
