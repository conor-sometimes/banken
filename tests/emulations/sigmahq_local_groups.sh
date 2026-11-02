#!/usr/bin/env bash
# sigmahq_local_groups.sh - benign SigmaHQ emulation (see sigmahq_nohup.sh header).
#
# What an attacker does: enumerate local groups (T1069.001), e.g. `groups` or
# reading /etc/group. Harmless analogue: run `groups` with no arguments - it
# prints the current user's own group membership. The execve of /groups, which
# the rule keys on (selection_1), is real.
#
# Imitates (SigmaHQ): proc_creation_lnx_local_groups.yml - ATT&CK T1069.001
# Expected rule: proc_creation_lnx_local_groups
set -u

command -v groups >/dev/null 2>&1 || { echo "BANKEN-EMUL-SKIP: no groups"; exit 0; }

groups >/dev/null 2>&1 || true

exit 0
