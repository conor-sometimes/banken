#!/usr/bin/env bash
# sigmahq_awk_shell.sh - benign SigmaHQ emulation (see sigmahq_nohup.sh header).
#
# What an attacker does: spawn a shell from awk (GTFOBins T1059.004), e.g.
# `awk 'BEGIN {system("/bin/sh")}'`. Harmless analogue: the same shape but the
# spawned shell runs `true` and exits. The execve of /awk (gawk) whose command
# line contains 'BEGIN {system' and '/bin/sh', which the rule keys on, is real.
#
# Imitates (SigmaHQ): proc_creation_lnx_awk_shell_spawn.yml - ATT&CK T1059.004
# Expected rule: proc_creation_lnx_awk_shell_spawn
set -u

command -v awk >/dev/null 2>&1 || { echo "BANKEN-EMUL-SKIP: no awk"; exit 0; }

awk 'BEGIN {system("/bin/sh -c true")}' >/dev/null 2>&1 || true

exit 0
