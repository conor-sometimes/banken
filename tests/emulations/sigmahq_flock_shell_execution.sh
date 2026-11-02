#!/usr/bin/env bash
# sigmahq_flock_shell_execution.sh - benign SigmaHQ emulation (see sigmahq_nohup.sh header).
#
# What an attacker does: use flock to launch a shell (GTFOBins T1059.004), e.g.
# `flock -u / /bin/sh`. The rule keys on /flock with ` -u ` whose command line
# carries a shell path. Harmless analogue: `flock -u <scratch lockfile> /bin/sh
# -c true` - flock takes (and immediately drops) a lock on a throwaway file in
# /tmp and runs `/bin/sh -c true`, which exits at once. The execve of /flock
# with ' -u ' and '/bin/sh', which the rule keys on, is real.
#
# Imitates (SigmaHQ): proc_creation_lnx_flock_shell_execution.yml - ATT&CK T1059.004
# Expected rule: proc_creation_lnx_flock_shell_execution
set -u

command -v flock >/dev/null 2>&1 || { echo "BANKEN-EMUL-SKIP: no flock"; exit 0; }

lock="/tmp/bk-flock-lock.$$"
: > "$lock" 2>/dev/null || true
flock -u "$lock" /bin/sh -c true >/dev/null 2>&1 || true
rm -f "$lock" 2>/dev/null || true

exit 0
