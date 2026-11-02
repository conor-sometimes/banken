#!/usr/bin/env bash
# sigmahq_capsh.sh - benign SigmaHQ emulation (see sigmahq_nohup.sh header).
#
# What an attacker does: use capsh to drop into a shell (a GTFOBins break-out
# that can escape restricted contexts, T1059). Harmless analogue: `capsh --`
# spawns a shell, but with stdin redirected from /dev/null the shell reads EOF
# and exits immediately, running nothing. The execve of capsh ending in ' --',
# which is what the rule keys on, is real.
#
# Imitates (SigmaHQ): proc_creation_lnx_capsh_shell_invocation.yml - ATT&CK T1059
# Expected rule: proc_creation_lnx_capsh_shell_invocation
set -u

command -v capsh >/dev/null 2>&1 || { echo "BANKEN-EMUL-SKIP: no capsh"; exit 0; }

capsh -- </dev/null >/dev/null 2>&1 || true

exit 0
