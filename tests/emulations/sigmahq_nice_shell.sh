#!/usr/bin/env bash
# sigmahq_nice_shell.sh - benign SigmaHQ emulation (see sigmahq_nohup.sh header).
#
# What an attacker does: launch a shell through `nice` so the shell is a child of
# a benign-looking priority wrapper (a GTFOBins-style indirection, T1083/T1059).
# Harmless analogue: `nice /bin/sh` with stdin from /dev/null - the shell reads
# EOF and exits immediately. The execve of nice ending in '/bin/sh', which is
# what the rule keys on, is real.
#
# Imitates (SigmaHQ): proc_creation_lnx_nice_shell_execution.yml - ATT&CK T1083
# Expected rule: proc_creation_lnx_nice_shell_execution
set -u

command -v nice >/dev/null 2>&1 || { echo "BANKEN-EMUL-SKIP: no nice"; exit 0; }

nice /bin/sh </dev/null >/dev/null 2>&1 || true

exit 0
