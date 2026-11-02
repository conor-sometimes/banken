#!/usr/bin/env bash
# sigmahq_find_shell.sh - benign SigmaHQ emulation (see sigmahq_nohup.sh header).
#
# What an attacker does: break out of a restricted context by having find spawn
# a shell (GTFOBins T1059.004), e.g. `find . -exec /bin/sh \;`. Harmless
# analogue: in an empty scratch dir, `find . -maxdepth 0 -exec /bin/sh -c true`
# - this matches only '.' and runs `sh -c true` exactly once. The execve of
# /find whose command line contains ' . ', '-exec' and '/bin/sh', which the rule
# keys on, is real. find also fires file_and_directory_discovery (any /find) -
# a legit twin.
#
# Imitates (SigmaHQ): proc_creation_lnx_find_shell_execution.yml - ATT&CK T1059.004
# Expected rules: proc_creation_lnx_find_shell_execution, proc_creation_lnx_file_and_directory_discovery
set -u

command -v find >/dev/null 2>&1 || { echo "BANKEN-EMUL-SKIP: no find"; exit 0; }

d="$HOME/sigmaemul-findshell"
mkdir -p "$d" 2>/dev/null || true
( cd "$d" && find . -maxdepth 0 -exec /bin/sh -c true \; ) >/dev/null 2>&1 || true

exit 0
