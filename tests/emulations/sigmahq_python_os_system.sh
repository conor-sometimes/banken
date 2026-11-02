#!/usr/bin/env bash
# sigmahq_python_os_system.sh - benign SigmaHQ emulation (see sigmahq_nohup.sh header).
#
# What an attacker does: shell out from python with os.system to run a shell
# (GTFOBins T1059.004 / T1059.006), e.g. `python3 -c 'import os;
# os.system("/bin/sh")'`. Harmless analogue: the same shape but the shell runs
# `true` and exits. The execve of /python3 whose command line contains ' -c ',
# 'os.system(' and '/bin/sh', which the rule keys on, is real.
#
# Imitates (SigmaHQ): proc_creation_lnx_python_shell_os_system.yml - ATT&CK T1059.004
# Expected rule: proc_creation_lnx_python_shell_os_system
set -u

command -v python3 >/dev/null 2>&1 || { echo "BANKEN-EMUL-SKIP: no python3"; exit 0; }

python3 -c 'import os; os.system("/bin/sh -c true")' >/dev/null 2>&1 || true

exit 0
