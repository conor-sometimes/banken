#!/usr/bin/env bash
# sigmahq_python_pty.sh - benign SigmaHQ emulation (see sigmahq_nohup.sh header).
#
# What an attacker does: upgrade a dumb reverse shell to an interactive TTY with
# python's pty module (T1059.004), e.g. `python3 -c 'import pty;
# pty.spawn("/bin/bash")'`. Harmless analogue: the same shape but pty.spawn runs
# `/bin/true`, which exits immediately. The execve of /python3 whose command
# line contains 'import pty' and 'spawn', which the rule keys on, is real.
#
# Imitates (SigmaHQ): proc_creation_lnx_python_pty_spawn.yml - ATT&CK T1059.004
# Expected rule: proc_creation_lnx_python_pty_spawn
set -u

command -v python3 >/dev/null 2>&1 || { echo "BANKEN-EMUL-SKIP: no python3"; exit 0; }

python3 -c 'import pty; pty.spawn("/bin/true")' >/dev/null 2>&1 || true

exit 0
