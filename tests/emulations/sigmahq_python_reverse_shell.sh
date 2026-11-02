#!/usr/bin/env bash
# sigmahq_python_reverse_shell.sh - benign SigmaHQ emulation (see sigmahq_nohup.sh header).
#
# What an attacker does: a python reverse shell one-liner (T1059.004) that
# imports socket, connects back and pty.spawn()s a shell. The rule keys on a
# python ` -c ` whose command line carries all of 'import', 'pty', 'socket',
# 'spawn' and '.connect'. Harmless analogue: `python3 -c` that merely `import
# sys` and carries the marker words inside a trailing comment - no socket is
# opened, nothing connects, nothing is spawned. The words are kept non-adjacent
# so 'import pty' never appears (that would be the pty_spawn rule's indicator).
# The execve of python with the marker words, which the rule keys on, is real.
#
# Imitates (SigmaHQ): proc_creation_lnx_python_reverse_shell.yml - ATT&CK T1059.004
# Expected rule: proc_creation_lnx_python_reverse_shell
set -u

command -v python3 >/dev/null 2>&1 || { echo "BANKEN-EMUL-SKIP: no python3"; exit 0; }

python3 -c 'import sys  # pty socket spawn .connect' >/dev/null 2>&1 || true

exit 0
