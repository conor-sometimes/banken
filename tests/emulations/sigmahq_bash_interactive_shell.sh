#!/usr/bin/env bash
# sigmahq_bash_interactive_shell.sh - benign SigmaHQ emulation (see sigmahq_nohup.sh header).
#
# What an attacker does: upgrade to an interactive bash shell after a foothold
# (T1059.004), e.g. `bash -i`. The rule keys on /bash whose command line carries
# ' -i '. Harmless analogue: `bash -i -c true </dev/null` - an interactive bash
# that simply runs `true` and exits, reading from /dev/null so nothing is typed.
# The execve of /bash with ' -i ', which the rule keys on, is real.
#
# Imitates (SigmaHQ): proc_creation_lnx_bash_interactive_shell.yml - ATT&CK T1059.004
# Expected rule: proc_creation_lnx_bash_interactive_shell
set -u

bash -i -c true </dev/null >/dev/null 2>&1 || true

exit 0
