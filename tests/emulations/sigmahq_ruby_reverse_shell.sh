#!/usr/bin/env bash
# sigmahq_ruby_reverse_shell.sh - benign SigmaHQ emulation (see sigmahq_nohup.sh header).
#
# What an attacker does: a ruby reverse shell one-liner (T1059.004) built on
# TCPSocket, e.g. `ruby -rsocket -e 'c=TCPSocket.new(...);exec "bash -i"...'`.
# The rule keys on a ruby ` -e` whose command line carries 'rsocket', 'TCPSocket'
# and a shell name. Harmless analogue: the same words only inside a dead string
# literal, so no socket is created and nothing executes. The execve of ruby with
# ' -e', 'rsocket', 'TCPSocket' and ' bash', which the rule keys on, is real.
#
# Imitates (SigmaHQ): proc_creation_lnx_ruby_reverse_shell.yml - ATT&CK T1059.004
# Expected rule: proc_creation_lnx_ruby_reverse_shell
set -u

command -v ruby >/dev/null 2>&1 || { echo "BANKEN-EMUL-SKIP: no ruby"; exit 0; }

ruby -e '"rsocket TCPSocket bash"' >/dev/null 2>&1 || true

exit 0
