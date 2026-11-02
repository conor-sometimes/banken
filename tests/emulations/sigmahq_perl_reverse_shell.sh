#!/usr/bin/env bash
# sigmahq_perl_reverse_shell.sh - benign SigmaHQ emulation (see sigmahq_nohup.sh header).
#
# What an attacker does: a perl reverse shell one-liner (T1059.004), e.g.
# `perl -e 'use Socket;...connect(...);open(...);exec("/bin/sh -i");'`. The rule
# keys on `perl -e` whose command line carries the Socket/connect/open/exec words.
# Harmless analogue: `perl -e` with those words appearing only inside a dead
# string literal, so no socket is opened, nothing connects and nothing is exec'd.
# The execve of /perl with ' -e ' and the marker words, which the rule keys on,
# is real.
#
# Imitates (SigmaHQ): proc_creation_lnx_perl_reverse_shell.yml - ATT&CK T1059.004
# Expected rule: proc_creation_lnx_perl_reverse_shell
set -u

command -v perl >/dev/null 2>&1 || { echo "BANKEN-EMUL-SKIP: no perl"; exit 0; }

# The one statement is a bare string constant: evaluated, discarded, no effect.
perl -e '"Socket connect open exec"' >/dev/null 2>&1 || true

exit 0
