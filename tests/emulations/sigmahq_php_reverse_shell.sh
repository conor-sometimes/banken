#!/usr/bin/env bash
# sigmahq_php_reverse_shell.sh - benign SigmaHQ emulation (see sigmahq_nohup.sh header).
#
# What an attacker does: a php reverse shell one-liner (T1059.004), e.g.
# `php -r '$s=fsockopen(...);exec("/bin/sh -i <&3 >&3 2>&3");'`. The rule keys on
# `php -r` whose command line carries 'fsockopen' and a shell name. Harmless
# analogue: `php -r` with those words only inside a dead string literal, so no
# socket is opened and nothing executes. The execve of /php with ' -r ',
# 'fsockopen' and 'bash', which the rule keys on, is real.
#
# Imitates (SigmaHQ): proc_creation_lnx_php_reverse_shell.yml - ATT&CK T1059.004
# Expected rule: proc_creation_lnx_php_reverse_shell
set -u

command -v php >/dev/null 2>&1 || { echo "BANKEN-EMUL-SKIP: no php"; exit 0; }

php -r '"fsockopen bash";' >/dev/null 2>&1 || true

exit 0
