#!/usr/bin/env bash
# sigmahq_env_shell.sh - benign SigmaHQ emulation (see sigmahq_nohup.sh header).
#
# What an attacker does: use `env` to spawn a shell (a GTFOBins break-out that
# also lets you reset the environment, T1059). Harmless analogue: `env /bin/sh`
# with stdin from /dev/null - the shell reads EOF and exits immediately. The
# execve of env carrying '/bin/sh', which is what the rule keys on, is real.
#
# Imitates (SigmaHQ): proc_creation_lnx_env_shell_invocation.yml - ATT&CK T1059
# Expected rule: proc_creation_lnx_env_shell_invocation
set -u

command -v env >/dev/null 2>&1 || { echo "BANKEN-EMUL-SKIP: no env"; exit 0; }

env /bin/sh </dev/null >/dev/null 2>&1 || true

exit 0
