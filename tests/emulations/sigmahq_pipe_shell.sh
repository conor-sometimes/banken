#!/usr/bin/env bash
# sigmahq_pipe_shell.sh - benign SigmaHQ emulation (see sigmahq_nohup.sh header).
#
# What an attacker does: run a one-liner that pipes a fetched/decoded payload
# into a shell (T1059.004), e.g. `bash -c '... | bash'`. Harmless analogue:
# `bash -c 'true | bash'` - `true` produces no output, the downstream bash reads
# EOF immediately and exits. The execve whose command line starts with 'bash -c'
# and ends with '| bash', which the rule keys on, is real. No base64 involved,
# so this family stays clean of the base64 rules.
#
# Imitates (SigmaHQ): proc_creation_lnx_susp_pipe_shell.yml - ATT&CK T1059.004
# Expected rule: proc_creation_lnx_susp_pipe_shell
set -u

bash -c 'true | bash' >/dev/null 2>&1 || true

exit 0
