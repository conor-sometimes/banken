#!/usr/bin/env bash
# sigmahq_base64_exec.sh - benign SigmaHQ emulation (see sigmahq_nohup.sh header).
#
# What an attacker does: decode a base64 payload and pipe it straight into a
# shell (T1140 / T1059.004), e.g. `echo <b64> | base64 -d | bash`. Harmless
# analogue: the blob 'dHJ1ZQ==' decodes to the no-op `true`, so the downstream
# bash runs nothing but `true`. The execve whose command line contains 'base64 '
# and ends with '| bash', which the rule keys on, is real. Running through
# `bash -c` with a pipe also trips susp_pipe_shell, and `base64 -d` trips
# base64_decode - both legit twins of the same one-liner.
#
# Imitates (SigmaHQ): proc_creation_lnx_base64_execution.yml - ATT&CK T1140
# Expected rules: proc_creation_lnx_base64_execution, proc_creation_lnx_base64_decode, proc_creation_lnx_susp_pipe_shell
set -u

command -v base64 >/dev/null 2>&1 || { echo "BANKEN-EMUL-SKIP: no base64"; exit 0; }

bash -c 'echo dHJ1ZQ== | base64 -d | bash' >/dev/null 2>&1 || true

exit 0
