#!/usr/bin/env bash
# sigmahq_mkfifo_named_pipe_creation_susp_location.sh - benign SigmaHQ emulation (see sigmahq_nohup.sh header).
#
# What an attacker does: create a named pipe in a suspicious location (e.g. /tmp)
# to wire up a reverse shell (T1059.004), e.g. `mkfifo /tmp/f`. This rule is the
# /tmp-location refinement of the base mkfifo rule, keying on /mkfifo whose
# command line carries ' /tmp/'. Harmless analogue: create a fifo in /tmp and
# immediately remove it - nothing ever reads or writes it. The execve of /mkfifo
# with ' /tmp/', which the rule keys on, is real. Any mkfifo at all also trips
# the base proc_creation_lnx_mkfifo_named_pipe_creation rule (its legitimate twin).
#
# Imitates (SigmaHQ): proc_creation_lnx_mkfifo_named_pipe_creation_susp_location.yml - ATT&CK T1059.004
# Expected rules: proc_creation_lnx_mkfifo_named_pipe_creation_susp_location, proc_creation_lnx_mkfifo_named_pipe_creation
set -u

command -v mkfifo >/dev/null 2>&1 || { echo "BANKEN-EMUL-SKIP: no mkfifo"; exit 0; }

fifo="/tmp/bk-fifo.$$"
mkfifo "$fifo" >/dev/null 2>&1 || true
rm -f "$fifo" 2>/dev/null || true

exit 0
