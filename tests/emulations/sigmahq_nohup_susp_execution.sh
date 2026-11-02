#!/usr/bin/env bash
# sigmahq_nohup_susp_execution.sh - benign SigmaHQ emulation (see sigmahq_nohup.sh header).
#
# What an attacker does: detach a payload staged in /tmp with nohup so it
# survives logout (T1053/T1059.004), e.g. `nohup /tmp/implant &`. This rule is
# the /tmp-location refinement of the base nohup rule, keying on /nohup whose
# command line carries '/tmp/'. Harmless analogue: `nohup cat <nonexistent
# /tmp path>` - cat fails at once, nothing is backgrounded. The execve of
# /nohup with '/tmp/', which the rule keys on, is real. Any nohup at all also
# trips the base proc_creation_lnx_nohup rule (its legitimate twin).
#
# Imitates (SigmaHQ): proc_creation_lnx_nohup_susp_execution.yml - ATT&CK T1059.004
# Expected rules: proc_creation_lnx_nohup_susp_execution, proc_creation_lnx_nohup
set -u

command -v nohup >/dev/null 2>&1 || { echo "BANKEN-EMUL-SKIP: no nohup"; exit 0; }

nohup cat /tmp/bk-nohup-nonexistent.$$ >/dev/null 2>&1 || true

exit 0
