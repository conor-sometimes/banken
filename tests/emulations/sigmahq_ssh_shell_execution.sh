#!/usr/bin/env bash
# sigmahq_ssh_shell_execution.sh - benign SigmaHQ emulation (see sigmahq_nohup.sh header).
#
# What an attacker does: abuse the ssh client to break out of a restricted shell
# (GTFOBins T1059), e.g. `ssh -o permitlocalcommand=yes -o 'LocalCommand=/bin/sh'
# <host>`, so a shell runs on connection. Harmless analogue: the same option
# shape, but BatchMode and a 1s ConnectTimeout point it at TEST-NET-1 (192.0.2.1,
# RFC 5737, unroutable). LocalCommand only runs on a successful connection, which
# never happens, so /bin/sh is never run. The execve of /ssh whose command line
# carries 'permitlocalcommand=yes' and '/bin/sh', which the rule keys on, is real.
#
# Imitates (SigmaHQ): proc_creation_lnx_ssh_shell_execution.yml - ATT&CK T1059
# Expected rule: proc_creation_lnx_ssh_shell_execution
set -u

command -v ssh >/dev/null 2>&1 || { echo "BANKEN-EMUL-SKIP: no ssh"; exit 0; }

ssh -F /dev/null -o BatchMode=yes -o ConnectTimeout=1 \
    -o permitlocalcommand=yes -o 'LocalCommand=/bin/sh -c true' \
    192.0.2.1 true >/dev/null 2>&1 || true

exit 0
