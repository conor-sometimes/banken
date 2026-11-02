#!/usr/bin/env bash
# sigmahq_rsync_shell_execution.sh - benign SigmaHQ emulation (see sigmahq_nohup.sh header).
#
# What an attacker does: break out of a restricted context with rsync's remote
# shell option (GTFOBins T1059), e.g. `rsync -e 'sh -c "sh 0<&2 1>&2"' ...`, so
# rsync runs a shell. The rule keys on an Image ending in '/rsync', a command line
# containing ' -e ' AND a shell token ('/sh ', '/bash ', ...). The detection is
# purely name + args, so this runs the stock `true` binary copied under the name
# 'rsync' from a scratch dir in HOME (NOT /tmp or /dev/shm, to avoid the tmp-exec
# rules) with the matching ' -e '/'/bin/sh ' arguments; `true` ignores them, no
# shell is spawned and it exits 0. The execve of an 'rsync' image carrying ' -e '
# and '/sh ', which the rule keys on, is real.
#
# Imitates (SigmaHQ): proc_creation_lnx_rsync_shell_execution.yml - ATT&CK T1059
# Expected rule: proc_creation_lnx_rsync_shell_execution
set -u

src="$(type -P true)"
[ -n "$src" ] || { echo "BANKEN-EMUL-SKIP: no true binary on PATH"; exit 0; }
d="${HOME:-/home/alice}/.bk-emul-rsyncexec.$$"
mkdir -p "$d" 2>/dev/null || { echo "BANKEN-EMUL-SKIP: cannot create scratch dir"; exit 0; }
cp "$src" "$d/rsync" 2>/dev/null || { echo "BANKEN-EMUL-SKIP: cannot stage binary"; exit 0; }
"$d/rsync" -e '/bin/sh -c id' /nonexistent/src /nonexistent/dst >/dev/null 2>&1 || true
rm -rf "$d" 2>/dev/null || true

exit 0
