#!/usr/bin/env bash
# sigmahq_susp_exec_from_dev_shm.sh - benign SigmaHQ emulation (see sigmahq_nohup.sh header).
#
# What an attacker does: run a payload staged in the tmpfs /dev/shm so it never
# touches disk (T1620/T1059), e.g. `/dev/shm/implant`. The rule keys on any
# process whose Image path starts with '/dev/shm/'. Harmless analogue: copy the
# stock `true` binary into /dev/shm, run it (exits 0, does nothing), remove it.
# The execve of an image under /dev/shm/, which the rule keys on, is real.
#
# Imitates (SigmaHQ): proc_creation_lnx_susp_exec_from_dev_shm.yml - ATT&CK T1620
# Expected rule: proc_creation_lnx_susp_exec_from_dev_shm
set -u

src="$(type -P true)"
[ -n "$src" ] || { echo "BANKEN-EMUL-SKIP: no true binary on PATH"; exit 0; }

dst="/dev/shm/bk-shm.$$"
cp "$src" "$dst" >/dev/null 2>&1 || { echo "BANKEN-EMUL-SKIP: cannot write /dev/shm"; exit 0; }
"$dst" >/dev/null 2>&1 || true
rm -f "$dst" 2>/dev/null || true

exit 0
