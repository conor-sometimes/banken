#!/usr/bin/env bash
# sigmahq_susp_execution_tmp_folder.sh - benign SigmaHQ emulation (see sigmahq_nohup.sh header).
#
# What an attacker does: run a dropped payload straight out of /tmp (T1059), e.g.
# `/tmp/implant`. The rule keys on any process whose Image path starts with
# '/tmp/' (bar a nextcloud false positive). Harmless analogue: copy the stock
# `true` binary into /tmp, run it (exits 0, does nothing), remove it. The execve
# of an image under /tmp/, which the rule keys on, is real.
#
# Imitates (SigmaHQ): proc_creation_lnx_susp_execution_tmp_folder.yml - ATT&CK T1059
# Expected rule: proc_creation_lnx_susp_execution_tmp_folder
set -u

src="$(type -P true)"
[ -n "$src" ] || { echo "BANKEN-EMUL-SKIP: no true binary on PATH"; exit 0; }

dst="/tmp/bk-tmp-exec.$$"
cp "$src" "$dst" >/dev/null 2>&1 || { echo "BANKEN-EMUL-SKIP: cannot write /tmp"; exit 0; }
"$dst" >/dev/null 2>&1 || true
rm -f "$dst" 2>/dev/null || true

exit 0
