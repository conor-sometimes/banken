#!/usr/bin/env bash
# sigmahq_cp_passwd_or_shadow_tmp.sh - benign SigmaHQ emulation (see sigmahq_nohup.sh header).
#
# What an attacker does: stage a copy of the credential databases somewhere
# world-readable for offline cracking (T1003.008), e.g. `cp /etc/shadow /tmp/`.
# The rule keys on /cp whose command line carries '/tmp/' and 'passwd'/'shadow'.
# Harmless analogue: copy an innocuous file (/etc/hostname) to a /tmp path whose
# NAME merely contains 'passwd' - the real shadow/passwd files are never read.
# The execve of /cp with '/tmp/' and 'passwd', which the rule keys on, is real.
#
# Imitates (SigmaHQ): proc_creation_lnx_cp_passwd_or_shadow_tmp.yml - ATT&CK T1003.008
# Expected rule: proc_creation_lnx_cp_passwd_or_shadow_tmp
set -u

dst="/tmp/bk-passwd-copy.$$"
cp /etc/hostname "$dst" >/dev/null 2>&1 || true
rm -f "$dst" 2>/dev/null || true

exit 0
