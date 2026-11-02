#!/usr/bin/env bash
# sigmahq_setgid_setuid.sh - benign SigmaHQ emulation (see sigmahq_nohup.sh header).
#
# What an attacker does: chown a file to root and set its setuid/setgid bit so it
# runs with elevated privilege - a classic privilege-escalation persistence trick
# (T1548.001). Harmless analogue: a single command line that chowns and chmods a
# scratch file in the user's own home; as an unprivileged user both are refused
# (EPERM) and nothing changes - but the execve carrying both 'chown root' and
# ' chmod u+s', which is what the rule keys on, is real. The scratch path is
# deliberately NOT under /tmp, /etc or /opt, so no path-based rule is tripped.
#
# Imitates (SigmaHQ): proc_creation_lnx_setgid_setuid.yml - ATT&CK T1548.001
# Expected rule: proc_creation_lnx_setgid_setuid
set -u

f="$HOME/.sigmaemul_suidbin"
: > "$f" 2>/dev/null || true
bash -c "chown root '$f' && chmod u+s '$f'" >/dev/null 2>&1 || true

exit 0
