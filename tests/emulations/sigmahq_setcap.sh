#!/usr/bin/env bash
# sigmahq_setcap.sh - benign SigmaHQ emulation (see sigmahq_nohup.sh header).
#
# What an attacker does: grant a file a dangerous capability with setcap so an
# unprivileged binary can escalate (cap_setuid / cap_setgid lets a process change
# its uid/gid). Harmless analogue: run setcap for each capability against a scratch
# file in the user's own home. As an unprivileged user the change is refused
# (EPERM, needs CAP_SETFCAP) and nothing changes - but the two execves, carrying
# the 'cap_setuid'/'cap_setgid' indicators the rules key on, are real.
#
# Imitates (SigmaHQ): proc_creation_lnx_cap_setuid.yml, proc_creation_lnx_cap_setgid.yml
#   ATT&CK T1548.001
# Expected rules: proc_creation_lnx_cap_setuid, proc_creation_lnx_cap_setgid
set -u

command -v setcap >/dev/null 2>&1 || { echo "BANKEN-EMUL-SKIP: no setcap"; exit 0; }

f="$HOME/.sigmaemul_capbin"
: > "$f" 2>/dev/null || true
setcap cap_setuid+ep "$f" >/dev/null 2>&1 || true
setcap cap_setgid+ep "$f" >/dev/null 2>&1 || true

exit 0
