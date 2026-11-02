#!/usr/bin/env bash
# sigmahq_chattr.sh - benign SigmaHQ emulation (see sigmahq_nohup.sh header).
#
# What an attacker does: clear the immutable bit on a protected file so it can be
# tampered with or deleted (T1222.002). Harmless analogue: run `chattr -i` on a
# scratch file in the user's own home. As an unprivileged user the attribute
# change is refused (EPERM) and nothing changes - but the execve, which is what
# the rule keys on, is real.
#
# Imitates (SigmaHQ): proc_creation_lnx_chattr_immutable_removal.yml - ATT&CK T1222.002
# Expected rule: proc_creation_lnx_chattr_immutable_removal
set -u

command -v chattr >/dev/null 2>&1 || { echo "BANKEN-EMUL-SKIP: no chattr"; exit 0; }

f="$HOME/.sigmaemul_immutable"
: > "$f" 2>/dev/null || true
chattr -i "$f" >/dev/null 2>&1 || true

exit 0
