#!/usr/bin/env bash
# sigmahq_clipboard_collection.sh - benign SigmaHQ emulation (see sigmahq_nohup.sh header).
#
# What an attacker does: harvest the X clipboard with xclip (T1115), e.g.
# `xclip -selection clipboard -o`, to steal whatever a user copied (passwords,
# tokens). The rule keys on an xclip command line with '-sel', 'clip' and '-o'.
# Harmless analogue: the same invocation on a headless host - with no X display
# xclip errors ("Can't open display") and reads nothing, but the execve of xclip
# with those flags, which the rule keys on, is real.
#
# Imitates (SigmaHQ): proc_creation_lnx_clipboard_collection.yml - ATT&CK T1115
# Expected rule: proc_creation_lnx_clipboard_collection
set -u

command -v xclip >/dev/null 2>&1 || { echo "BANKEN-EMUL-SKIP: no xclip"; exit 0; }

DISPLAY= xclip -selection clipboard -o >/dev/null 2>&1 || true

exit 0
