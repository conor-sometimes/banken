#!/usr/bin/env bash
# gtfointerp.sh - benign emulation of a GTFOBins interpreter one-liner, for detection-rule testing.
#
# What an attacker does: use an inline interpreter program to run a command or spawn a shell -
# `python3 -c 'os.system("...")'`, `perl -e 'exec "/bin/sh"'`, `awk 'BEGIN{system(...)}'`. This does
# the harmless analogue: it runs the SAME idioms but the command is `true` / `/bin/true` (a no-op).
# The command-exec idiom in the inline argv is the signal; nothing of consequence runs. The
# socket/connect reverse-shell idioms are left to revshell.sh / reverse_shell.yml. See ./README.md.
#
# Imitates: rules/execution/gtfobin_interpreter_exec.yml - ATT&CK T1059 / T1059.006 / T1202
# Expected rules: gtfobin_interpreter_exec
set -u

# --- TTP: python -c os.system() -> gtfobin_interpreter_exec (exec_idiom os.system) ---
if command -v python3 >/dev/null 2>&1; then
	python3 -c 'import os;os.system("true")' >/dev/null 2>&1 || true
fi

# --- TTP: perl -e exec a binary -> gtfobin_interpreter_exec (exec_idiom exec /bin/) ---
# (awk BEGIN{system} is deliberately left to gtfoshell.sh - it belongs to gtfobin_shell_spawn's
# awk_system branch, and firing it here would cross into that rule.)
if command -v perl >/dev/null 2>&1; then
	perl -e 'exec "/bin/true"' >/dev/null 2>&1 || true
fi

exit 0
