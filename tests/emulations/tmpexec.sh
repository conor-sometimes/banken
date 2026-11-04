#!/usr/bin/env bash
# tmpexec.sh - benign emulation of a payload executed from a world-writable temp dir, for
# detection-rule testing.
#
# What an attacker does: drop a payload into a scratch dir and run it - either the binary itself
# lives in /tmp, /dev/shm, /var/tmp or /run/user and is exec'd directly, or an interpreter is handed
# a script staged there (`bash /tmp/x.sh`, `python3 /dev/shm/y.py`). This does the harmless
# analogue: it copies the no-op `true` into a /tmp scratch dir under an ordinary name and runs it,
# and writes DUMMY scripts into scratch that just echo and runs them through bash/python. The
# executable LOCATION is the signal; nothing harmful runs and everything is cleaned up on exit.
# A normal binary run from /usr/bin, or an interpreter whose temp path is only inside inline `-c`
# code, is NOT matched. See ./README.md.
#
# Imitates: rules/execution/exec_from_tmp.yml - ATT&CK T1059 Execution (run from a scratch dir)
# Expected rules: exec_from_tmp
set -u
work=$(mktemp -d /tmp/tmpexec.XXXXXX) || exit 0
trap 'rm -rf "$work" 2>/dev/null' EXIT

# type -P (not `command -v`): `true` is a shell builtin, so `command -v true` prints "true", not a
# filesystem path -- `cp true ...` would then fail and TTP (a) below (the bare-ELF drop) would
# silently never run. type -P forces a PATH search for the real binary to copy and exec.
true_bin=$(type -P true 2>/dev/null) || exit 0
[ -n "$true_bin" ] || exit 0

# --- TTP (a): a binary whose own image is under /tmp, run directly -> exec_from_tmp (image_in_tmp).
# An ordinary name (not a daemon name, not a "..." dir), so this is the generic location signal and
# not masquerading. The copy is of `true`, so running it just exits 0. ---
cp "$true_bin" "$work/stage1" >/dev/null 2>&1 && "$work/stage1" >/dev/null 2>&1 || true

# --- TTP (b): an interpreter handed a script PATH under a temp dir -> exec_from_tmp
# (interp_tmp_script). The script just echoes; the signal is `bash /tmp/.../run.sh`. ---
printf '#!/bin/sh\necho benign\n' > "$work/run.sh"
bash "$work/run.sh" >/dev/null 2>&1 || true

# --- TTP (b) via /dev/shm with python (guarded: /dev/shm must be writable and python present) ---
if command -v python3 >/dev/null 2>&1 && [ -w /dev/shm ]; then
	shm=$(mktemp -d /dev/shm/tmpexec.XXXXXX 2>/dev/null) || shm=""
	if [ -n "$shm" ]; then
		printf 'print("benign")\n' > "$shm/calc.py"
		python3 "$shm/calc.py" >/dev/null 2>&1 || true
		rm -rf "$shm" 2>/dev/null || true
	fi
fi

exit 0
