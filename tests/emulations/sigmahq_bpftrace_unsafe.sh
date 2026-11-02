#!/usr/bin/env bash
# sigmahq_bpftrace_unsafe.sh - benign SigmaHQ emulation (see sigmahq_nohup.sh header).
#
# What an attacker does: run bpftrace with its '--unsafe' option (T1059.004), which
# lets a bpftrace script shell out via system() - handy for offensive BPF tooling.
# The rule keys on an image ending 'bpftrace' with '--unsafe' on the command line.
# Harmless analogue: bpftrace is a heavy LLVM closure and the detection is purely
# name + flag, so this runs the stock `true` binary copied under a name ending
# 'bpftrace' from a scratch dir in HOME (NOT /tmp or /dev/shm, to avoid the
# tmp-exec rules) with '--unsafe'; true ignores the flag and exits 0, no BPF is
# loaded. The execve of a 'bpftrace' image with '--unsafe', which the rule keys
# on, is real.
#
# Imitates (SigmaHQ): proc_creation_lnx_bpftrace_unsafe_option_usage.yml - ATT&CK T1059.004
# Expected rule: proc_creation_lnx_bpftrace_unsafe_option_usage
set -u

src="$(type -P true)"
[ -n "$src" ] || { echo "BANKEN-EMUL-SKIP: no true binary on PATH"; exit 0; }
d="${HOME:-/home/alice}/.bk-emul-bpftrace.$$"
mkdir -p "$d" 2>/dev/null || { echo "BANKEN-EMUL-SKIP: cannot create scratch dir"; exit 0; }
cp "$src" "$d/bpftrace" 2>/dev/null || { echo "BANKEN-EMUL-SKIP: cannot stage binary"; exit 0; }
"$d/bpftrace" --unsafe -e 'BEGIN { exit(); }' >/dev/null 2>&1 || true
rm -rf "$d" 2>/dev/null || true

exit 0
