#!/usr/bin/env bash
# sigmahq_bpf_kprobe.sh - benign SigmaHQ emulation (see sigmahq_nohup.sh header).
#
# What an attacker does: enable a kprobe event through the debugfs tracing
# interface to hook kernel functions (stealth/execution), e.g.
# `echo 1 > /sys/kernel/debug/tracing/events/kprobes/myprobe/enable`. The rule
# keys on one command line containing 'echo 1 >',
# '/sys/kernel/debug/tracing/events/kprobes/' and '/myprobe/enable' (or
# '/myretprobe/enable'). Harmless analogue: the same `bash -c 'echo 1 > ...'` as
# the unprivileged alice - the redirection target does not exist / is not writable,
# so the write fails (ENOENT/EACCES) and no probe is enabled, but the execve of
# the shell carrying that exact command line, which the rule keys on, is real.
#
# Imitates (SigmaHQ): proc_creation_lnx_bpf_kprob_tracing_enabled.yml - ATT&CK (execution/stealth)
# Expected rule: proc_creation_lnx_bpf_kprob_tracing_enabled
set -u

command -v bash >/dev/null 2>&1 || { echo "BANKEN-EMUL-SKIP: no bash"; exit 0; }

bash -c 'echo 1 > /sys/kernel/debug/tracing/events/kprobes/myprobe/enable' >/dev/null 2>&1 || true

exit 0
