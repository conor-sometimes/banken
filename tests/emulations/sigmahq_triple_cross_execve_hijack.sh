#!/usr/bin/env bash
# sigmahq_triple_cross_execve_hijack.sh - benign SigmaHQ emulation (see sigmahq_nohup.sh header).
#
# What an attacker does: the Triple Cross eBPF rootkit elevates privileges by
# running a helper named 'execve_hijack' via sudo (T1548), i.e. `sudo execve_hijack
# ...`. The rule keys on /sudo whose command line contains 'execve_hijack'.
# Harmless analogue: `sudo -n execve_hijack` as the unprivileged alice - sudo
# runs non-interactively (-n, never prompts), alice is not in sudoers and the
# helper does not exist, so sudo refuses and runs nothing, but the execve of /sudo
# with 'execve_hijack', which the rule keys on, is real. -n guarantees no hang.
#
# Imitates (SigmaHQ): proc_creation_lnx_triple_cross_rootkit_execve_hijack.yml - ATT&CK T1548
# Expected rule: proc_creation_lnx_triple_cross_rootkit_execve_hijack
set -u

command -v sudo >/dev/null 2>&1 || { echo "BANKEN-EMUL-SKIP: no sudo"; exit 0; }

sudo -n execve_hijack >/dev/null 2>&1 || true

exit 0
