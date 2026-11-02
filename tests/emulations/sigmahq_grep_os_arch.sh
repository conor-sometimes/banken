#!/usr/bin/env bash
# sigmahq_grep_os_arch.sh - benign SigmaHQ emulation (see sigmahq_nohup.sh header).
#
# What an attacker does: fingerprint the host architecture (T1083/T1082) by
# grepping for a CPU arch token such as 'x86_64'. The rule keys on an execve of
# /grep whose command line ends with an architecture string. Harmless analogue:
# `grep x86_64 </dev/null` - grep reads empty stdin, matches nothing and exits.
# argv stays [grep, x86_64] so the command line ends with 'x86_64'.
#
# Imitates (SigmaHQ): proc_creation_lnx_grep_os_arch_discovery.yml - ATT&CK T1083
# Expected rule: proc_creation_lnx_grep_os_arch_discovery
set -u

command -v grep >/dev/null 2>&1 || { echo "BANKEN-EMUL-SKIP: no grep"; exit 0; }

grep x86_64 </dev/null >/dev/null 2>&1 || true

exit 0
