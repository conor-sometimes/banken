#!/usr/bin/env bash
# sigmahq_gobrat_grep.sh - benign SigmaHQ emulation (see sigmahq_nohup.sh header).
#
# What an attacker does: the GobRAT malware uses grep to locate its own dropped
# files (T1082), e.g. grepping for 'frpc', 'apached', 'sshd.sh' or 'zone.arm'.
# The rule keys on /grep whose command line contains one of those names.
# Harmless analogue: `grep frpc /dev/null` - greps an empty source, matches
# nothing, but the execve of /grep with 'frpc', which the rule keys on, is real.
# ('frpc' does not end in an arch string, so grep_os_arch_discovery does not fire.)
#
# Imitates (SigmaHQ): proc_creation_lnx_malware_gobrat_grep_payload_discovery.yml - ATT&CK T1082
# Expected rule: proc_creation_lnx_malware_gobrat_grep_payload_discovery
set -u

command -v grep >/dev/null 2>&1 || { echo "BANKEN-EMUL-SKIP: no grep"; exit 0; }

grep frpc /dev/null >/dev/null 2>&1 || true

exit 0
