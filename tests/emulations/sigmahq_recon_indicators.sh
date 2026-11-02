#!/usr/bin/env bash
# sigmahq_recon_indicators.sh - benign SigmaHQ emulation (see sigmahq_nohup.sh header).
#
# What an attacker does: run privilege-escalation recon one-liners (T1592.004/
# T1552.001), e.g. hunting for web creds with `find / -name .htpasswd` or for
# setuid binaries with `find / -perm -4000`. The rule keys on a command line
# containing ' -name .htpasswd' or ' -perm -4000 '. Harmless analogue:
# `find <HOME> -name .htpasswd` - searches only the user's own home, finds nothing,
# but the execve carrying ' -name .htpasswd', which the rule keys on, is real.
# file_and_directory_discovery (any find) genuinely fires alongside - a legit twin.
#
# Imitates (SigmaHQ): proc_creation_lnx_susp_recon_indicators.yml - ATT&CK T1592.004
# Expected rules: proc_creation_lnx_susp_recon_indicators,
#                 proc_creation_lnx_file_and_directory_discovery
set -u

command -v find >/dev/null 2>&1 || { echo "BANKEN-EMUL-SKIP: no find"; exit 0; }

find "${HOME:-/home/alice}" -name .htpasswd >/dev/null 2>&1 || true

exit 0
