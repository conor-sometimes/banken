#!/usr/bin/env bash
# sigmahq_susp_dockerenv_recon.sh - benign SigmaHQ emulation (see sigmahq_nohup.sh header).
#
# What an attacker does: probe for the Docker marker file to decide whether they
# are containerised (T1082), e.g. `ls /.dockerenv` / `cat /.dockerenv`. The rule
# keys on a tool (ls/cat/stat/find/...) whose command line ENDS with '.dockerenv'.
# Harmless analogue: `ls /.dockerenv` on a host where the file does not exist -
# ls just reports "No such file", reading nothing. The execve of /ls ending in
# '.dockerenv', which the rule keys on, is real.
#
# Imitates (SigmaHQ): proc_creation_lnx_susp_dockerenv_recon.yml - ATT&CK T1082
# Expected rule: proc_creation_lnx_susp_dockerenv_recon
set -u

ls /.dockerenv >/dev/null 2>&1 || true

exit 0
