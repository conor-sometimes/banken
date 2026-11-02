#!/usr/bin/env bash
# sigmahq_install_suspicious_packages.sh - benign SigmaHQ emulation (see sigmahq_nohup.sh header).
#
# What an attacker does: install offensive tooling (nmap, netcat, socat, ...) via
# a package manager on a compromised host (T1553.004), e.g. `dpkg -i nmap.deb`.
# The rule keys on a package tool (apt/yum/rpm/dpkg) with an install flag plus one
# of a set of tool keywords ('nmap', 'socat', ...). Harmless analogue: `dpkg -i`
# on a nonexistent '*nmap*.deb' in a scratch dir - dpkg errors immediately (no such
# file), nothing is installed, but the execve of /dpkg with '-i' and 'nmap', which
# the rule keys on, is real.
#
# Imitates (SigmaHQ): proc_creation_lnx_install_suspicious_packages.yml - ATT&CK T1553.004
# Expected rule: proc_creation_lnx_install_suspicious_packages
set -u

command -v dpkg >/dev/null 2>&1 || { echo "BANKEN-EMUL-SKIP: no dpkg"; exit 0; }

dpkg -i "/var/empty/nonexistent-nmap-$$.deb" >/dev/null 2>&1 || true

exit 0
