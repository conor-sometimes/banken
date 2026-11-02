#!/usr/bin/env bash
# sigmahq_remote_discovery.sh - benign SigmaHQ emulation (see sigmahq_nohup.sh header).
#
# What an attacker does: probe other hosts on the local network to find pivot
# targets (T1018 Remote System Discovery) - arp -a, or ping sweeps of RFC1918 /
# loopback ranges. Harmless analogue: a single ICMP echo to loopback
# (127.0.0.1); it leaves no network and reaches nothing remote.
#
# Imitates (SigmaHQ): proc_creation_lnx_remote_system_discovery.yml - ATT&CK T1018
# Expected rule: proc_creation_lnx_remote_system_discovery
set -u

if command -v ping >/dev/null 2>&1; then
	ping -c 1 -W 1 127.0.0.1 >/dev/null 2>&1 || true
elif command -v arp >/dev/null 2>&1; then
	arp -a >/dev/null 2>&1 || true
else
	echo "BANKEN-EMUL-SKIP: no ping/arp available"
fi

exit 0
