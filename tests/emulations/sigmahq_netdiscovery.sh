#!/usr/bin/env bash
# sigmahq_netdiscovery.sh - benign SigmaHQ emulation (see sigmahq_nohup.sh header).
#
# What an attacker does: read the host's network configuration - interfaces,
# routes, firewall, DNS - to plan lateral movement (T1016 System Network
# Configuration Discovery). Harmless analogue: `ip addr show`, read-only.
#
# Imitates (SigmaHQ): proc_creation_lnx_system_network_discovery.yml - ATT&CK T1016
# Expected rule: proc_creation_lnx_system_network_discovery
set -u

if command -v ip >/dev/null 2>&1; then
	ip addr show >/dev/null 2>&1 || true
elif command -v ifconfig >/dev/null 2>&1; then
	ifconfig -a >/dev/null 2>&1 || true
else
	echo "BANKEN-EMUL-SKIP: no ip/ifconfig available"
fi

exit 0
