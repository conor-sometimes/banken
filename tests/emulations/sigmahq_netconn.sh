#!/usr/bin/env bash
# sigmahq_netconn.sh - benign SigmaHQ emulation (see sigmahq_nohup.sh header).
#
# What an attacker does: enumerate active connections and logged-in users to
# understand the host's network position (T1049 System Network Connections
# Discovery). Harmless analogue: run a read-only lister (`last`), which only
# reads the login record. Nothing is modified.
#
# Imitates (SigmaHQ): proc_creation_lnx_system_network_connections_discovery.yml - ATT&CK T1049
# Expected rule: proc_creation_lnx_system_network_connections_discovery
set -u

ran=0
for tool in last lsof netstat; do
	if command -v "$tool" >/dev/null 2>&1; then
		case "$tool" in
			last) last -n 1 >/dev/null 2>&1 || true ;;
			lsof) lsof -p $$ >/dev/null 2>&1 || true ;;
			netstat) netstat -tn >/dev/null 2>&1 || true ;;
		esac
		ran=1
		break
	fi
done

[ "$ran" = 0 ] && echo "BANKEN-EMUL-SKIP: no connection lister (last/lsof/netstat) available"

exit 0
