#!/usr/bin/env bash
# sigmahq_sysinfo.sh - benign SigmaHQ emulation (see sigmahq_nohup.sh header).
#
# What an attacker does: fingerprint the host (kernel, CPU, loaded modules) to
# pick an exploit or payload (T1082 System Information Discovery). Harmless
# analogue: run the same read-only discovery binaries. Nothing is modified.
#
# Imitates (SigmaHQ): proc_creation_lnx_system_info_discovery.yml - ATT&CK T1082
# Expected rule: proc_creation_lnx_system_info_discovery
set -u

ran=0
for tool in uname hostname uptime lscpu lsmod; do
	if command -v "$tool" >/dev/null 2>&1; then
		"$tool" >/dev/null 2>&1 || true
		ran=1
	fi
done

[ "$ran" = 0 ] && echo "BANKEN-EMUL-SKIP: no system-info tool (uname/lscpu/lsmod) available"

exit 0
