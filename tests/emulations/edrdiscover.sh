#!/usr/bin/env bash
# edrdiscover.sh - benign emulation of security-software discovery, for detection-rule testing.
#
# What an attacker does: find out which defender is running before evading it - `ps aux | egrep
# 'falcond|osqueryd|...'`, `pgrep -l 'wazuh-agent|...'` (T1518.001). This does the harmless analogue:
# it pgreps/greps for EDR product names (they match nothing on a clean box); the product names in
# argv are the signal. See ./README.md.
#
# Imitates: rules/discovery/security_software_discovery.yml - ATT&CK T1518.001 Security Software Discovery
# Expected rules: security_software_discovery
set -u

# --- TTP: pgrep for an EDR process -> security_software_discovery (tool + edr_names) ---
pgrep falcond >/dev/null 2>&1 || true

# --- TTP: grep for EDR/AV agents -> security_software_discovery (tool + edr_names) ---
grep -E 'osqueryd|wazuh-agent|sentinelone|clamd' /etc/hostname >/dev/null 2>&1 || true

exit 0
