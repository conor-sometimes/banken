#!/usr/bin/env bash
# torstart.sh - benign emulation of starting the Tor client, for detection-rule testing.
#
# What an attacker does: start Tor to anonymise C2 and defeat egress controls - `systemctl start
# tor` (T1090.003). This does the harmless analogue: it asks systemctl to start a nonexistent
# tor-emul dummy unit (systemctl errors, nothing starts); the `tor` + start verb in argv is the
# signal. tunnel_tool covers the other relays; this covers Tor. See ./README.md.
#
# Imitates: rules/command-and-control/tor_usage.yml - ATT&CK T1090.003 Multi-hop Proxy (Tor)
# Expected rules: tor_usage
set -u

# --- TTP: systemctl start the tor service -> tor_usage (tor_service + tor_action) ---
if command -v systemctl >/dev/null 2>&1; then
	systemctl start tor-emul-nonexistent.service >/dev/null 2>&1 || true
fi

exit 0
