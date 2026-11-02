#!/usr/bin/env bash
# servicestop.sh - benign emulation of stopping/disabling a service, for detection-rule testing.
#
# What an attacker does: stop or disable a service to disrupt availability or clear the way before
# acting - `systemctl stop cron` (T1489). This does the harmless analogue: it asks systemctl to stop
# a nonexistent dummy unit (systemctl errors, nothing real is touched); the stop verb in argv is the
# signal. The defense services (logging, banken/auditd, firewall, AppArmor) are carved out of this
# rule and owned by their own rules, so this fires only on a non-defense stop. See ./README.md.
#
# Imitates: rules/impact/service_stop.yml - ATT&CK T1489 Service Stop
# Expected rules: service_stop
set -u

# --- TTP: systemctl stop a (nonexistent) service -> service_stop (systemctl, not defense) ---
if command -v systemctl >/dev/null 2>&1; then
	systemctl stop cups-emul-dummy.service >/dev/null 2>&1 || true
fi

exit 0
