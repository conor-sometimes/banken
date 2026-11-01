#!/usr/bin/env bash
# killlog.sh - benign emulation of disabling host logging, for detection-rule testing.
#
# What an attacker does: blind the host by stopping journald/rsyslog/auditd or an EDR agent, or edit
# journald.conf to stop storing logs (T1562.001). This does the harmless analogue: it edits a SCRATCH
# copy of journald.conf (Storage=none) - never the real one - and `systemctl stop`s a NONEXISTENT
# "-emul-dummy" logging unit (so nothing real is stopped). The real logging stack is never touched;
# the edit/stop exec is the signal. tamper_banken covers banken+auditd; this covers the rest.
# See ./README.md.
#
# Imitates: rules/defense-evasion/disable_logging.yml - ATT&CK T1562.001 Disable or Modify Tools
# Expected rules: disable_logging
set -u
work=$(mktemp -d) || exit 0
trap 'rm -rf "$work" 2>/dev/null' EXIT
printf '[Journal]\nStorage=auto\n' > "$work/journald.conf"

# --- TTP: edit journald.conf to stop storing logs -> disable_logging (journald_conf) ---
if command -v sed >/dev/null 2>&1; then
	sed -i 's/Storage=auto/Storage=none/' "$work/journald.conf" >/dev/null 2>&1 || true
fi

# --- TTP: systemctl stop a (nonexistent) logging unit -> disable_logging (systemctl) ---
# Targets rsyslog-emul-dummy.service, which does not exist: systemctl errors out and no real logging
# unit is stopped. The argv ("stop ... rsyslog") is what the rule matches.
if command -v systemctl >/dev/null 2>&1; then
	systemctl stop rsyslog-emul-dummy.service >/dev/null 2>&1 || true
fi

exit 0
