#!/usr/bin/env bash
# auditconf.sh - benign emulation of audit/syslog config tampering, for detection-rule testing.
#
# What an attacker does: quietly edit the audit or syslog config on disk (/etc/audit, /etc/audisp,
# /etc/rsyslog, /etc/syslog-ng) so the service keeps running but stops recording the events they care
# about (T1562.006). This does the harmless analogue: it cp-s the REAL config to a scratch copy (a
# read-only reference that names the real path in argv, which is what the rule matches) and then
# edits only the SCRATCH copy, never the real file. disable_logging covers stopping the service;
# tamper_banken covers auditctl flushing live rules; this is the on-disk config edit. See ./README.md.
#
# Imitates: rules/defense-evasion/audit_config_tamper.yml - ATT&CK T1562.006 Indicator Blocking
# Expected rules: audit_config_tamper
set -u
work=$(mktemp -d) || exit 0
trap 'rm -rf "$work" 2>/dev/null' EXIT

# --- TTP: reference the real audit config with a file tool -> audit_config_tamper (editor + config_cmd) ---
# cp READS the real /etc/audit/auditd.conf into scratch (fails harmlessly if unreadable); the real
# file is never written. The argv (a file tool naming /etc/audit) is the signal.
cp /etc/audit/auditd.conf "$work/auditd.conf" >/dev/null 2>&1 || true
cp /etc/rsyslog.conf "$work/rsyslog.conf" >/dev/null 2>&1 || true

# --- benign analogue of the actual tamper: the edit lands only on the SCRATCH copy ---
sed -i 's/$/ # emul harmless/' "$work/rsyslog.conf" >/dev/null 2>&1 || true

exit 0
