#!/usr/bin/env bash
# tamper.sh — benign emulation of defense-evasion / anti-banken tampering for detection-rule testing.
#
# What an attacker does once they have a foothold: turn the watchdog off — stop/disable the banken
# service, kill its process, delete its unit or binary, flush the audit rules that feed it. This
# does the harmless analogue: it generates the SAME exec events WITHOUT stopping, killing or
# deleting anything real. Every service/process name it targets is a nonexistent "-emul-dummy"
# sentinel, every file it removes is in its own mktemp scratch, and auditctl is only run
# unprivileged (where it cannot actually flush anything). The real banken and auditd are never
# touched. See ./README.md and the safety contract there.
#
# Imitates: ATT&CK T1562 Impair Defenses (stop/kill/remove banken, flush auditd)
# Expected rules: tamper_banken
set -u
work=$(mktemp -d) || exit 0
trap 'rm -rf "$work" 2>/dev/null' EXIT

# --- TTP: systemctl stop a (nonexistent) banken unit -> tamper_banken (systemctl_banken) ---
# Targets banken-emul-dummy.service, which does not exist: systemctl errors out, the REAL banken
# unit is never touched. The argv ("stop ... banken") is what the rule matches.
if command -v systemctl >/dev/null 2>&1; then
	systemctl stop banken-emul-dummy.service >/dev/null 2>&1 || true
fi

# --- TTP: pkill a (nonexistent) banken process -> tamper_banken (kill_tool / kill_cmd) ---
# -f against a sentinel pattern that matches no running process: kills nothing, exits non-zero.
pkill -f banken-emul-dummy-process >/dev/null 2>&1 || true

# --- TTP: remove banken's unit file -> tamper_banken (edit_unit_or_binary) ---
# a dummy file in scratch named like the real unit; rm's argv contains banken.service.
: > "$work/banken.service"
rm -f "$work/banken.service" >/dev/null 2>&1 || true

# --- TTP: flush audit rules -> tamper_banken (auditctl_flush) ---
# ONLY when unprivileged: auditctl -D needs CAP_AUDIT_CONTROL, so as a normal user it fails with
# "permission denied" and changes nothing — a harmless attempt that still emits the /auditctl exec.
# Never run as root, where it WOULD actually blind the audit pipeline (safety contract).
if command -v auditctl >/dev/null 2>&1 && [ "$(id -u)" -ne 0 ]; then
	auditctl -D >/dev/null 2>&1 || true
fi

exit 0
