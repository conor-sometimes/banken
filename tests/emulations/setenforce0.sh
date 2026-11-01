#!/usr/bin/env bash
# setenforce0.sh - benign emulation of disabling mandatory access control, for detection-rule testing.
#
# What an attacker does: turn off SELinux or AppArmor to remove a containment boundary before acting -
# setenforce 0 / Permissive, aa-disable, systemctl stop apparmor, or editing /etc/selinux/config to
# SELINUX=disabled (T1562.001). This does the harmless analogue: it sed-s SELINUX=disabled into a
# SCRATCH selinux config (the string in argv is the signal; the real config is untouched), stops a
# NONEXISTENT "-emul-dummy" apparmor unit, and runs setenforce only if it exists and unprivileged
# (where it cannot change enforcement). No live MAC is ever disabled. See ./README.md.
#
# Imitates: rules/defense-evasion/disable_mac.yml - ATT&CK T1562.001 Disable or Modify Tools
# Expected rules: disable_mac
set -u
work=$(mktemp -d) || exit 0
trap 'rm -rf "$work" 2>/dev/null' EXIT
printf 'SELINUX=enforcing\nSELINUXTYPE=targeted\n' > "$work/selinux.config"

# --- TTP: set SELINUX=disabled in a (scratch) selinux config -> disable_mac (selinux_conf) ---
sed -i 's/SELINUX=enforcing/SELINUX=disabled/' "$work/selinux.config" >/dev/null 2>&1 || true

# --- TTP: systemctl stop a (nonexistent) apparmor unit -> disable_mac (apparmor_systemctl) ---
# Targets apparmor-emul-dummy.service, which does not exist: systemctl errors, nothing real is stopped.
if command -v systemctl >/dev/null 2>&1; then
	systemctl stop apparmor-emul-dummy.service >/dev/null 2>&1 || true
fi

# --- TTP: setenforce 0, only if present AND unprivileged (cannot change enforcement) -> disable_mac (setenforce) ---
# Guarded so a box without SELinux no-ops, and a box with it is never actually set permissive.
if command -v setenforce >/dev/null 2>&1 && [ "$(id -u)" -ne 0 ]; then
	setenforce 0 >/dev/null 2>&1 || true
fi

exit 0
