#!/usr/bin/env bash
# pammod.sh - benign emulation of PAM configuration tampering, for detection-rule testing.
#
# What an attacker does: edit a PAM config to insert a module that waves every login through -
# `sed -i "...pam_succeed_if.so uid >= 0..." /etc/pam.d/su-l` (T1556.003), a credential backdoor.
# This does the harmless analogue: it read-only copies a real /etc/pam.d file to scratch (no edit of
# the live file, like auditconf.sh does), and seds a pam_*.so rule into a DUMMY scratch file; the
# /etc/pam.d path and the pam_*.so token in argv are the signal. See ./README.md.
#
# Imitates: rules/credential-access/pam_config_modification.yml - ATT&CK T1556.003 Pluggable Auth Modules
# Expected rules: pam_config_modification
set -u
work=$(mktemp -d) || exit 0
trap 'rm -rf "$work" 2>/dev/null' EXIT
: > "$work/pamrule"

# --- TTP: read a real PAM config (read-only copy) -> pam_config_modification (editor + pam_path) ---
cp /etc/pam.d/other "$work/pam.d-other.bak" >/dev/null 2>&1 \
	|| cp /etc/pam.conf "$work/pam.conf.bak" >/dev/null 2>&1 \
	|| cp /etc/pam.d/su "$work/pam.d-su.bak" >/dev/null 2>&1 || true

# --- TTP: drop a permissive PAM module rule into a scratch file -> pam_config_modification (editor + pam_module) ---
sed -i '1s,^,auth sufficient pam_succeed_if.so uid >= 0\n,' "$work/pamrule" >/dev/null 2>&1 || true

exit 0
