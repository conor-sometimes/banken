#!/usr/bin/env bash
# rootca.sh - benign emulation of installing a rogue root CA, for detection-rule testing.
#
# What an attacker does: drop a certificate into the system trust store and rebuild it so the host
# trusts anything they sign - `cp rootCA.crt /etc/pki/ca-trust/source/anchors/ && update-ca-trust`
# (T1553.004), enabling TLS interception. This does the harmless analogue: it copies a DUMMY cert
# into a scratch `.../etc/pki/ca-trust/source/anchors/` tree (removed on exit) - never the real trust
# store, and never runs the rebuild tool; the anchors path in argv is the signal. See ./README.md.
#
# Imitates: rules/defense-evasion/root_ca_installed.yml - ATT&CK T1553.004 Install Root Certificate
# Expected rules: root_ca_installed
set -u
work=$(mktemp -d) || exit 0
trap 'rm -rf "$work" 2>/dev/null' EXIT
mkdir -p "$work/etc/pki/ca-trust/source/anchors" >/dev/null 2>&1 || true
printf -- '-----BEGIN CERTIFICATE-----\nDUMMYNOTREAL\n-----END CERTIFICATE-----\n' > "$work/rootCA.crt"

# --- TTP: copy a cert into the trust-store anchors dir -> root_ca_installed (copy_to_trust) ---
cp "$work/rootCA.crt" "$work/etc/pki/ca-trust/source/anchors/" >/dev/null 2>&1 || true

exit 0
