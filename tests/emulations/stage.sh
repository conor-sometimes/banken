#!/usr/bin/env bash
# stage.sh - benign emulation of data staged (archived/encrypted) for exfil, for detection-rule testing.
#
# What an attacker does: encrypt an archive or bundle a sensitive source as the staging step before
# exfil - zip --password, gpg --symmetric, openssl enc, or tar of the auth logs / etc (T1560.001).
# This does the harmless analogue: it openssl-enc-s DUMMY data in its own scratch dir (and zip -P-s it
# if zip is present); nothing sensitive is read and the output is removed on exit. The encrypt argv is
# the signal. See ./README.md.
#
# Imitates: rules/collection/data_staged_for_exfil.yml - ATT&CK T1560.001 Archive via Utility
# Expected rules: data_staged_for_exfil
set -u
work=$(mktemp -d) || exit 0
trap 'rm -rf "$work" 2>/dev/null' EXIT
printf 'dummy loot (harmless)\n' > "$work/loot"

# --- TTP: encrypt data (exfil / ransomware prep) -> data_staged_for_exfil (archive_encrypt) ---
if command -v openssl >/dev/null 2>&1; then
	openssl enc -aes-256-cbc -pass pass:dummy -in "$work/loot" -out "$work/loot.enc" >/dev/null 2>&1 || true
fi

# --- TTP: zip with a password (encrypted archive) -> data_staged_for_exfil (archive_encrypt) ---
if command -v zip >/dev/null 2>&1; then
	zip -P dummy "$work/loot.zip" "$work/loot" >/dev/null 2>&1 || true
fi

exit 0
