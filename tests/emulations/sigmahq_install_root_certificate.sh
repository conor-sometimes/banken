#!/usr/bin/env bash
# sigmahq_install_root_certificate.sh - benign SigmaHQ emulation (see sigmahq_nohup.sh header).
#
# What an attacker does: install a rogue root CA so their C2/TLS MITM is trusted
# (T1553.004), by running the system trust-store updater `update-ca-certificates`
# (Debian) or `update-ca-trust` (RHEL). The rule keys purely on the Image name of
# that updater. Harmless analogue: run the real updater if present (as an
# unprivileged user it cannot modify the trust store and no-ops/errors); if the
# binary is not in nixpkgs, run the stock `true` binary copied under a name ending
# '/update-ca-certificates' from a scratch dir in HOME (NOT /tmp or /dev/shm, to
# avoid the tmp-exec rules). Either way the execve of an image ending
# '/update-ca-certificates', which is all the rule keys on, is real.
#
# Imitates (SigmaHQ): proc_creation_lnx_install_root_certificate.yml - ATT&CK T1553.004
# Expected rule: proc_creation_lnx_install_root_certificate
set -u

real="$(type -P update-ca-certificates || type -P update-ca-trust)"
if [ -n "$real" ]; then
  "$real" >/dev/null 2>&1 || true
  exit 0
fi

src="$(type -P true)"
[ -n "$src" ] || { echo "BANKEN-EMUL-SKIP: no true binary on PATH"; exit 0; }
d="${HOME:-/home/alice}/.bk-emul-rootca.$$"
mkdir -p "$d" 2>/dev/null || { echo "BANKEN-EMUL-SKIP: cannot create scratch dir"; exit 0; }
cp "$src" "$d/update-ca-certificates" 2>/dev/null || { echo "BANKEN-EMUL-SKIP: cannot stage binary"; exit 0; }
"$d/update-ca-certificates" >/dev/null 2>&1 || true
rm -rf "$d" 2>/dev/null || true

exit 0
