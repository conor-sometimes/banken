#!/usr/bin/env bash
# agentssh.sh - benign emulation of an agent account reading SSH files, for detection-rule testing.
#
# What an attacker does: a compromised agent reads SSH material - a private key (theft), config /
# known_hosts (recon on where to move next), or appends to authorized_keys (a planted backdoor). This
# does the harmless analogue: it creates a DUMMY ~/.ssh ENTIRELY INSIDE its own scratch dir and
# reads/writes those, never a real key. The access of an .ssh path is the signal; no real secret is
# touched. See ./README.md.
#
# Account-scoped: rules/agent/agent_ssh_access.yml keys on User in {claude,redteam,lab}, so this only
# fires when run AS an agent account; for an ordinary login, which reads ~/.ssh constantly, it is
# inert by design (it is the *who*, not the file, that makes it signal).
#
# Imitates: rules/agent/agent_ssh_access.yml - ATT&CK T1552.004 Private Keys / T1018 (agent account)
# Expected rules: agent_ssh_access
set -u
work=$(mktemp -d) || exit 0
trap 'rm -rf "$work" 2>/dev/null' EXIT

mkdir -p "$work/.ssh"
printf 'Host example\n  User x\n' > "$work/.ssh/config"
printf '# dummy known_hosts\n' > "$work/.ssh/known_hosts"
printf -- '-----BEGIN OPENSSH PRIVATE KEY-----\nDUMMYNOTREAL\n-----END OPENSSH PRIVATE KEY-----\n' > "$work/.ssh/id_rsa"

# --- TTP: read an .ssh file with a known reader -> agent_ssh_access (reader + reader_ssh) ---
cat "$work/.ssh/config" >/dev/null 2>&1 || true
cat "$work/.ssh/known_hosts" >/dev/null 2>&1 || true
cat "$work/.ssh/id_rsa" >/dev/null 2>&1 || true

# --- TTP: append to authorized_keys, i.e. plant a backdoor key (scratch) -> agent_ssh_access (ssh_file) ---
# (tee is not in the reader list, so this branch fires via the TargetFilename watch on /.ssh/, not argv.)
echo '# emul harmless marker' | tee -a "$work/.ssh/authorized_keys" >/dev/null 2>&1 || true

exit 0
