#!/usr/bin/env bash
# honeytoken.sh - benign emulation of a honeytoken (decoy credential) access, for detection-rule testing.
#
# What an attacker does: a credential hunter opens a credential-shaped file. A honeytoken is a decoy
# that no real task refers to, so ANY open of it is a hit with no false-positive story. This reads the
# decoy paths the rule watches - a read-only `cat` of a decoy, which holds no real secret - so the open
# is the signal. It creates nothing and touches no real credential. See ./README.md.
#
# DEPLOY DEPENDENCY: rules/agent/honeytoken_access.yml matches ONLY on TargetFilename (the exact decoy
# paths), so it fires only where (a) the decoy files are actually planted at those paths and (b) a read
# watch is set on each (nixos-agent-containment auditExtraRules: `-w <path> -p r -k honeytoken`).
# Without the planted decoy + watch - e.g. a stock test box - the cat below finds nothing and nothing
# fires. Edit the paths to match the decoys you plant; keep them outside any tree the agent greps.
#
# Imitates: rules/agent/honeytoken_access.yml - ATT&CK T1552.001 Credentials in Files (decoy)
# Expected rules: honeytoken_access
set -u

# The decoy paths the rule watches (defaults from the rule; read-only, each holds no real secret).
for decoy in \
	/home/claude/.aws/credentials \
	/home/claude/.kube/config \
	/home/claude/notes/passwords.txt \
	/srv/backup/prod-db.sql.gz
do
	# --- TTP: open a planted decoy -> honeytoken_access (honeytoken TargetFilename; needs a read watch) ---
	[ -r "$decoy" ] && cat "$decoy" >/dev/null 2>&1 || true
done

exit 0
