#!/usr/bin/env bash
# destructive.sh - benign emulation of an agent running a destructive git/filesystem action, for detection-rule testing.
#
# What an attacker (or a derailed agent) does: force-push, delete branches, expire the reflog to
# destroy history, hard-reset far back, `git clean -fdx`, or rm -rf a repo - empirically the most
# common real agent harm. This does the harmless analogue: every git command runs INSIDE a throwaway
# scratch repo and targets a NONEXISTENT branch (so it errors and changes nothing); no real repo,
# remote or path is touched. The destructive argv is the signal. See ./README.md.
#
# Account-scoped: rules/agent/agent_destructive_action.yml keys on User in {claude,redteam,lab}, so
# this only fires when run AS an agent account. The worker_branch carve-out is deliberately avoided
# (no ' worker/' or ' lane-' in argv) so the rule is not suppressed.
#
# Imitates: rules/agent/agent_destructive_action.yml - ATT&CK T1485 Data Destruction / T1070
# Expected rules: agent_destructive_action
set -u
work=$(mktemp -d) || exit 0
trap 'rm -rf "$work" 2>/dev/null' EXIT

command -v git >/dev/null 2>&1 || exit 0
git -C "$work" init -q >/dev/null 2>&1 || exit 0

# --- TTP: delete a branch (errors: the branch does not exist) -> agent_destructive_action (git_destructive) ---
git -C "$work" branch -D emul-nonexistent-branch >/dev/null 2>&1 || true

# --- TTP: expire the reflog --all (covering tracks inside git) -> agent_destructive_action (git_destructive) ---
git -C "$work" reflog expire --expire=now --all >/dev/null 2>&1 || true

exit 0
