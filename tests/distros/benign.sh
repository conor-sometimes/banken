#!/usr/bin/env bash
# benign.sh - an ordinary day on a server as an unprivileged user. None of this
# is an attack, so a detect check with `expect = [ ]` requires that banken fires
# nothing. Run under its own launcher, so process-subtree attribution scopes the
# "fired nothing" to exactly these commands (a cron job beside it cannot fail
# it). sudo is absent on purpose: banken alerts on every privilege-escalation
# attempt by design.
set -u

ls -la ~ >/dev/null 2>&1 || true
cat /etc/os-release >/dev/null 2>&1 || true
ps aux >/dev/null 2>&1 || true
df -h >/dev/null 2>&1 || true
uname -a >/dev/null 2>&1 || true
id >/dev/null 2>&1 || true
date >/dev/null 2>&1 || true
grep root /etc/passwd >/dev/null 2>&1 || true
head -n 3 /etc/hosts >/dev/null 2>&1 || true
echo hello | base64 >/dev/null 2>&1 || true
tar czf /tmp/benign-home.tgz -C ~ . >/dev/null 2>&1 && rm -f /tmp/benign-home.tgz || true
python3 -c 'print(sum(range(10)))' >/dev/null 2>&1 || true
curl --version >/dev/null 2>&1 || true
crontab -l >/dev/null 2>&1 || true

exit 0
