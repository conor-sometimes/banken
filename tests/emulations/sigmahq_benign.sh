#!/usr/bin/env bash
# sigmahq_benign.sh - the benign baseline for the SigmaHQ emulation harness.
#
# Ordinary, unremarkable activity that a normal user does all day. It must fire
# NO SigmaHQ Linux rule: it is the false-positive guard, the counterpart to the
# tests/fixtures/*.expect-none.json baselines. If any rule fires here, either a
# rule is too broad or the harness is miscounting. Deliberately avoids tool/flag
# combinations any linux rule keys on (e.g. no `id`, no `ls -R`, no `find`).
set -u

date >/dev/null 2>&1 || true
cat /etc/os-release >/dev/null 2>&1 || true
ls -l "$HOME" >/dev/null 2>&1 || true
echo "banken sigmahq benign baseline" >/dev/null 2>&1 || true

exit 0
