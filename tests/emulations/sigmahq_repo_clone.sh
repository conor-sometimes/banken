#!/usr/bin/env bash
# sigmahq_repo_clone.sh - benign SigmaHQ emulation (see sigmahq_nohup.sh header).
#
# What an attacker does: clone a public exploit/PoC repo onto a compromised host
# as recon before weaponising (T1593.003), e.g.
# `git clone https://.../CVE-2021-...-proxyshell-poc`. The rule keys on an Image
# ending in '/git', a command line containing ' clone ', AND a suspicious keyword
# ('CVE-', 'proxyshell', 'exploit', ...). The detection is purely name + args, so
# this runs the stock `true` binary copied under the name 'git' from a scratch dir
# in HOME (NOT /tmp or /dev/shm, to avoid the tmp-exec rules) with a clone command
# line whose source is a NONEXISTENT local path (no network, nothing fetched);
# `true` ignores the args and exits 0. The execve of a 'git' image with ' clone '
# and 'CVE-'/'proxyshell' in its command line, which the rule keys on, is real.
#
# Imitates (SigmaHQ): proc_creation_lnx_susp_git_clone.yml - ATT&CK T1593.003
# Expected rule: proc_creation_lnx_susp_git_clone
set -u

src="$(type -P true)"
[ -n "$src" ] || { echo "BANKEN-EMUL-SKIP: no true binary on PATH"; exit 0; }
d="${HOME:-/home/alice}/.bk-emul-gitclone.$$"
mkdir -p "$d" 2>/dev/null || { echo "BANKEN-EMUL-SKIP: cannot create scratch dir"; exit 0; }
cp "$src" "$d/git" 2>/dev/null || { echo "BANKEN-EMUL-SKIP: cannot stage binary"; exit 0; }
"$d/git" clone /nonexistent/exploit-CVE-2099-0001-proxyshell-poc "$d/dst" >/dev/null 2>&1 || true
rm -rf "$d" 2>/dev/null || true

exit 0
