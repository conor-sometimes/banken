#!/usr/bin/env bash
# sigmahq_chroot_execution.sh - benign SigmaHQ emulation (see sigmahq_nohup.sh header).
#
# What an attacker does: abuse `sudo --chroot` (CVE-2025-32463) to run a command
# in a modified root as part of a privilege-escalation chain (T1068), e.g.
# `sudo --chroot /some/dir sh`. The rule keys on an Image ending in '/sudo' with a
# command line containing ' --chroot ' (or 'sudo -R '). Harmless analogue: invoke
# the real sudo non-interactively (`-n`) as the unprivileged user alice with
# ' --chroot ' and a NONEXISTENT directory; alice is not a sudoer so sudo refuses
# (no password, no tty) and nothing is chrooted or run. The execve of a 'sudo'
# image carrying ' --chroot ', which the rule keys on, is real. (sudo also trips
# banken's own privilege_escalation rule, which is not a SigmaHQ rule and so is
# not counted by this test.)
#
# Imitates (SigmaHQ): proc_creation_lnx_chroot_execution.yml - ATT&CK T1068
# Expected rule: proc_creation_lnx_chroot_execution
set -u

command -v sudo >/dev/null 2>&1 || { echo "BANKEN-EMUL-SKIP: no sudo on PATH"; exit 0; }
sudo -n --chroot /nonexistent/bk-chroot true </dev/null >/dev/null 2>&1 || true

exit 0
