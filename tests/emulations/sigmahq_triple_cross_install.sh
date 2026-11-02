#!/usr/bin/env bash
# sigmahq_triple_cross_install.sh - benign SigmaHQ emulation (see sigmahq_nohup.sh header).
#
# What an attacker does: the Triple Cross eBPF rootkit's deployer.sh attaches its
# BPF program to an interface with sudo + tc (T1014), e.g.
# `sudo tc qdisc add dev enp0s3 clsact`. The rule keys on /sudo whose command line
# contains ' tc ', ' enp0s3 ' and one of ' qdisc '/' filter '. Harmless analogue:
# the same shape as the unprivileged alice via `sudo -n` - alice is not in sudoers
# so sudo refuses (non-interactively, no prompt) and tc never runs, but the execve
# of /sudo carrying ' tc ', ' enp0s3 ' and ' qdisc ', which the rule keys on, is
# real. -n guarantees no hang.
#
# Imitates (SigmaHQ): proc_creation_lnx_triple_cross_rootkit_install.yml - ATT&CK T1014
# Expected rule: proc_creation_lnx_triple_cross_rootkit_install
set -u

command -v sudo >/dev/null 2>&1 || { echo "BANKEN-EMUL-SKIP: no sudo"; exit 0; }

sudo -n tc qdisc add dev enp0s3 clsact >/dev/null 2>&1 || true

exit 0
