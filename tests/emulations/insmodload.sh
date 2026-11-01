#!/usr/bin/env bash
# insmodload.sh - benign emulation of a kernel module load, for detection-rule testing.
#
# What an attacker does: load a loadable kernel module (insmod/modprobe) - a top-tier rootkit and
# persistence mechanism that can hide processes, files and connections and survive a reboot
# (T1547.006 / T1014). This does the harmless analogue: it modprobe/insmod a NONEXISTENT dummy module
# name, so the tool runs (the Image the rule keys on) but fails to find anything and loads NO module.
# See ./README.md.
#
# Imitates: rules/persistence/kernel_module_load.yml - ATT&CK T1547.006 Kernel Modules / T1014 Rootkit
# Expected rules: kernel_module_load
set -u

# --- TTP: modprobe a nonexistent module (loads nothing) -> kernel_module_load (modtool) ---
if command -v modprobe >/dev/null 2>&1; then
	modprobe banken_emul_nonexistent_module >/dev/null 2>&1 || true
fi

# --- TTP: insmod a nonexistent .ko (loads nothing) -> kernel_module_load (modtool) ---
if command -v insmod >/dev/null 2>&1; then
	insmod /tmp/banken-emul-nonexistent.ko >/dev/null 2>&1 || true
fi

exit 0
