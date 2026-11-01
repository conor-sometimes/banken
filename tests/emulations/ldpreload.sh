#!/usr/bin/env bash
# ldpreload.sh - benign emulation of a dynamic-linker preload hijack, for detection-rule testing.
#
# What an attacker does: set LD_PRELOAD/LD_AUDIT, or write /etc/ld.so.preload (or an ld.so.conf.d
# drop), so the linker loads an attacker object into every dynamically-linked process - code
# injection, libc hooking, process hiding, or setuid escalation (T1574.006). This does the harmless
# analogue: it sets LD_PRELOAD to a NONEXISTENT .so on the no-op `true` (the linker ignores the
# missing lib and true just exits), and cp-s the REAL /etc/ld.so.preload to scratch read-only (naming
# the path in argv) without ever writing it. See ./README.md.
#
# Imitates: rules/privilege-escalation/ld_preload_hijack.yml - ATT&CK T1574.006 Dynamic Linker Hijacking
# Expected rules: ld_preload_hijack
set -u
work=$(mktemp -d) || exit 0
trap 'rm -rf "$work" 2>/dev/null' EXIT

# --- TTP: LD_PRELOAD on a command's environment -> ld_preload_hijack (preload_env) ---
# /tmp/banken-emul-nonexistent.so does not exist: the linker warns and ignores it, and `true` exits 0.
env LD_PRELOAD=/tmp/banken-emul-nonexistent.so true >/dev/null 2>&1 || true

# --- TTP: a file tool naming the system-wide preload file -> ld_preload_hijack (writer + preload_cmd) ---
# cp READS the real /etc/ld.so.preload into scratch (it usually does not exist, so this fails
# harmlessly); the real file is never written. The argv naming /etc/ld.so.preload is the signal.
cp /etc/ld.so.preload "$work/ld.so.preload" >/dev/null 2>&1 || true

exit 0
