#!/usr/bin/env bash
# procmemdump.sh - benign emulation of reading process memory via /proc, for detection-rule testing.
#
# What an attacker does: scrape a running process's address space for secrets straight from memory -
# `dd if=/proc/<pid>/mem ...` (T1003.007), bypassing files on disk. This does the harmless analogue:
# it dds ONE byte of its OWN /proc/<pid>/maps into a scratch file (removed on exit) - maps is a
# readable text pseudo-file and nothing of consequence is dumped; the if=/proc/<pid>/maps in argv is
# the signal. See ./README.md.
#
# Imitates: rules/credential-access/proc_memory_dump.yml - ATT&CK T1003.007 Proc Filesystem
# Expected rules: proc_memory_dump
set -u
work=$(mktemp -d) || exit 0
trap 'rm -rf "$work" 2>/dev/null' EXIT

# --- TTP: dd reading from /proc/<pid>/maps -> proc_memory_dump (reader dd + proc_mem) ---
dd if=/proc/$$/maps of="$work/maps.bin" bs=1 count=1 >/dev/null 2>&1 || true

exit 0
