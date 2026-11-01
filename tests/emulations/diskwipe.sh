#!/usr/bin/env bash
# diskwipe.sh - benign emulation of data/disk destruction, for detection-rule testing.
#
# What an attacker does: obliterate the medium, not a file - dd to a raw block device, mkfs
# reformatting one, wipefs/blkdiscard/shred of a device, or rm -rf --no-preserve-root / - the
# destructive endgame of a wiper or ransomware (T1485). This does the harmless analogue, under a HARD
# safety contract: it NEVER touches a real disk or /. It rm-s a SCRATCH dir with --no-preserve-root
# (the flag is the signal; the target is scratch), and - only when UNPRIVILEGED, where the kernel
# denies writing block devices - names a NONEXISTENT device /dev/sdz with dd count=0 (writes nothing)
# and mkfs (which fails to open it). No real device or filesystem is ever written. See ./README.md.
#
# Imitates: rules/impact/data_destruction.yml - ATT&CK T1485 Data Destruction
# Expected rules: data_destruction
set -u
work=$(mktemp -d) || exit 0
trap 'rm -rf "$work" 2>/dev/null' EXIT
mkdir -p "$work/doomed"

# --- TTP: rm -rf --no-preserve-root pointed at a SCRATCH dir -> data_destruction (rm_rootfs) ---
# The --no-preserve-root flag is the signal; the target is scratch, so only scratch is removed.
rm -rf --no-preserve-root "$work/doomed" >/dev/null 2>&1 || true

# The device-writing TTPs run ONLY unprivileged, where the kernel refuses to open a block device for
# write, and target a NONEXISTENT device (/dev/sdz) with a zero-byte count - triply safe. Never as
# root, where dd/mkfs could actually destroy a disk (safety contract).
if [ "$(id -u)" -ne 0 ]; then
	# --- TTP: dd to a raw block device -> data_destruction (disk_wipe) ---
	if command -v dd >/dev/null 2>&1; then
		dd if=/dev/zero of=/dev/sdz bs=1M count=0 >/dev/null 2>&1 || true
	fi
	# --- TTP: mkfs reformatting a device -> data_destruction (reformat) ---
	if command -v mkfs.ext4 >/dev/null 2>&1; then
		mkfs.ext4 /dev/sdz >/dev/null 2>&1 </dev/null || true
	fi
fi

exit 0
