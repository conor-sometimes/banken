package parser

import "path"

// multicallBinaries are programs that hold many tools in one binary and pick
// which one to run from argv[0]: GNU coreutils as NixOS builds it (cat, rm,
// base64, chmod, ... are all symlinks to bin/coreutils), busybox (Alpine,
// containers, embedded), toybox (Android) and kmod (the Linux module tools --
// lsmod, insmod, rmmod, modprobe, depmod are all symlinks to /bin/kmod on every
// modern distro). The kernel, and so auditd, only ever sees the multicall binary
// as exe=, so without this a rule written for /cat or /rm would never see cat or
// rm run on those systems -- and, just as important, a rule written for the
// LOADING tools (/insmod, /modprobe) must not fire on the read-only /lsmod, which
// resolving argv[0] keeps distinct where a bare exe=/.../kmod could not.
var multicallBinaries = map[string]bool{
	"coreutils": true,
	"busybox":   true,
	"toybox":    true,
	"kmod":      true,
}

// resolveMulticall returns the path of the tool a multicall binary actually
// ran, decided the way the binary itself decides it -- by argv[0]'s basename:
// exe /nix/store/…-coreutils/bin/coreutils with argv[0] "cat" ran cat, and is
// reported as /nix/store/…-coreutils/bin/cat (the symlink that invoked it).
// Trusting argv[0] here grants an attacker nothing: whatever it names is the
// tool that ran. Any other exe, or a multicall binary invoked under its own
// name ("busybox cat f"), is returned unchanged.
func resolveMulticall(exe, argv0 string) string {
	if !multicallBinaries[path.Base(exe)] {
		return exe
	}
	tool := path.Base(argv0)
	if argv0 == "" || tool == "/" || tool == "." || multicallBinaries[tool] {
		return exe
	}
	return path.Join(path.Dir(exe), tool)
}
