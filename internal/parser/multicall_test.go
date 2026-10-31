package parser

import "testing"

func TestResolveMulticall(t *testing.T) {
	cases := []struct{ name, exe, argv0, want string }{
		{"coreutils symlink", "/nix/store/x-coreutils-9.11/bin/coreutils", "cat", "/nix/store/x-coreutils-9.11/bin/cat"},
		{"argv0 as a path", "/nix/store/x-coreutils-9.11/bin/coreutils", "/run/current-system/sw/bin/rm", "/nix/store/x-coreutils-9.11/bin/rm"},
		{"busybox applet", "/bin/busybox", "wget", "/bin/wget"},
		{"toybox applet", "/system/bin/toybox", "nc", "/system/bin/nc"},
		{"invoked under its own name stays", "/bin/busybox", "busybox", "/bin/busybox"},
		{"multicall argv0 as another multicall stays", "/bin/busybox", "/usr/bin/coreutils", "/bin/busybox"},
		{"no argv0 stays", "/bin/busybox", "", "/bin/busybox"},
		{"degenerate argv0 stays", "/bin/busybox", "/", "/bin/busybox"},
		{"ordinary binary untouched", "/usr/bin/cat", "dog", "/usr/bin/cat"},
		{"empty exe untouched", "", "cat", ""},
	}
	for _, c := range cases {
		if got := resolveMulticall(c.exe, c.argv0); got != c.want {
			t.Errorf("%s: resolveMulticall(%q, %q) = %q, want %q", c.name, c.exe, c.argv0, got, c.want)
		}
	}
}
