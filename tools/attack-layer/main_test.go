package main

import (
	"strings"
	"testing"
)

func TestTechTag(t *testing.T) {
	cases := map[string]string{
		"attack.t1059.004": "T1059.004",
		"attack.t1485":     "T1485",
		"attack.T1059":     "T1059", // already upper
		"attack.execution": "",      // a tactic, not a technique
		"attack.s0001":     "",      // software, not a technique
		"attack.g0016":     "",      // group, not a technique
		"cve.2021-0001":    "",      // not an attack tag
	}
	for tag, want := range cases {
		got := ""
		if m := techTag.FindStringSubmatch(tag); m != nil {
			got = strings.ToUpper(m[1])
		}
		if got != want {
			t.Errorf("%q -> %q, want %q", tag, got, want)
		}
	}
}
