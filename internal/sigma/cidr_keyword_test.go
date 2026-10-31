package sigma

import (
	"testing"

	"github.com/conor-sometimes/banken/internal/event"
)

// TestCIDRModifier covers the |cidr modifier (field IP within a CIDR range).
func TestCIDRModifier(t *testing.T) {
	r := compileOK(t, "detection:\n  s:\n    DestinationIp|cidr:\n      - 10.0.0.0/8\n      - 192.168.0.0/16\n  condition: s\n")
	r.Name = "cidr"
	cases := []struct {
		ip   string
		want bool
	}{
		{"10.1.2.3", true},
		{"192.168.5.5", true},
		{"8.8.8.8", false},
		{"not-an-ip", false},
		{"", false},
	}
	for _, tc := range cases {
		ev := event.Event{Raw: map[string]string{"DestinationIp": tc.ip}}
		if got := r.Match(ev); got != tc.want {
			t.Errorf("ip %q: got %v, want %v", tc.ip, got, tc.want)
		}
	}
}

func TestBadCIDRRejected(t *testing.T) {
	if _, err := Compile([]byte("detection:\n  s:\n    ip|cidr: not-a-cidr\n  condition: s\n")); err == nil {
		t.Error("expected a load error for an invalid CIDR")
	}
}

// TestKeywordAllModifier covers a bare `|all` keyword selection (the SigmaHQ
// binary-padding form): every string must appear in some field.
func TestKeywordAllModifier(t *testing.T) {
	r := compileOK(t, "detection:\n  k:\n    '|all':\n      - truncate\n      - ' -s'\n  condition: k\n")
	r.Name = "kwall"
	if !r.Match(event.Event{CommandLine: "truncate -s 0 /bin/legit"}) {
		t.Error("should match when both keywords are present")
	}
	if r.Match(event.Event{CommandLine: "truncate /bin/legit"}) {
		t.Error("should not match when ' -s' is missing (|all requires all)")
	}
}

// TestKeywordAllAcrossFields: |all is satisfied when each value appears in
// some field, not necessarily the same one.
func TestKeywordAllAcrossFields(t *testing.T) {
	r := compileOK(t, "detection:\n  k:\n    '|all':\n      - /bin/dd\n      - 'if='\n  condition: k\n")
	r.Name = "kwaf"
	ev := event.Event{Image: "/bin/dd", CommandLine: "dd if=/dev/zero of=x"}
	if !r.Match(ev) {
		t.Error("|all should match with one value in Image and the other in CommandLine")
	}
}
