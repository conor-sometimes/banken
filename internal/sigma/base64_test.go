package sigma

import (
	"reflect"
	"testing"

	"github.com/conor-sometimes/banken/internal/event"
)

// TestBase64OffsetReferenceVectors pins banken's base64offset encoding to
// pySigma's. The "foobar" vector is pySigma's own unit-test reference
// (tests/test_modifiers.py::test_base64offset); the others are generated from
// pySigma 0.11.x and checked in so a drift from the reference implementation
// fails here, not silently in the field.
func TestBase64OffsetReferenceVectors(t *testing.T) {
	cases := []struct {
		in   string
		want []string
	}{
		// pySigma's canonical reference vector (tests/test_modifiers.py).
		{"foobar", []string{"Zm9vYmFy", "Zvb2Jhc", "mb29iYX"}},
		// Generated from pySigma's SigmaBase64OffsetModifier on the conformance
		// host and checked in verbatim; these span every length residue mod 3.
		{"whoami", []string{"d2hvYW1p", "dob2Fta", "3aG9hbW"}},
		{"net user", []string{"bmV0IHVzZX", "5ldCB1c2Vy", "uZXQgdXNlc"}},
		{"cmd", []string{"Y21k", "NtZ", "jbW"}},
		{"a", []string{"Y", "", "h"}},
		{"ab", []string{"YW", "Fi", "hY"}},
		{"abc", []string{"YWJj", "FiY", "hYm"}},
	}
	for _, c := range cases {
		got := base64OffsetEncodings(c.in)
		if !reflect.DeepEqual(got, c.want) {
			t.Errorf("base64OffsetEncodings(%q) = %q, want %q", c.in, got, c.want)
		}
	}
}

func TestBase64Encode(t *testing.T) {
	cases := map[string]string{
		"foobar":   "Zm9vYmFy",
		"whoami":   "d2hvYW1p",
		"":         "",
		"net user": "bmV0IHVzZXI=",
	}
	for in, want := range cases {
		if got := base64Encode(in); got != want {
			t.Errorf("base64Encode(%q) = %q, want %q", in, got, want)
		}
	}
}

// TestBase64Modifiers is the end-to-end compile+match for the two value
// modifiers, including the chained forms SigmaHQ encoded-command rules use.
func TestBase64Modifiers(t *testing.T) {
	cases := []struct {
		name string
		rule string
		ev   event.Event
		want bool
	}{
		{
			name: "base64 equals, encoded value present",
			rule: "detection:\n  s:\n    CommandLine|base64: foobar\n  condition: s",
			// the whole field must equal the encoding (opEquals)
			ev:   event.Event{CommandLine: "Zm9vYmFy"},
			want: true,
		},
		{
			name: "base64 equals, plaintext not matched",
			rule: "detection:\n  s:\n    CommandLine|base64: foobar\n  condition: s",
			ev:   event.Event{CommandLine: "foobar"},
			want: false,
		},
		{
			name: "base64|contains finds encoding inside a longer line",
			rule: "detection:\n  s:\n    CommandLine|base64|contains: whoami\n  condition: s",
			ev:   event.Event{CommandLine: "echo d2hvYW1p | base64 -d | sh"},
			want: true,
		},
		{
			name: "base64offset|contains matches at offset 0",
			rule: "detection:\n  s:\n    CommandLine|base64offset|contains: foobar\n  condition: s",
			ev:   event.Event{CommandLine: "x Zm9vYmFy y"},
			want: true,
		},
		{
			name: "base64offset|contains matches shifted by one byte",
			rule: "detection:\n  s:\n    CommandLine|base64offset|contains: foobar\n  condition: s",
			// "Xfoobar" base64 embeds the offset-1 encoding "Zvb2Jhc"
			ev:   event.Event{CommandLine: base64Encode("Xfoobar")},
			want: true,
		},
		{
			name: "base64offset|contains matches shifted by two bytes",
			rule: "detection:\n  s:\n    CommandLine|base64offset|contains: foobar\n  condition: s",
			ev:   event.Event{CommandLine: base64Encode("XYfoobar")},
			want: true,
		},
		{
			name: "base64offset|contains no match on unrelated text",
			rule: "detection:\n  s:\n    CommandLine|base64offset|contains: foobar\n  condition: s",
			ev:   event.Event{CommandLine: "nothing encoded here"},
			want: false,
		},
	}
	for _, c := range cases {
		t.Run(c.name, func(t *testing.T) {
			r := compileOK(t, c.rule)
			if got := r.Match(c.ev); got != c.want {
				t.Errorf("Match() = %v, want %v", got, c.want)
			}
		})
	}
}

func TestBase64WildcardRejected(t *testing.T) {
	for _, rule := range []string{
		"detection:\n  s:\n    CommandLine|base64: 'foo*'\n  condition: s",
		"detection:\n  s:\n    CommandLine|base64offset: 'foo?'\n  condition: s",
	} {
		if _, err := Compile([]byte(rule)); err == nil {
			t.Errorf("expected a load error for a wildcard base64 value:\n%s", rule)
		}
	}
}
