package parser

import (
	"fmt"
	"strconv"
	"strings"
	"testing"
	"time"

	"pgregory.net/rapid"
)

// Property-based tests (pgregory.net/rapid): distinct from the Fuzz*
// targets, which throw raw garbage at the parsers to find panics. These
// build a *well-formed* audit event from random-but-valid pieces and check
// the parser recovers exactly those pieces -- the "never mis-normalise"
// half of the contract, swept across the whole space of valid argv/exe/uid
// shapes rather than the handful the table tests pin down. Run deeper with
// `just property-deep`.

// safeToken draws a shell token with no space, quote or control char, so
// it is quoted literally in the audit line and the argv join reconstructs
// it unambiguously.
func safeToken(t *rapid.T, label string) string {
	return rapid.StringMatching(`[A-Za-z0-9/_.:=@+-]{1,20}`).Draw(t, label)
}

func TestPropertyAuditdRecoversWellFormedExec(t *testing.T) {
	rapid.Check(t, func(t *rapid.T) {
		exe := "/" + rapid.StringMatching(`[a-z]{1,8}(/[a-z]{1,8}){0,3}`).Draw(t, "exe")
		uid := strconv.Itoa(rapid.IntRange(0, 65535).Draw(t, "uid"))
		sec := rapid.Int64Range(0, 4_000_000_000).Draw(t, "sec")
		ms := rapid.IntRange(0, 999).Draw(t, "ms")
		seq := rapid.IntRange(1, 1_000_000).Draw(t, "seq")
		argv := rapid.SliceOfN(rapid.Custom(func(t *rapid.T) string {
			return safeToken(t, "arg")
		}), 1, 8).Draw(t, "argv")

		id := fmt.Sprintf("%d.%03d:%d", sec, ms, seq)
		var b strings.Builder
		fmt.Fprintf(&b, "type=SYSCALL msg=audit(%s): exe=%q uid=%s\n", id, exe, uid)
		fmt.Fprintf(&b, "type=EXECVE msg=audit(%s): argc=%d", id, len(argv))
		for i, a := range argv {
			fmt.Fprintf(&b, " a%d=%q", i, a)
		}

		evs, err := Auditd{}.Parse(strings.NewReader(b.String()))
		if err != nil {
			t.Fatalf("parse error: %v", err)
		}
		if len(evs) != 1 {
			t.Fatalf("got %d events, want 1\ninput:\n%s", len(evs), b.String())
		}
		ev := evs[0]
		if ev.Image != exe {
			t.Errorf("Image = %q, want %q", ev.Image, exe)
		}
		if ev.User != uid {
			t.Errorf("User = %q, want %q", ev.User, uid)
		}
		if want := strings.Join(argv, " "); ev.CommandLine != want {
			t.Errorf("CommandLine = %q, want %q", ev.CommandLine, want)
		}
		wantTime := time.Unix(sec, int64(ms)*int64(time.Millisecond)).UTC()
		if !ev.Time.Equal(wantTime) {
			t.Errorf("Time = %v, want %v", ev.Time, wantTime)
		}
	})
}

func TestPropertyLaurelRecoversWellFormedExec(t *testing.T) {
	rapid.Check(t, func(t *rapid.T) {
		exe := "/" + rapid.StringMatching(`[a-z]{1,8}(/[a-z]{1,8}){0,3}`).Draw(t, "exe")
		uid := strconv.Itoa(rapid.IntRange(0, 65535).Draw(t, "uid"))
		argv := rapid.SliceOfN(rapid.Custom(func(t *rapid.T) string {
			return safeToken(t, "arg")
		}), 1, 8).Draw(t, "argv")

		quoted := make([]string, len(argv))
		for i, a := range argv {
			quoted[i] = strconv.Quote(a)
		}
		line := fmt.Sprintf(`{"ID":"100.000:1","SYSCALL":{"exe":%q,"uid":%q},"EXECVE":{"argc":"%d","ARGV":[%s]}}`,
			exe, uid, len(argv), strings.Join(quoted, ","))

		evs, err := Laurel{}.Parse(strings.NewReader(line))
		if err != nil {
			t.Fatalf("parse error: %v", err)
		}
		if len(evs) != 1 {
			t.Fatalf("got %d events, want 1\ninput: %s", len(evs), line)
		}
		ev := evs[0]
		if ev.Image != exe {
			t.Errorf("Image = %q, want %q", ev.Image, exe)
		}
		if ev.User != uid {
			t.Errorf("User = %q, want %q", ev.User, uid)
		}
		if want := strings.Join(argv, " "); ev.CommandLine != want {
			t.Errorf("CommandLine = %q, want %q", ev.CommandLine, want)
		}
	})
}
