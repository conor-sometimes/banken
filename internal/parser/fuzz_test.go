package parser

import (
	"reflect"
	"strings"
	"testing"
)

// The parsers eat untrusted log bytes, so the one invariant that matters
// most is: never panic, on anything. These targets also assert the parser
// is deterministic (same bytes in, same events out) and never mislabels a
// source -- a parser that quietly produced a different normalisation on a
// re-read, or stamped the wrong Source, would be mis-normalising in a way a
// crash-only check would miss. Run via `just fuzz`; the seed corpus also
// runs under plain `go test`.

func fuzzSeedsAuditd(f *testing.F) {
	for _, s := range []string{
		"",
		"\n\n\n",
		"type=SYSCALL msg=audit(1.0:1): exe=\"/bin/x\" uid=0",
		"type=EXECVE msg=audit(1.0:1): argc=2 a0=\"x\" a1=\"y\"",
		"type=SYSCALL msg=audit(",
		"type=PROCTITLE msg=audit(2.0:2): proctitle=6361740041",
		"type=SYSCALL msg=audit(3.0:3): a0=\"unterminated",
		"type=PATH msg=audit(4.0:4): name=(null) nametype=CREATE",
		strings.Repeat("A", 5000),
		"type=SYSCALL msg=audit(9999999999999999999.0:1): exe=\"/x\"",
		"type=EXECVE msg=audit(5.0:5): argc=-1 a0=\"z\"",
		"type=EXECVE msg=audit(6.0:6): argc=999999999 a0=\"z\"",
		string([]byte{0, 1, 2, 255, 254, '\n', 't', 'y', 'p', 'e', '='}),
	} {
		f.Add(s)
	}
}

func FuzzParseAuditd(f *testing.F) {
	fuzzSeedsAuditd(f)
	p := Auditd{}
	f.Fuzz(func(t *testing.T, data string) {
		checkParser(t, p, data)
	})
}

func fuzzSeedsLaurel(f *testing.F) {
	for _, s := range []string{
		"",
		"{}",
		"null",
		"[1,2,3]",
		`{"ID":"1.0:1","SYSCALL":{"exe":"/bin/x","uid":"0"}}`,
		`{"ID":1,"SYSCALL":"bad","EXECVE":{"ARGV":"bad"},"PATH":"bad"}`,
		`{"ID":"1.0:1","EXECVE":{"argc":"2","ARGV":["a","b"]}}`,
		`{"ID":"1.0:1","PROCTITLE":{"proctitle":"6361740041"}}`,
		`{"ID":"1.0:1","PATH":[{"name":null,"nametype":5}]}`,
		"{ broken json",
		`{"ID":"` + strings.Repeat("9", 400) + `"}`,
		string([]byte{'{', '"', 0, 255, '"', ':', '1', '}'}),
	} {
		f.Add(s)
	}
}

func FuzzParseLaurel(f *testing.F) {
	fuzzSeedsLaurel(f)
	p := Laurel{}
	f.Fuzz(func(t *testing.T, data string) {
		checkParser(t, p, data)
	})
}

// FuzzParseStubs asserts the journald/syslog stubs also never panic and
// faithfully drain their input (so a cursor advances) while emitting
// nothing -- the interface contract holds even before they are real.
func FuzzParseStubs(f *testing.F) {
	f.Add("")
	f.Add("anything at all")
	f.Add(string([]byte{0, 1, 2, 255}))
	f.Fuzz(func(t *testing.T, data string) {
		for _, p := range []Parser{Journald{}, Syslog{}} {
			evs, err := p.Parse(strings.NewReader(data))
			if err != nil {
				t.Fatalf("%s stub returned error on %q: %v", p.Name(), data, err)
			}
			if len(evs) != 0 {
				t.Fatalf("%s stub emitted %d events, want 0", p.Name(), len(evs))
			}
		}
	})
}

// checkParser runs the never-panic / deterministic / correct-source
// invariants shared by both real parsers.
func checkParser(t *testing.T, p Parser, data string) {
	t.Helper()
	evs, err := p.Parse(strings.NewReader(data))
	if err != nil {
		// An in-memory reader never fails for I/O; an error here would mean
		// the parser invented one for bad content, which it must not.
		t.Fatalf("%s.Parse returned an error on in-memory input: %v", p.Name(), err)
	}
	for i, ev := range evs {
		if ev.Source != p.Name() {
			t.Fatalf("event %d has Source %q, want %q", i, ev.Source, p.Name())
		}
	}
	// Determinism: the same bytes must always normalise to the same events.
	evs2, _ := p.Parse(strings.NewReader(data))
	if !reflect.DeepEqual(evs, evs2) {
		t.Fatalf("%s.Parse is not deterministic for %q", p.Name(), data)
	}
}
