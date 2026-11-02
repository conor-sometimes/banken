package sigma

import "testing"

// TestPatternBytesCountsEveryLiteral proves PatternBytes sums the literal match
// patterns across fields and selections (the figure the refresh resource guard
// bounds), and that a rule with no literals reports zero.
func TestPatternBytesCountsEveryLiteral(t *testing.T) {
	// Two selections, three literal values: "foo" (3), "barbar" (6), "baz" (3).
	r, err := Compile([]byte(`detection:
  a:
    CommandLine|contains: foo
    Image|endswith: barbar
  b:
    User: baz
  condition: a or b
`))
	if err != nil {
		t.Fatalf("Compile: %v", err)
	}
	if got, want := r.PatternBytes(), 3+6+3; got != want {
		t.Fatalf("PatternBytes() = %d, want %d", got, want)
	}

	// A presence-only rule (field|exists) carries no literal patterns.
	bare, err := Compile([]byte("detection:\n  s:\n    CommandLine|exists: true\n  condition: s\n"))
	if err != nil {
		t.Fatalf("Compile bare: %v", err)
	}
	if got := bare.PatternBytes(); got != 0 {
		t.Fatalf("PatternBytes() on a presence-only rule = %d, want 0", got)
	}
}
