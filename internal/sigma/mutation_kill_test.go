package sigma

import (
	"os"
	"path/filepath"
	"testing"

	"github.com/conor-sometimes/banken/internal/event"
)

// The tests here close specific gaps that gremlins mutation testing surfaced:
// each corresponds to a mutant that survived because no test pinned the
// behaviour down. They are behavioural, not score-chasing.

// load.go: LoadTree must ignore a non-YAML file in a rule tree (a surviving
// CONDITIONALS_NEGATION on the extension check meant nothing asserted it).
func TestLoadTreeIgnoresNonYAML(t *testing.T) {
	dir := t.TempDir()
	must(t, os.WriteFile(filepath.Join(dir, "notes.txt"), []byte("not a rule"), 0o600))
	must(t, os.WriteFile(filepath.Join(dir, "README.md"), []byte("# docs"), 0o600))
	must(t, os.WriteFile(filepath.Join(dir, "r.yml"),
		[]byte("detection:\n  s:\n    Image: /x\n  condition: s\n"), 0o600))

	rules, problems := LoadTree(dir)
	for _, p := range problems {
		t.Errorf("unexpected problem loading tree: %v", p)
	}
	if len(rules) != 1 {
		t.Fatalf("got %d rules, want 1 — non-YAML files must be ignored, not loaded or errored", len(rules))
	}
}

// rule.go: a selMap with no fields must never match, guarding an empty
// selection from matching every event (surviving CONDITIONALS_BOUNDARY on
// `len(m.fields) > 0`).
func TestEmptySelMapDoesNotMatch(t *testing.T) {
	if (selMap{}).match(event.Event{Image: "/x"}) {
		t.Error("an empty selMap matched; it must not (would match everything)")
	}
}

// matcher.go: an empty |contains value makes the field wild (an empty string
// is contained in everything), so the rule must still be a candidate and
// fire. A surviving mutant here would make such a rule silently never fire.
func TestEmptyContainsStillFiresViaMatcher(t *testing.T) {
	r := compileOK(t, "detection:\n  s:\n    CommandLine|contains: ''\n  condition: s\n")
	r.Name = "empty"
	m := NewMatcher([]*Rule{r})
	if len(m.Match(event.Event{CommandLine: "anything"})) != 1 {
		t.Error("a rule with an empty |contains should match an event with a non-empty CommandLine")
	}
}

// matcher.go: an all-empty |all field is wild for the same reason.
func TestEmptyAllStillFiresViaMatcher(t *testing.T) {
	r := compileOK(t, "detection:\n  s:\n    CommandLine|contains|all: ['']\n  condition: s\n")
	r.Name = "emptyall"
	m := NewMatcher([]*Rule{r})
	if len(m.Match(event.Event{CommandLine: "anything"})) != 1 {
		t.Error("a rule with an all-empty |all should match an event with a non-empty CommandLine")
	}
}

func must(t *testing.T, err error) {
	t.Helper()
	if err != nil {
		t.Fatal(err)
	}
}
