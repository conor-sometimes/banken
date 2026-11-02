package engine

import (
	"encoding/json"
	"os"
	"path/filepath"
	"strings"
	"testing"

	"github.com/conor-sometimes/banken/internal/event"
	"github.com/conor-sometimes/banken/internal/ioc"
	"github.com/conor-sometimes/banken/internal/sigma"
)

// TestFixtures is the end-to-end detection check against the repo's own
// rules: each tests/fixtures/NAME.expect-<rule>.json must fire <rule> on at
// least one of its events, and each *.expect-none.json (the benign
// baseline) must fire no Sigma rule at all. These are seeded from the
// emulation scripts' expected behaviour, so a regression in a rule or the
// matcher shows up here as a concrete, named failure.
func TestFixtures(t *testing.T) {
	rulesDir := filepath.Join("..", "..", "rules")
	fixturesDir := filepath.Join("..", "..", "tests", "fixtures")

	rules, problems := sigma.LoadTree(rulesDir)
	for _, p := range problems {
		t.Fatalf("rule failed to load: %v", p)
	}
	if len(rules) == 0 {
		t.Fatalf("no rules loaded from %s", rulesDir)
	}
	iocSet, err := ioc.LoadTree(rulesDir)
	if err != nil {
		t.Fatalf("load iocs: %v", err)
	}
	eng := New(rules, iocSet, nil)

	entries, err := os.ReadDir(fixturesDir)
	if err != nil {
		t.Fatalf("read fixtures dir: %v", err)
	}
	seenExpect, seenNone := false, false
	for _, e := range entries {
		if e.IsDir() || !strings.HasSuffix(e.Name(), ".json") {
			continue
		}
		name := e.Name()
		t.Run(name, func(t *testing.T) {
			events := loadFixtureEvents(t, filepath.Join(fixturesDir, name))

			firedSigma := map[string]bool{}
			for _, ev := range events {
				for _, a := range eng.Match(ev) {
					if a.Kind == "sigma" {
						firedSigma[a.Rule] = true
					}
				}
			}

			wantRule, ok := expectedRule(name)
			if !ok {
				t.Fatalf("fixture name %q does not follow NAME.expect-<rule>.json", name)
			}
			if wantRule == "none" {
				seenNone = true
				if len(firedSigma) != 0 {
					t.Errorf("benign baseline %q fired rules %v, want none", name, keys(firedSigma))
				}
				return
			}
			seenExpect = true
			if !firedSigma[wantRule] {
				t.Errorf("fixture %q expected rule %q to fire; fired: %v", name, wantRule, keys(firedSigma))
			}
		})
	}
	if !seenExpect || !seenNone {
		t.Errorf("expected both expect-<rule> and expect-none fixtures to exist (expect=%v none=%v)", seenExpect, seenNone)
	}
}

// TestEveryRuleHasAFixture enforces the project rule that no detection ships
// without a test: every loaded Sigma rule must have at least one
// tests/fixtures/NAME.expect-<rule>.json proving it fires. When a new rule --
// or an imported SigmaHQ rule -- lands without a fixture, this fails loudly,
// which is also how banken ends up testing upstream rules against real events.
func TestEveryRuleHasAFixture(t *testing.T) {
	rulesDir := filepath.Join("..", "..", "rules")
	fixturesDir := filepath.Join("..", "..", "tests", "fixtures")

	rules, problems := sigma.LoadTree(rulesDir)
	for _, p := range problems {
		t.Fatalf("rule failed to load: %v", p)
	}
	if len(rules) == 0 {
		t.Fatalf("no rules loaded from %s", rulesDir)
	}

	tested := map[string]bool{}
	entries, err := os.ReadDir(fixturesDir)
	if err != nil {
		t.Fatalf("read fixtures dir: %v", err)
	}
	for _, e := range entries {
		if r, ok := expectedRule(e.Name()); ok && r != "none" {
			tested[r] = true
		}
	}
	for _, r := range rules {
		if !tested[r.Name] {
			t.Errorf("rule %q (%s) has no tests/fixtures/*.expect-%s.json - every rule must ship with a test",
				r.Name, r.Path, r.Name)
		}
	}
}

// expectedRule parses the rule name out of NAME.expect-<rule>.json.
func expectedRule(filename string) (string, bool) {
	base := strings.TrimSuffix(filename, ".json")
	i := strings.Index(base, ".expect-")
	if i < 0 {
		return "", false
	}
	return base[i+len(".expect-"):], true
}

func loadFixtureEvents(t *testing.T, path string) []event.Event {
	t.Helper()
	data, err := os.ReadFile(path)
	if err != nil {
		t.Fatalf("read fixture: %v", err)
	}
	var events []event.Event
	if err := json.Unmarshal(data, &events); err != nil {
		t.Fatalf("fixture %s is not a JSON array of events: %v", path, err)
	}
	if len(events) == 0 {
		t.Fatalf("fixture %s has no events", path)
	}
	return events
}

func keys(m map[string]bool) []string {
	out := make([]string, 0, len(m))
	for k := range m {
		out = append(out, k)
	}
	return out
}
