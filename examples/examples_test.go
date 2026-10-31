// Package examples holds no code; this test loads the example rule tree on
// every `go test` so the capability showcase can never drift from what the
// engine actually accepts. A broken example fails CI.
package examples

import (
	"testing"

	"github.com/conor-sometimes/banken/internal/ioc"
	"github.com/conor-sometimes/banken/internal/sigma"
)

func TestExampleRulesCompile(t *testing.T) {
	rules, problems := sigma.LoadTree("rules")
	for _, p := range problems {
		t.Errorf("example rule failed to load: %v", p)
	}
	if len(rules) == 0 {
		t.Fatal("no example rules loaded from rules/")
	}

	set, err := ioc.LoadTree("rules")
	if err != nil {
		t.Fatalf("example IOC feed failed to load: %v", err)
	}
	if set.Len() == 0 {
		t.Error("example IOC feed loaded zero indicators")
	}
}
