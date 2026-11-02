package engine

import (
	"sync"
	"testing"

	"github.com/conor-sometimes/banken/internal/event"
	"github.com/conor-sometimes/banken/internal/sigma"
)

const probeRuleA = `title: probe a
id: probe-a
level: low
detection:
  sel:
    CommandLine|contains: TOKEN_A
  condition: sel
`

const probeRuleB = `title: probe b
id: probe-b
level: low
detection:
  sel:
    CommandLine|contains: TOKEN_B
  condition: sel
`

func mustCompile(t *testing.T, y string) *sigma.Rule {
	t.Helper()
	r, err := sigma.Compile([]byte(y))
	if err != nil {
		t.Fatalf("compile: %v", err)
	}
	return r
}

// TestSetRulesConcurrentSwapIsRaceFree runs many concurrent Match calls against
// an engine whose rule set is being replaced in a tight loop by SetRules. It
// asserts nothing itself: the point is that `go test -race` sees no data race
// between the atomic.Pointer store in SetRules and the loads in Match, and that
// Match never observes a torn or half-built matcher (a panic would fail the
// test). This is the race-free live-swap guarantee of the engine (task
// 6f2ffe74 / docs/design/rule-refresh.md section 6).
func TestSetRulesConcurrentSwapIsRaceFree(t *testing.T) {
	ra := mustCompile(t, probeRuleA)
	rb := mustCompile(t, probeRuleB)

	eng := New([]*sigma.Rule{ra}, nil, nil)

	var wg sync.WaitGroup
	stop := make(chan struct{})

	// Readers: hammer Match from several goroutines with events that match
	// whichever set is live at the moment, so matches actually walk the matcher
	// rather than short-circuiting.
	for i := 0; i < 8; i++ {
		wg.Add(1)
		go func() {
			defer wg.Done()
			evA := event.Event{CommandLine: "run TOKEN_A now"}
			evB := event.Event{CommandLine: "run TOKEN_B now"}
			for {
				select {
				case <-stop:
					return
				default:
					_ = eng.Match(evA)
					_ = eng.Match(evB)
				}
			}
		}()
	}

	// Swapper: replace the live set repeatedly.
	wg.Add(1)
	go func() {
		defer wg.Done()
		for i := 0; i < 3000; i++ {
			if i%2 == 0 {
				eng.SetRules([]*sigma.Rule{ra}, nil)
			} else {
				eng.SetRules([]*sigma.Rule{rb}, nil)
			}
		}
		close(stop)
	}()

	wg.Wait()

	// After the final swap (i=2999 is odd -> rule B), a TOKEN_B event matches and
	// a TOKEN_A event does not: the swap took effect and the pointer is coherent.
	if got := len(eng.Match(event.Event{CommandLine: "x TOKEN_B y"})); got != 1 {
		t.Fatalf("after final swap to rule B: TOKEN_B event got %d alerts, want 1", got)
	}
	if got := len(eng.Match(event.Event{CommandLine: "x TOKEN_A y"})); got != 0 {
		t.Fatalf("after final swap to rule B: TOKEN_A event got %d alerts, want 0 (old set should be gone)", got)
	}
}
