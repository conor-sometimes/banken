package benchlib

import (
	"fmt"

	"github.com/conor-sometimes/banken/internal/sigma"
)

// LoadBaseline loads the shipped rule tree from dir (the repo's ./rules). It is
// the real detection set the latency and 1x scaling rows are measured against,
// so the numbers are the ones a deployment actually pays, not a synthetic
// best/worst case. A load error is fatal to a bench run: measuring against a
// half-loaded rule set would be a lie.
func LoadBaseline(dir string) ([]*sigma.Rule, error) {
	rules, probs := sigma.LoadTree(dir)
	if len(probs) > 0 {
		return nil, fmt.Errorf("loading %s: %d rule error(s), first: %w", dir, len(probs), probs[0])
	}
	if len(rules) == 0 {
		return nil, fmt.Errorf("loading %s: no rules found", dir)
	}
	return rules, nil
}

// PadTo returns a rule set of exactly n rules: the real baseline, plus synthetic
// rules with distinct literals to reach n. It is how the spec's "memory as a
// function of rule count: 211 / 2,000 / 10,000" row is built without inventing a
// rule corpus that large. The synthetic rules mirror the shape the prefilter is
// built for (a command token and a filename token unique to each), the same
// generator the in-package scaling benchmark uses, so the padded set exercises
// the automaton the way a real large tree would. If the baseline already has n
// or more rules, it is returned unpadded.
func PadTo(baseline []*sigma.Rule, n int) ([]*sigma.Rule, error) {
	out := make([]*sigma.Rule, len(baseline))
	copy(out, baseline)
	for i := len(baseline); i < n; i++ {
		r, err := synthetic(i)
		if err != nil {
			return nil, err
		}
		out = append(out, r)
	}
	return out, nil
}

func synthetic(i int) (*sigma.Rule, error) {
	y := fmt.Sprintf(`title: synthetic bench rule %d
detection:
  cmd:
    CommandLine|contains: evilcmd-%d-marker
  file:
    TargetFilename|contains: /opt/mal-%d/payload
  condition: cmd or file`, i, i, i)
	r, err := sigma.Compile([]byte(y))
	if err != nil {
		return nil, fmt.Errorf("compiling synthetic rule %d: %w", i, err)
	}
	r.Name = fmt.Sprintf("synthetic_%d", i)
	return r, nil
}
