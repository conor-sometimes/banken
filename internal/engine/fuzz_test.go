package engine

import (
	"strings"
	"testing"

	"github.com/conor-sometimes/banken/internal/parser"
	"github.com/conor-sometimes/banken/internal/sigma"
)

// FuzzEnginePipeline drives untrusted bytes through a real parser and the
// matcher with NO recover guard, so any panic the production guard would
// otherwise absorb surfaces here as a failure. It is the crash/DoS hunter
// for the whole read -> parse -> normalise -> match path: a crafted log line
// must never crash, hang, or mis-normalise its way into a panic.
func FuzzEnginePipeline(f *testing.F) {
	f.Add("type=SYSCALL msg=audit(1.1:1): exe=\"/bin/sh\" comm=\"sh\"\ntype=EXECVE msg=audit(1.1:1): argc=1 a0=\"sh\"\n")
	f.Add("{\"ID\":[1,1,1],\"SYSCALL\":{\"exe\":\"/bin/bash\"},\"EXECVE\":{\"ARGV\":[\"bash\",\"-c\",\"curl http://1.2.3.4\"]}}\n")
	f.Add("type=PATH msg=audit(9:9): name=\"/etc/shadow\"\n")
	f.Add("\x00\xff garbage not a log line at all \n\n\n")
	f.Add(strings.Repeat("type=SYSCALL msg=audit(1:1): a0=4141\n", 50))

	rules := pipelineRulesF(f)
	eng := New(rules, nil, nil)
	reg := parser.Registry()

	f.Fuzz(func(t *testing.T, data string) {
		for _, name := range []string{"auditd", "laurel"} {
			p, ok := reg[name]
			if !ok {
				continue
			}
			events, _ := p.Parse(strings.NewReader(data)) // error is fine; a panic is not
			for _, ev := range events {
				_ = eng.Match(ev) // raw path, no recover: a panic fails the fuzz
			}
		}
	})
}

// pipelineRulesF is the *testing.F twin of pipelineRules.
func pipelineRulesF(f *testing.F) []*sigma.Rule {
	f.Helper()
	ymls := []string{
		"detection:\n  s:\n    Image|endswith: [/sh, /bash]\n  n:\n    CommandLine|contains: /dev/tcp/\n  condition: s and n\n",
		"detection:\n  s:\n    TargetFilename|contains: [/etc/shadow, id_rsa]\n  condition: s\n",
		"detection:\n  s:\n    CommandLine|re: 'https?://(\\d{1,3}\\.){3}\\d{1,3}'\n  condition: s\n",
	}
	rules := make([]*sigma.Rule, 0, len(ymls))
	for i, y := range ymls {
		r, err := sigma.Compile([]byte(y))
		if err != nil {
			f.Fatalf("seed rule %d: %v", i, err)
		}
		r.Name = "r"
		rules = append(rules, r)
	}
	return rules
}
