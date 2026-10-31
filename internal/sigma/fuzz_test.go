package sigma

import (
	"testing"

	"github.com/conor-sometimes/banken/internal/event"
)

// FuzzSigmaParse asserts that compiling arbitrary rule YAML never panics:
// a malformed rule must come back as a clean error, never a crash, because
// a crash in rule loading is a crash of the whole detector.
func FuzzSigmaParse(f *testing.F) {
	seeds := []string{
		"",
		"not yaml: [",
		"detection:\n  sel:\n    Image|endswith: /a\n  condition: sel\n",
		"detection:\n  sel:\n    CommandLine|re: '('\n  condition: sel\n",
		"detection:\n  a:\n    Image: x\n  b:\n    User: y\n  condition: a and (b or not a)\n",
		"detection:\n  sel:\n    Image|contains|all: [a, b]\n  condition: 1 of them\n",
		"detection: {}\n",
		"detection:\n  condition: sel\n",
		"detection:\n  sel: []\n  condition: sel\n",
		"detection:\n  sel: 5\n  condition: sel\n",
		"detection:\n  sel:\n    Image|endswith:\n      - [nested]\n  condition: sel\n",
	}
	for _, s := range seeds {
		f.Add(s)
	}
	f.Fuzz(func(t *testing.T, data string) {
		rule, err := Compile([]byte(data))
		// Either a clean error or a usable rule -- never a panic, and never
		// a nil rule with a nil error.
		if err == nil && rule == nil {
			t.Fatalf("Compile returned (nil, nil) for %q", data)
		}
		if err == nil {
			// A compiled rule must match without panicking on any event.
			_ = rule.Match(event.Event{})
		}
	})
}

// FuzzMatch asserts that a compiled rule matched against arbitrary event
// field values never panics -- the fields come straight from a parsed log,
// i.e. from untrusted bytes.
func FuzzMatch(f *testing.F) {
	rule, err := Compile([]byte(`detection:
  reader:
    Image|endswith: [/cat, /base64]
  secret:
    CommandLine|contains: [id_rsa, /etc/shadow]
  ip:
    CommandLine|re: 'https?://(\d{1,3}\.){3}\d{1,3}'
  condition: (reader and secret) or ip`))
	if err != nil {
		f.Fatalf("seed rule failed to compile: %v", err)
	}

	f.Add("/usr/bin/cat", "cat /home/u/.ssh/id_rsa", "/etc/shadow", "root")
	f.Add("", "", "", "")
	f.Add("\x00\x00", "curl http://1.2.3.4/x", "\xff\xfe", "\x00")
	f.Add("/bin/\uFFFD", "日本語 http://999.999.999.999", "", "🔥")

	f.Fuzz(func(t *testing.T, image, cmd, target, user string) {
		ev := event.Event{
			Image:          image,
			CommandLine:    cmd,
			TargetFilename: target,
			User:           user,
		}
		_ = rule.Match(ev) // must never panic; result is irrelevant
	})
}
