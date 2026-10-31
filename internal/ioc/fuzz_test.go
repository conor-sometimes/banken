package ioc

import (
	"strings"
	"testing"

	"github.com/conor-sometimes/banken/internal/event"
)

// FuzzIOC asserts that loading an arbitrary indicator list and then
// matching an arbitrary event against it never panics -- both the feed
// bytes and the event fields come from untrusted sources.
func FuzzIOC(f *testing.F) {
	f.Add("192.0.2.1\nevil.example\nxmrig\n", "curl http://192.0.2.1/x")
	f.Add("", "")
	f.Add("#only a comment\n", "anything")
	f.Add(string([]byte{0, 255, '\n', '.', '.', '.'}), string([]byte{0, 1, 2}))
	f.Add(strings.Repeat("a.", 5000)+"\n", strings.Repeat("a.b ", 1000))
	f.Add(":::::\n...\n/\n\\\n", "/\\::.. ...")

	f.Fuzz(func(t *testing.T, feed, cmd string) {
		s := NewSet()
		s.Read(strings.NewReader(feed), "fuzz")
		// Matching must never panic regardless of feed or event content.
		_ = s.Match(event.Event{
			CommandLine:    cmd,
			Image:          cmd,
			TargetFilename: cmd,
		})
	})
}
