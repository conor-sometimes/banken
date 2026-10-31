// Command sigmacov measures what fraction of a Sigma rule tree banken's
// compiler accepts, and buckets the rejects by why. It turns "banken evaluates
// X% of the SigmaHQ Linux set" into a measured, honest number (and a roadmap:
// the biggest reject bucket is the next modifier to implement) instead of a
// boast. Point it at a checkout:
//
//	go run ./tools/sigmacov /path/to/sigma/rules/linux
package main

import (
	"fmt"
	"io/fs"
	"os"
	"path/filepath"
	"sort"
	"strings"

	"github.com/conor-sometimes/banken/internal/sigma"
)

func main() {
	if len(os.Args) < 2 {
		fmt.Fprintln(os.Stderr, "usage: sigmacov <rule-dir>...")
		os.Exit(2)
	}

	var total, ok int
	buckets := map[string]int{}
	examples := map[string]string{}

	for _, root := range os.Args[1:] {
		_ = filepath.WalkDir(root, func(p string, d fs.DirEntry, err error) error {
			if err != nil || d.IsDir() {
				return nil //nolint:nilerr // walk errors are not the measurement
			}
			if ext := strings.ToLower(filepath.Ext(p)); ext != ".yml" && ext != ".yaml" {
				return nil
			}
			total++
			data, e := os.ReadFile(p) //nolint:gosec // operator-supplied tree being measured
			if e != nil {
				return nil
			}
			if _, e := sigma.Compile(data); e == nil {
				ok++
			} else {
				b := bucket(e.Error())
				buckets[b]++
				if examples[b] == "" {
					examples[b] = filepath.Base(p) + ": " + e.Error()
				}
			}
			return nil
		})
	}

	if total == 0 {
		fmt.Fprintln(os.Stderr, "no .yml rules found")
		os.Exit(1)
	}
	fmt.Printf("banken loads %d/%d Sigma rules (%.1f%%)\n\n", ok, total, 100*float64(ok)/float64(total))

	type kv struct {
		name  string
		count int
	}
	rejects := make([]kv, 0, len(buckets))
	for k, v := range buckets {
		rejects = append(rejects, kv{k, v})
	}
	sort.Slice(rejects, func(i, j int) bool { return rejects[i].count > rejects[j].count })
	if len(rejects) > 0 {
		fmt.Println("rejected, by reason (biggest first = next thing to implement):")
		for _, r := range rejects {
			fmt.Printf("  %5d  %-26s  e.g. %s\n", r.count, r.name, truncate(examples[r.name], 90))
		}
	}
}

// bucket maps a load error to a coarse reason, so the reject reasons tally
// instead of being thousands of distinct messages.
func bucket(msg string) string {
	m := strings.ToLower(msg)
	switch {
	case strings.Contains(m, "unsupported modifier"):
		if i := strings.Index(m, "modifier \""); i >= 0 {
			rest := m[i+len("modifier \""):]
			if j := strings.IndexByte(rest, '"'); j >= 0 {
				return "modifier |" + rest[:j]
			}
		}
		return "unsupported modifier"
	case strings.Contains(m, "null value"):
		return "null value"
	case strings.Contains(m, "no detection"), strings.Contains(m, "no condition"), strings.Contains(m, "no selections"):
		return "no detection (correlation/meta)"
	case strings.Contains(m, "condition"):
		return "condition syntax"
	case strings.Contains(m, "regexp"):
		return "regexp"
	case strings.Contains(m, "mapping"), strings.Contains(m, "scalar"), strings.Contains(m, "selection must"):
		return "value/selection structure"
	case strings.Contains(m, "invalid yaml"):
		return "invalid yaml"
	default:
		return "other"
	}
}

func truncate(s string, n int) string {
	s = strings.ReplaceAll(s, "\n", " ")
	if len(s) > n {
		return s[:n] + "…"
	}
	return s
}
