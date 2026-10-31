package parser

import (
	"encoding/json"
	"flag"
	"os"
	"path/filepath"
	"strings"
	"testing"
)

// goldenUpdate rewrites the .golden files from the current parser output.
// Run `go test ./internal/parser -update` after an intentional parser
// change, then review the diff in the .golden files before committing.
var goldenUpdate = flag.Bool("update", false, "update parser golden files")

// TestGolden parses a realistic multi-event sample per source and asserts
// the normalised events match a checked-in golden file byte for byte. This
// is the regression guard for the whole fold/decode path: a change that
// silently alters how any field is normalised shows up as a golden diff.
func TestGolden(t *testing.T) {
	cases := []struct {
		name   string
		parser Parser
		input  string
	}{
		{"auditd", Auditd{}, "testdata/auditd_sample.audit"},
		{"laurel", Laurel{}, "testdata/laurel_sample.jsonl"},
	}
	for _, c := range cases {
		t.Run(c.name, func(t *testing.T) {
			data, err := os.ReadFile(c.input)
			if err != nil {
				t.Fatalf("read input: %v", err)
			}
			events, err := c.parser.Parse(strings.NewReader(string(data)))
			if err != nil {
				t.Fatalf("parse: %v", err)
			}
			got, err := json.MarshalIndent(events, "", "  ")
			if err != nil {
				t.Fatalf("marshal: %v", err)
			}
			got = append(got, '\n')

			goldenPath := filepath.Join("testdata", c.name+".golden")
			if *goldenUpdate {
				if err := os.WriteFile(goldenPath, got, 0o600); err != nil {
					t.Fatalf("write golden: %v", err)
				}
				return
			}
			want, err := os.ReadFile(goldenPath)
			if err != nil {
				t.Fatalf("read golden (run -update to create): %v", err)
			}
			if string(got) != string(want) {
				t.Errorf("golden mismatch for %s.\n--- got ---\n%s\n--- want ---\n%s", c.name, got, want)
			}
		})
	}
}
