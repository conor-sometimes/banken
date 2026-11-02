package view_test

import (
	"bytes"
	"flag"
	"os"
	"path/filepath"
	"testing"
	"time"

	"github.com/conor-sometimes/banken/internal/response"
	"github.com/conor-sometimes/banken/internal/response/view"
)

// updateGolden rewrites the golden files from the current output. Run with
//
//	go test ./internal/response/view/ -update
//
// then commit the refreshed tests/respond/golden/*. A normal run only reads.
var updateGolden = flag.Bool("update", false, "rewrite golden files under tests/respond/golden")

// fixtureRoot is the committed fixture tree; goldenDir holds the expected
// output. Both are rooted at the repo's tests/respond, three levels up from
// this package.
const (
	fixtureRoot = "../../../tests/respond/tree"
	goldenDir   = "../../../tests/respond/golden"
)

// fixedNow pins the clock so the window math and the WHEN column are
// reproducible: noon on the fixture day, well inside the default 24h list
// window and the 7d explain window.
var fixedNow = time.Date(2026, 11, 2, 12, 0, 0, 0, time.UTC)

// newFixtureReader builds a Reader and a MapProber over the committed fixture
// tree. The dir names match what the CLI passes (ledger "response", the three
// stores by name, the spool "spool"), so the test exercises the same paths.
func newFixtureReader(t *testing.T) (*view.Reader, view.Prober) {
	t.Helper()
	root := os.DirFS(fixtureRoot)
	prober, err := view.LoadMapProber(root, "live.json")
	if err != nil {
		t.Fatalf("load live.json: %v", err)
	}
	r := view.NewReader(root, "response", "freeze", "quarantine", "evidence", "spool")
	return r, prober
}

// assertGolden compares got to tests/respond/golden/<name>, or rewrites it
// under -update. A diff fails with both sides printed.
func assertGolden(t *testing.T, name string, got []byte) {
	t.Helper()
	path := filepath.Join(goldenDir, name)
	if *updateGolden {
		if err := os.MkdirAll(goldenDir, 0o755); err != nil {
			t.Fatalf("mkdir golden: %v", err)
		}
		if err := os.WriteFile(path, got, 0o644); err != nil {
			t.Fatalf("write golden %s: %v", name, err)
		}
		return
	}
	want, err := os.ReadFile(path)
	if err != nil {
		t.Fatalf("read golden %s: %v (run -update to create it)", name, err)
	}
	if !bytes.Equal(got, want) {
		t.Errorf("%s mismatch\n--- got ---\n%s\n--- want ---\n%s", name, got, want)
	}
}

func TestListGolden(t *testing.T) {
	r, prober := newFixtureReader(t)

	cases := []struct {
		name string
		opts view.ListOptions
	}{
		{"list.txt", view.ListOptions{Now: fixedNow}},
		{"list-freeze.txt", view.ListOptions{Now: fixedNow, Kind: response.ActionFreeze}},
		{"list-held.txt", view.ListOptions{Now: fixedNow, State: "held"}},
		{"list-lost.txt", view.ListOptions{Now: fixedNow, State: "lost"}},
	}
	for _, tc := range cases {
		rows, err := r.List(prober, tc.opts)
		if err != nil {
			t.Fatalf("%s: list: %v", tc.name, err)
		}
		var buf bytes.Buffer
		view.RenderList(&buf, rows)
		assertGolden(t, tc.name, buf.Bytes())
	}
}

func TestListJSONGolden(t *testing.T) {
	r, prober := newFixtureReader(t)
	rows, err := r.List(prober, view.ListOptions{Now: fixedNow})
	if err != nil {
		t.Fatalf("list: %v", err)
	}
	var buf bytes.Buffer
	if err := view.RenderListJSON(&buf, rows); err != nil {
		t.Fatalf("render json: %v", err)
	}
	assertGolden(t, "list.json", buf.Bytes())
}

func TestExplainGolden(t *testing.T) {
	r, prober := newFixtureReader(t)
	cases := []struct {
		name string
		id   string
	}{
		{"explain-frozen.txt", "a1a1a1a1a1a1a1a1a1a1a1a1"},      // handle id -> full executed chain
		{"explain-by-decision.txt", "d0f0f0f0f0f0f0f0f0f0f0f0"}, // same chain, addressed by decision id
		{"explain-never.txt", "d0aaaaaaaaaaaaaaaaaaaaaa"},       // decided, never requested
		{"explain-downgraded.txt", "d0bbbbbbbbbbbbbbbbbbbbbb"},  // requested kill, downgraded to freeze
	}
	for _, tc := range cases {
		exp, err := r.Explain(prober, tc.id, view.ExplainOptions{Now: fixedNow})
		if err != nil {
			t.Fatalf("%s: explain %s: %v", tc.name, tc.id, err)
		}
		var buf bytes.Buffer
		view.RenderExplain(&buf, exp)
		assertGolden(t, tc.name, buf.Bytes())
	}
}

func TestExplainUnknownID(t *testing.T) {
	r, prober := newFixtureReader(t)
	if _, err := r.Explain(prober, "ffffffffffffffffffffffff", view.ExplainOptions{Now: fixedNow}); err == nil {
		t.Fatal("explain of an unknown id: want error (the CLI maps this to exit 1), got nil")
	}
	// A query shorter than the 8-char minimum is a usage error, not a lookup.
	if _, err := r.Explain(prober, "a1a1", view.ExplainOptions{Now: fixedNow}); err == nil {
		t.Fatal("explain of a too-short id: want error, got nil")
	}
}

// TestComputeStateMapping pins the §3.1 state string for each handle directly
// from the store entry plus its live facts, independent of rendering, so the
// classification is asserted structurally for every state the fixtures cover.
func TestComputeStateMapping(t *testing.T) {
	r, prober := newFixtureReader(t)
	rows, err := r.List(prober, view.ListOptions{Now: fixedNow})
	if err != nil {
		t.Fatalf("list: %v", err)
	}
	want := map[string]view.State{
		"a1a1a1a1a1a1a1a1a1a1a1a1": "frozen (2 pids)",
		"b2b2b2b2b2b2b2b2b2b2b2b2": "thawed 06:40:00",
		"c3c3c3c3c3c3c3c3c3c3c3c3": "held sha256 ok",
		"d4d4d4d4d4d4d4d4d4d4d4d4": "held CHANGED (was 11111111, now 22222222)",
		"e5e5e5e5e5e5e5e5e5e5e5e5": "TAMPERED (mode 0755, immutable 0)",
		"f6f6f6f6f6f6f6f6f6f6f6f6": "lost (reboot)",
		"a7a7a7a7a7a7a7a7a7a7a7a7": "lost (inode replaced)",
		"b8b8b8b8b8b8b8b8b8b8b8b8": "killed (pidfd)",
	}
	got := make(map[string]view.State, len(rows))
	for _, row := range rows {
		got[row.ID] = row.State
	}
	for id, w := range want {
		if got[id] != w {
			t.Errorf("state for %s: got %q, want %q", id[:8], got[id], w)
		}
	}
	if len(got) != len(want) {
		t.Errorf("row count: got %d, want %d", len(got), len(want))
	}
}
