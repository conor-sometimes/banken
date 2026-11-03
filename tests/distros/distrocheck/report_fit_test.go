package main

import (
	"encoding/json"
	"strings"
	"testing"

	"github.com/conor-sometimes/banken/tests/distros/report"
)

// TestFitReport proves the report-disk guard: a report far larger than the disk
// is shrunk to fit, but every check's ID and Pass verdict survives and the
// output is still valid JSON. Without this, an oversized report overruns the
// fixed disk, is written without a trailing NUL, and the host loses the whole
// distro's result.
func TestFitReport(t *testing.T) {
	// 400 checks, each with a 10 KiB detail -> ~4 MiB, well over a 1 MiB disk.
	huge := strings.Repeat("x", 10*1024)
	var checks []report.Check
	for i := 0; i < 400; i++ {
		id := "B1/fam" + string(rune('a'+i%26))
		checks = append(checks, report.Check{ID: id, Pass: i%2 == 0, Detail: huge})
	}
	r := report.Report{
		Distro: "ubuntu-24.04",
		Info:   map[string]string{"kernel": huge}, // bulky Info too
		Checks: checks,
	}

	const cap = report.DiskSize
	got := fitReport(r, cap)

	// 1. It fits, with room for emit's newline.
	data, err := json.Marshal(got)
	if err != nil {
		t.Fatalf("marshal: %v", err)
	}
	if len(data)+1 > cap {
		t.Fatalf("report is %d bytes, over the %d-byte disk", len(data)+1, cap)
	}

	// 2. It is still valid JSON the host can parse.
	var round report.Report
	if err := json.Unmarshal(data, &round); err != nil {
		t.Fatalf("shrunk report is not valid JSON: %v", err)
	}

	// 3. Every verdict (ID + Pass) survived, in order.
	if len(round.Checks) != len(r.Checks) {
		t.Fatalf("lost checks: %d of %d", len(round.Checks), len(r.Checks))
	}
	for i := range r.Checks {
		if round.Checks[i].ID != r.Checks[i].ID || round.Checks[i].Pass != r.Checks[i].Pass {
			t.Errorf("check %d verdict changed: got {%s,%v} want {%s,%v}",
				i, round.Checks[i].ID, round.Checks[i].Pass, r.Checks[i].ID, r.Checks[i].Pass)
		}
	}
}

// TestFitReportSmallUnchanged: a report that already fits is returned untouched,
// detail and all.
func TestFitReportSmallUnchanged(t *testing.T) {
	r := report.Report{
		Distro: "rocky-9",
		Info:   map[string]string{"kernel": "5.14"},
		Checks: []report.Check{{ID: "A1", Pass: true, Detail: "installed clean"}},
	}
	got := fitReport(r, report.DiskSize)
	if got.Checks[0].Detail != "installed clean" || got.Info["kernel"] != "5.14" {
		t.Errorf("a fitting report was altered: %+v", got)
	}
}
