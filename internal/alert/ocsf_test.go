package alert

import (
	"encoding/json"
	"testing"
	"time"

	"github.com/conor-sometimes/banken/internal/event"
	"pgregory.net/rapid"
)

var testOpts = OCSFOptions{
	ProductVersion: "test",
	Hostname:       "golden-host",
	Now:            func() time.Time { return time.Date(2026, 10, 31, 12, 0, 0, 0, time.UTC) },
}

func TestOCSFSeverity(t *testing.T) {
	cases := []struct {
		level string
		id    int
		sev   string
	}{
		{"critical", 5, "Critical"},
		{"CRITICAL", 5, "Critical"}, // case-insensitive
		{"high", 4, "High"},
		{"medium", 3, "Medium"},
		{"low", 2, "Low"},
		{"informational", 1, "Informational"},
		{"", 0, "Unknown"},
		{"severe", 99, "severe"}, // unknown -> 99 Other, raw string as caption
	}
	for _, c := range cases {
		id, sev := ocsfSeverity(c.level)
		if id != c.id || sev != c.sev {
			t.Errorf("ocsfSeverity(%q) = (%d,%q), want (%d,%q)", c.level, id, sev, c.id, c.sev)
		}
	}
}

func TestOCSFAttacks(t *testing.T) {
	cases := []struct {
		name string
		tags []string
		want []ocsfAttack
	}{
		{
			name: "tactic + sub-technique",
			tags: []string{"attack.defense-evasion", "attack.t1562.001"},
			want: []ocsfAttack{{
				Tactic:       &ocsfIDName{UID: "TA0005", Name: "Defense Evasion"},
				Technique:    &ocsfIDName{UID: "T1562"},
				SubTechnique: &ocsfIDName{UID: "T1562.001"},
			}},
		},
		{
			name: "technique without sub",
			tags: []string{"attack.execution", "attack.t1059"},
			want: []ocsfAttack{{
				Tactic:    &ocsfIDName{UID: "TA0002", Name: "Execution"},
				Technique: &ocsfIDName{UID: "T1059"},
			}},
		},
		{
			name: "two techniques, one tactic -> one object each",
			tags: []string{"attack.persistence", "attack.t1053.003", "attack.t1543.002"},
			want: []ocsfAttack{
				{Tactic: &ocsfIDName{UID: "TA0003", Name: "Persistence"}, Technique: &ocsfIDName{UID: "T1053"}, SubTechnique: &ocsfIDName{UID: "T1053.003"}},
				{Tactic: &ocsfIDName{UID: "TA0003", Name: "Persistence"}, Technique: &ocsfIDName{UID: "T1543"}, SubTechnique: &ocsfIDName{UID: "T1543.002"}},
			},
		},
		{
			name: "tactic only",
			tags: []string{"attack.impact"},
			want: []ocsfAttack{{Tactic: &ocsfIDName{UID: "TA0040", Name: "Impact"}}},
		},
		{
			name: "unknown tactic dropped, non-attack tags ignored",
			tags: []string{"attack.not-a-tactic", "cve.2021-4034", "tlp.red"},
			want: nil,
		},
		{
			name: "no tags -> no attacks",
			tags: nil,
			want: nil,
		},
	}
	for _, c := range cases {
		t.Run(c.name, func(t *testing.T) {
			got := ocsfAttacks(c.tags)
			gotJSON, _ := json.Marshal(got)
			wantJSON, _ := json.Marshal(c.want)
			if string(gotJSON) != string(wantJSON) {
				t.Errorf("ocsfAttacks(%v):\n got  %s\n want %s", c.tags, gotJSON, wantJSON)
			}
		})
	}
}

func TestOCSFUIDDeterministic(t *testing.T) {
	base := Alert{
		Kind: KindSigma, Rule: "r", RuleID: "id",
		Time:  time.Date(2026, 10, 31, 12, 0, 0, 0, time.UTC),
		Event: event.Event{Source: "auditd", Image: "/bin/sh", CommandLine: "sh -c x", User: "1000", PID: 42},
	}
	u1 := ocsfUID(base)
	if len(u1) != 32 {
		t.Fatalf("uid length = %d, want 32", len(u1))
	}
	if ocsfUID(base) != u1 {
		t.Error("uid not stable for the same alert")
	}
	// Changing any tuple field changes the uid.
	mutators := []func(*Alert){
		func(a *Alert) { a.Kind = KindIOC },
		func(a *Alert) { a.Rule = "other" },
		func(a *Alert) { a.RuleID = "other" },
		func(a *Alert) { a.Time = a.Time.Add(time.Nanosecond) },
		func(a *Alert) { a.Event.Source = "laurel" },
		func(a *Alert) { a.Event.PID = 43 },
		func(a *Alert) { a.Event.Image = "/bin/bash" },
		func(a *Alert) { a.Event.CommandLine = "sh -c y" },
		func(a *Alert) { a.Event.User = "0" },
		func(a *Alert) { a.IOC = "1.2.3.4" },
		func(a *Alert) { a.Field = "CommandLine" },
	}
	seen := map[string]int{u1: -1}
	for i, m := range mutators {
		a := base
		m(&a)
		u := ocsfUID(a)
		if u == u1 {
			t.Errorf("mutator %d did not change the uid", i)
		}
		if prev, dup := seen[u]; dup {
			t.Errorf("mutator %d collided with %d", i, prev)
		}
		seen[u] = i
	}
}

func TestOCSFUserSplit(t *testing.T) {
	if u := ocsfUserFor("1000"); u == nil || u.UID != "1000" || u.Name != "" {
		t.Errorf("numeric user -> uid, got %+v", u)
	}
	if u := ocsfUserFor("0"); u == nil || u.UID != "0" {
		t.Errorf("uid 0 -> uid, got %+v", u)
	}
	if u := ocsfUserFor("root"); u == nil || u.Name != "root" || u.UID != "" {
		t.Errorf("name user -> name, got %+v", u)
	}
	if u := ocsfUserFor(""); u != nil {
		t.Errorf("empty user -> nil, got %+v", u)
	}
}

func TestOCSFZeroTimeFallback(t *testing.T) {
	a := Alert{Kind: KindSigma, Rule: "r", Title: "t", Level: "high", Event: event.Event{Source: "auditd"}}
	f := ToOCSF(a, testOpts)
	if f.Time != testOpts.Now().UTC().UnixMilli() {
		t.Errorf("zero Alert.Time should use Options.Now, got %d", f.Time)
	}
	if f.Metadata.OriginalTime != "" {
		t.Errorf("zero Alert.Time should omit original_time, got %q", f.Metadata.OriginalTime)
	}
	// A non-zero time sets original_time.
	a.Time = time.Date(2026, 10, 31, 12, 0, 0, 0, time.UTC)
	f = ToOCSF(a, testOpts)
	if f.Metadata.OriginalTime != "2026-10-31T12:00:00Z" {
		t.Errorf("original_time = %q", f.Metadata.OriginalTime)
	}
}

func TestOCSFEmptyHostnameOmitsDevice(t *testing.T) {
	a := Alert{Kind: KindSigma, Rule: "r", Title: "t", Level: "high", Event: event.Event{Source: "auditd", Image: "/bin/sh"}}
	f := ToOCSF(a, OCSFOptions{Now: testOpts.Now})
	if f.Device != nil {
		t.Errorf("empty hostname should omit device, got %+v", f.Device)
	}
	for _, o := range f.Observables {
		if o.TypeID == 1 && o.Type == "Hostname" {
			t.Errorf("empty hostname should omit the hostname observable, got %+v", o)
		}
	}
}

func TestOCSFRawSorted(t *testing.T) {
	a := Alert{
		Kind: KindSigma, Rule: "r", Title: "t", Level: "high",
		Event: event.Event{Source: "auditd", Raw: map[string]string{"Zeta": "z", "Alpha": "a", "Mu": "m"}},
	}
	f := ToOCSF(a, testOpts)
	for _, k := range []string{"raw.Alpha", "raw.Mu", "raw.Zeta"} {
		if _, ok := f.Unmapped[k]; !ok {
			t.Errorf("unmapped missing %q", k)
		}
	}
	// encoding/json sorts map keys, so the serialized order is deterministic.
	b, _ := json.Marshal(f.Unmapped)
	if !json.Valid(b) {
		t.Error("unmapped is not valid JSON")
	}
}

func TestOCSFIOCObservableByShape(t *testing.T) {
	cases := []struct {
		ioc    string
		typeID int
		typ    string
	}{
		{"192.0.2.44", 2, "IP Address"},
		{"evil.example.com", 1, "Hostname"},
		{"/tmp/loot", 7, "File Name"},
	}
	for _, c := range cases {
		a := Alert{Kind: KindIOC, Rule: "feed.txt", Title: "IOC match", Level: "high", IOC: c.ioc, Field: "CommandLine", Event: event.Event{Source: "auditd"}}
		f := ToOCSF(a, testOpts)
		if f.FindingInfo.Analytic.TypeID != 9 || f.FindingInfo.Analytic.Type != "Exact Data Match" {
			t.Errorf("IOC analytic = %+v, want Exact Data Match (9)", f.FindingInfo.Analytic)
		}
		var found bool
		for _, o := range f.Observables {
			if o.Value == c.ioc {
				found = true
				if o.TypeID != c.typeID || o.Type != c.typ {
					t.Errorf("IOC %q observable = (%d,%q), want (%d,%q)", c.ioc, o.TypeID, o.Type, c.typeID, c.typ)
				}
			}
		}
		if !found {
			t.Errorf("IOC %q produced no observable", c.ioc)
		}
		if len(f.Osint) != 1 || f.Osint[0].Value != c.ioc || f.Metadata.Profiles[len(f.Metadata.Profiles)-1] != "osint" {
			t.Errorf("IOC %q: osint = %+v, profiles = %v", c.ioc, f.Osint, f.Metadata.Profiles)
		}
	}
}

// FuzzOCSF is the never-die property: an arbitrary Alert (random strings in
// every field, non-UTF-8 and control characters included -- the parsers
// hex-decode anything) must encode without error and the output must be valid
// JSON. A mapper bug degrades one output via the sink's Emit error; it never
// panics the scan.
func FuzzOCSF(f *testing.F) {
	f.Add("sigma", "r", "id", "crit", "auditd", "/bin/sh", "sh -c x", "1000", "", "", 42)
	f.Fuzz(func(t *testing.T, kind, rule, ruleID, level, source, image, cmd, user, ioc, field string, pid int) {
		a := Alert{
			Kind: kind, Rule: rule, RuleID: ruleID, Title: rule, Level: level,
			IOC: ioc, Field: field, Tags: []string{"attack.execution", "attack.t1059.004"},
			Event: event.Event{Source: source, Image: image, CommandLine: cmd, User: user, PID: pid},
		}
		b, err := EncodeOCSF(testOpts)(a)
		if err != nil {
			t.Fatalf("EncodeOCSF errored: %v", err)
		}
		if !json.Valid(b) {
			t.Fatalf("EncodeOCSF produced invalid JSON: %q", b)
		}
	})
}

// TestOCSFRapid is the same property under rapid, exercising structured
// variety the corpus seed does not reach.
func TestOCSFRapid(t *testing.T) {
	rapid.Check(t, func(t *rapid.T) {
		a := Alert{
			Kind:    rapid.SampledFrom([]string{KindSigma, KindIOC, "weird"}).Draw(t, "kind"),
			Rule:    rapid.String().Draw(t, "rule"),
			RuleID:  rapid.String().Draw(t, "ruleID"),
			Title:   rapid.String().Draw(t, "title"),
			Level:   rapid.SampledFrom([]string{"critical", "high", "medium", "low", "informational", "", "severe"}).Draw(t, "level"),
			IOC:     rapid.String().Draw(t, "ioc"),
			Field:   rapid.String().Draw(t, "field"),
			Message: rapid.String().Draw(t, "msg"),
			Event: event.Event{
				Source:      rapid.String().Draw(t, "source"),
				Image:       rapid.String().Draw(t, "image"),
				CommandLine: rapid.String().Draw(t, "cmd"),
				User:        rapid.String().Draw(t, "user"),
				PID:         rapid.Int().Draw(t, "pid"),
				PPID:        rapid.Int().Draw(t, "ppid"),
			},
		}
		b, err := EncodeOCSF(testOpts)(a)
		if err != nil {
			t.Fatalf("EncodeOCSF errored: %v", err)
		}
		if !json.Valid(b) {
			t.Fatalf("invalid JSON: %q", b)
		}
	})
}
