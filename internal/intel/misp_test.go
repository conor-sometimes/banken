package intel

import (
	"os"
	"strings"
	"testing"
)

func TestParseMISPEvent(t *testing.T) {
	f, err := os.Open("testdata/misp_event.json")
	if err != nil {
		t.Fatal(err)
	}
	defer func() { _ = f.Close() }()

	inds, err := ParseMISP(f, "misp-sample")
	if err != nil {
		t.Fatalf("ParseMISP: %v", err)
	}
	want := map[string]Type{
		"198.51.100.45":                     TypeIPv4,
		"loader.evil.example":               TypeDomain,
		"http://loader.evil.example/beacon": TypeURL,
		"aa61ce8c3b2f9e6d5a4b7c8d9e0f1a2b3c4d5e6f70819a2b3c4d5e6f7a8b9c0d1": TypeHash,
		"/tmp/update-helper":               TypeFile,
		"d41d8cd98f00b204e9800998ecf8427e": TypeHash,
	}
	got := indexByValue(inds)
	assertIndicators(t, got, want)

	// to_ids:false attribute (203.0.113.200) must be dropped.
	if _, ok := got["203.0.113.200"]; ok {
		t.Error("to_ids:false attribute 203.0.113.200 should be dropped")
	}
}

func TestParseMISPSearchAndComposites(t *testing.T) {
	f, err := os.Open("testdata/misp_search.json")
	if err != nil {
		t.Fatal(err)
	}
	defer func() { _ = f.Close() }()

	inds, err := ParseMISP(f, "misp-search")
	if err != nil {
		t.Fatalf("ParseMISP: %v", err)
	}
	want := map[string]Type{
		"198.51.100.88": TypeIPv4, // from ip-dst|port, port half dropped
		"svc-helper":    TypeFile, // from filename|sha1
		"da39a3ee5e6b4b0d3255bfef95601890afd80709": TypeHash, // from filename|sha1
		"c2.search.example":                        TypeDomain,
	}
	got := indexByValue(inds)
	assertIndicators(t, got, want)

	// mutex has no banken match.
	for v := range got {
		if strings.Contains(v, "Mutex") {
			t.Errorf("mutex leaked: %q", v)
		}
	}
}

func TestParseMISPBadJSON(t *testing.T) {
	if _, err := ParseMISP(strings.NewReader("{bad"), "s"); err == nil {
		t.Fatal("expected decode error")
	}
}
