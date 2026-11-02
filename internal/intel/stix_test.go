package intel

import (
	"os"
	"strings"
	"testing"
)

func TestParseSTIXBundle(t *testing.T) {
	f, err := os.Open("testdata/stix_bundle.json")
	if err != nil {
		t.Fatal(err)
	}
	defer func() { _ = f.Close() }()

	inds, err := ParseSTIX(f, "stix-sample")
	if err != nil {
		t.Fatalf("ParseSTIX: %v", err)
	}

	want := map[string]Type{
		"198.51.100.23": TypeIPv4,
		"evil.example":  TypeDomain,
		"http://downloads.evil.example/stage2.bin": TypeURL,
		"backup-c2.test": TypeDomain,
		"e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855": TypeHash,
		"203.0.113.77": TypeIPv4,
	}
	got := indexByValue(inds)
	assertIndicators(t, got, want)

	// The windows-registry-key indicator has no banken match and must be absent.
	for v := range got {
		if strings.Contains(strings.ToLower(v), "software") {
			t.Errorf("registry-key indicator leaked into normalised set: %q", v)
		}
	}
	// Source propagates to every indicator.
	for _, ind := range inds {
		if ind.Source != "stix-sample" {
			t.Errorf("indicator %q source = %q, want stix-sample", ind.Value, ind.Source)
		}
	}
}

func TestIndicatorsFromPattern(t *testing.T) {
	cases := []struct {
		name    string
		pattern string
		want    map[string]Type
	}{
		{
			name:    "single ipv4",
			pattern: "[ipv4-addr:value = '192.0.2.5']",
			want:    map[string]Type{"192.0.2.5": TypeIPv4},
		},
		{
			name:    "ipv6",
			pattern: "[ipv6-addr:value = '2001:db8::1']",
			want:    map[string]Type{"2001:db8::1": TypeIPv6},
		},
		{
			name:    "OR join yields both",
			pattern: "[domain-name:value = 'a.test'] OR [domain-name:value = 'b.test']",
			want:    map[string]Type{"a.test": TypeDomain, "b.test": TypeDomain},
		},
		{
			name:    "AND join yields both",
			pattern: "[url:value = 'http://a.test/x'] AND [ipv4-addr:value = '192.0.2.9']",
			want:    map[string]Type{"http://a.test/x": TypeURL, "192.0.2.9": TypeIPv4},
		},
		{
			name:    "file hash by quoted path",
			pattern: "[file:hashes.'SHA-256' = 'abc123']",
			want:    map[string]Type{"abc123": TypeHash},
		},
		{
			name:    "file hash by bare MD5 path, no spaces",
			pattern: "[file:hashes.MD5='d41d8cd98f00b204e9800998ecf8427e']",
			want:    map[string]Type{"d41d8cd98f00b204e9800998ecf8427e": TypeHash},
		},
		{
			name:    "file name",
			pattern: "[file:name = 'dropper.exe']",
			want:    map[string]Type{"dropper.exe": TypeFile},
		},
		{
			name:    "double-quoted value",
			pattern: "[domain-name:value = \"quoted.test\"]",
			want:    map[string]Type{"quoted.test": TypeDomain},
		},
		{
			name:    "escaped quote in value",
			pattern: "[file:name = 'it\\'s-bad']",
			want:    map[string]Type{"it's-bad": TypeFile},
		},
		{
			name:    "unknown object type is skipped",
			pattern: "[email-addr:value = 'evil@phish.test']",
			want:    map[string]Type{},
		},
		{
			name:    "file property banken does not match is skipped",
			pattern: "[file:size = '4096']",
			want:    map[string]Type{},
		},
	}
	for _, c := range cases {
		t.Run(c.name, func(t *testing.T) {
			got := indexByValue(indicatorsFromPattern(c.pattern, "p"))
			assertIndicators(t, got, c.want)
		})
	}
}

func TestParseSTIXBadJSON(t *testing.T) {
	_, err := ParseSTIX(strings.NewReader("{not json"), "s")
	if err == nil {
		t.Fatal("expected a decode error on malformed JSON")
	}
}

// indexByValue maps indicator value -> type for order-independent assertions.
func indexByValue(inds []Indicator) map[string]Type {
	m := make(map[string]Type, len(inds))
	for _, ind := range inds {
		m[ind.Value] = ind.Type
	}
	return m
}

func assertIndicators(t *testing.T, got, want map[string]Type) {
	t.Helper()
	if len(got) != len(want) {
		t.Errorf("got %d indicators %v, want %d %v", len(got), got, len(want), want)
	}
	for v, wt := range want {
		gt, ok := got[v]
		if !ok {
			t.Errorf("missing indicator %q (want type %s)", v, wt)
			continue
		}
		if gt != wt {
			t.Errorf("indicator %q type = %s, want %s", v, gt, wt)
		}
	}
	for v := range got {
		if _, ok := want[v]; !ok {
			t.Errorf("unexpected indicator %q (type %s)", v, got[v])
		}
	}
}
