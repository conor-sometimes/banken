package main

import (
	"strings"
	"testing"
)

const sample = `goos: linux
goarch: amd64
pkg: github.com/conor-sometimes/banken/internal/sigma
cpu: Test CPU @ 3.00GHz
BenchmarkMatcher100-8   	  800000	       700.0 ns/op	     364 B/op	       4 allocs/op
BenchmarkMatcher100-8   	  800000	       900.0 ns/op	     364 B/op	       4 allocs/op
BenchmarkMatcher100-8   	  800000	       710.0 ns/op	     364 B/op	       4 allocs/op
PASS
ok  	github.com/conor-sometimes/banken/internal/sigma	1.0s
pkg: github.com/conor-sometimes/banken
BenchmarkDetectionLatency/threat-8   	  1000	  2000 ns/op	  10 B/op	  1 allocs/op
`

func TestParseMedian(t *testing.T) {
	l, err := Parse(strings.NewReader(sample))
	if err != nil {
		t.Fatal(err)
	}
	if l.Goos != "linux" || l.Goarch != "amd64" || l.CPU != "Test CPU @ 3.00GHz" {
		t.Fatalf("machine fields wrong: %+v", l)
	}
	m := l.Benchmarks["internal/sigma.BenchmarkMatcher100"]
	if m["ns/op"] != 710 {
		t.Fatalf("median ns/op = %v, want 710 (the noisy 900 must not win)", m["ns/op"])
	}
	if m["allocs/op"] != 4 || m["B/op"] != 364 {
		t.Fatalf("benchmem units wrong: %v", m)
	}
	if l.Count != 3 {
		t.Fatalf("count = %d, want 3", l.Count)
	}
	if _, ok := l.Benchmarks["banken.BenchmarkDetectionLatency/threat"]; !ok {
		t.Fatalf("root package / sub-benchmark key missing: %v", l.Benchmarks)
	}
}

func TestParseEmptyIsError(t *testing.T) {
	if _, err := Parse(strings.NewReader("PASS\nok  \tx\t0.1s\n")); err == nil {
		t.Fatal("input with no benchmark lines must be an error, not an empty history row")
	}
}
