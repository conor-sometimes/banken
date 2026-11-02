// Command benchhist turns `go test -bench -benchmem` output into ONE JSON line
// for bench/history.ndjson, the per-commit performance log. The committed
// bench/baseline.txt is the benchstat reference for a delta; the history file is
// the longitudinal record: one line per measured commit, so a regression or an
// improvement shows up as a time series instead of a single diff.
//
//	go test ./... -run '^$' -bench . -benchmem -count=6 | tee bench/new.txt
//	go run ./bench/cmd/benchhist -commit "$(git rev-parse HEAD)" -date "$(date -u +%FT%TZ)" \
//	    -binary-bytes "$(wc -c < output/banken)" < bench/new.txt >> bench/history.ndjson
//
// Each benchmark is reduced to the MEDIAN of its -count repetitions per unit
// (ns/op, B/op, allocs/op, and any custom metric), which is robust to the one
// noisy repetition a shared runner always has. The line also records
// goos/goarch/cpu: rows are only comparable within the same machine, exactly as
// for baseline.txt.
package main

import (
	"bufio"
	"encoding/json"
	"errors"
	"flag"
	"fmt"
	"io"
	"os"
	"sort"
	"strconv"
	"strings"
)

// Line is one history.ndjson record. JSON keys are camelCase like the rest of
// banken; the unit keys inside Benchmarks are Go's own spelling ("ns/op").
type Line struct {
	Commit      string                        `json:"commit"`
	Date        string                        `json:"date"`
	Goos        string                        `json:"goos,omitempty"`
	Goarch      string                        `json:"goarch,omitempty"`
	CPU         string                        `json:"cpu,omitempty"`
	Count       int                           `json:"count"`
	BinaryBytes int64                         `json:"binaryBytes,omitempty"`
	Benchmarks  map[string]map[string]float64 `json:"benchmarks"`
}

func main() {
	commit := flag.String("commit", "", "commit id the numbers were measured at (required)")
	date := flag.String("date", "", "RFC 3339 UTC time of the measurement (required)")
	binBytes := flag.Int64("binary-bytes", 0, "size of the stripped release binary, 0 to omit")
	flag.Parse()
	if *commit == "" || *date == "" {
		fmt.Fprintln(os.Stderr, "benchhist: -commit and -date are required")
		os.Exit(2)
	}
	l, err := Parse(os.Stdin)
	if err != nil {
		fmt.Fprintln(os.Stderr, "benchhist:", err)
		os.Exit(1)
	}
	l.Commit, l.Date, l.BinaryBytes = *commit, *date, *binBytes
	if err := json.NewEncoder(os.Stdout).Encode(l); err != nil {
		fmt.Fprintln(os.Stderr, "benchhist:", err)
		os.Exit(1)
	}
}

// Parse reads `go test -bench` text and returns the median per benchmark and
// unit. It is an error to find no benchmark lines: an empty history row would
// look like a measurement and is not one.
func Parse(r io.Reader) (Line, error) {
	l := Line{Benchmarks: map[string]map[string]float64{}}
	samples := map[string]map[string][]float64{}
	reps := map[string]int{}
	pkg := ""
	sc := bufio.NewScanner(r)
	for sc.Scan() {
		line := sc.Text()
		switch {
		case strings.HasPrefix(line, "goos: "):
			l.Goos = strings.TrimPrefix(line, "goos: ")
		case strings.HasPrefix(line, "goarch: "):
			l.Goarch = strings.TrimPrefix(line, "goarch: ")
		case strings.HasPrefix(line, "cpu: "):
			l.CPU = strings.TrimSpace(strings.TrimPrefix(line, "cpu: "))
		case strings.HasPrefix(line, "pkg: "):
			pkg = pkgTail(strings.TrimPrefix(line, "pkg: "))
		case strings.HasPrefix(line, "Benchmark"):
			name, vals, ok := benchLine(line)
			if !ok {
				continue
			}
			key := pkg + "." + name
			if samples[key] == nil {
				samples[key] = map[string][]float64{}
			}
			for unit, v := range vals {
				samples[key][unit] = append(samples[key][unit], v)
			}
			reps[key] = max(reps[key], len(samples[key]["ns/op"]))
		}
	}
	if err := sc.Err(); err != nil {
		return l, err
	}
	if len(samples) == 0 {
		return l, errors.New("no benchmark lines in input")
	}
	for key, units := range samples {
		l.Benchmarks[key] = map[string]float64{}
		for unit, vs := range units {
			l.Benchmarks[key][unit] = median(vs)
		}
		l.Count = max(l.Count, reps[key])
	}
	return l, nil
}

// pkgTail drops the module prefix: "github.com/x/banken/internal/sigma" ->
// "internal/sigma"; the root package (module path only) becomes "banken".
func pkgTail(p string) string {
	const marker = "/banken"
	if _, tail, ok := strings.Cut(p, marker+"/"); ok {
		return tail
	}
	if strings.HasSuffix(p, marker) {
		return "banken"
	}
	return p
}

// benchLine parses "BenchmarkX-10  815845  745.4 ns/op  364 B/op  4 allocs/op"
// into the name (GOMAXPROCS suffix removed; the cpu field tells machines apart)
// and a unit->value map.
func benchLine(line string) (string, map[string]float64, bool) {
	f := strings.Fields(line)
	if len(f) < 4 {
		return "", nil, false
	}
	if _, err := strconv.ParseInt(f[1], 10, 64); err != nil {
		return "", nil, false
	}
	name := f[0]
	if i := strings.LastIndex(name, "-"); i > 0 {
		if _, err := strconv.Atoi(name[i+1:]); err == nil {
			name = name[:i]
		}
	}
	vals := map[string]float64{}
	for i := 2; i+1 < len(f); i += 2 {
		v, err := strconv.ParseFloat(f[i], 64)
		if err != nil {
			return "", nil, false
		}
		vals[f[i+1]] = v
	}
	return name, vals, len(vals) > 0
}

func median(vs []float64) float64 {
	s := append([]float64(nil), vs...)
	sort.Float64s(s)
	n := len(s)
	if n%2 == 1 {
		return s[n/2]
	}
	return (s[n/2-1] + s[n/2]) / 2
}
