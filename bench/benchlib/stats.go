// Package benchlib is the measurement core shared by the banken-bench tool:
// per-operation timing with honest percentiles, the raw-JSON schema the runs
// publish, and the rule-set loader the scaling benches build on.
//
// The spec (docs/design/benchmarking.md) is explicit that a latency number is
// reported as p50/p99/max and never as a mean: one slow alert matters more than
// a fast average. So the timing primitive here records every sample and sorts,
// rather than leaning on `go test -bench`, which reports only the mean ns/op.
package benchlib

import (
	"sort"
	"time"
)

// Stats is the distribution of one measured operation, in nanoseconds. Mean is
// carried only for continuity with the old `go test -bench` numbers; p50/p99/max
// are what the spec judges on. TimerOverheadNs is the measured cost of the
// time.Now pair that brackets each sample, reported (not subtracted) so a
// sub-microsecond number can be read honestly: a 1 us match timed with a ~30 ns
// timer carries ~3% timing overhead, and the reader can see it.
type Stats struct {
	Samples         int   `json:"samples"`
	MinNs           int64 `json:"minNs"`
	P50Ns           int64 `json:"p50Ns"`
	P99Ns           int64 `json:"p99Ns"`
	MaxNs           int64 `json:"maxNs"`
	MeanNs          int64 `json:"meanNs"`
	TimerOverheadNs int64 `json:"timerOverheadNs"`
}

// Measure runs fn iters times, timing each call individually, and returns the
// distribution. A warmup pass (iters/10, at least one) runs first so the first
// measured call is not paying one-time costs (allocation of the first buffer,
// code fault-in) that would show up only as max. fn must do the work and must
// not be optimised away; callers assign its result to a package sink.
func Measure(iters int, fn func()) Stats {
	if iters < 1 {
		iters = 1
	}
	warm := iters / 10
	if warm < 1 {
		warm = 1
	}
	for i := 0; i < warm; i++ {
		fn()
	}

	samples := make([]int64, iters)
	for i := 0; i < iters; i++ {
		start := time.Now()
		fn()
		samples[i] = time.Since(start).Nanoseconds()
	}
	s := fromSamples(samples)
	s.TimerOverheadNs = timerOverhead(iters)
	return s
}

// timerOverhead measures the cost of the time.Now/time.Since pair with an empty
// body, so Measure can report what each sample's bracket cost.
func timerOverhead(iters int) int64 {
	if iters > 10000 {
		iters = 10000 // the overhead is constant; a short probe is enough
	}
	samples := make([]int64, iters)
	for i := 0; i < iters; i++ {
		start := time.Now()
		samples[i] = time.Since(start).Nanoseconds()
	}
	return fromSamples(samples).P50Ns
}

// StatsFromSamples computes a distribution from samples already measured
// elsewhere (process spawns, fork-execs, /proc readings), where the caller timed
// the work itself rather than through Measure.
func StatsFromSamples(samples []int64) Stats { return fromSamples(samples) }

// fromSamples computes the distribution from raw nanosecond samples using the
// nearest-rank percentile (no interpolation): p99 is the smallest sample at or
// above the 99th rank, which is the value an operator actually waited for.
func fromSamples(samples []int64) Stats {
	n := len(samples)
	if n == 0 {
		return Stats{}
	}
	sorted := make([]int64, n)
	copy(sorted, samples)
	sort.Slice(sorted, func(i, j int) bool { return sorted[i] < sorted[j] })

	var sum int64
	for _, v := range sorted {
		sum += v
	}
	return Stats{
		Samples: n,
		MinNs:   sorted[0],
		P50Ns:   rank(sorted, 0.50),
		P99Ns:   rank(sorted, 0.99),
		MaxNs:   sorted[n-1],
		MeanNs:  sum / int64(n),
	}
}

// rank returns the nearest-rank percentile of an already-sorted slice.
func rank(sorted []int64, p float64) int64 {
	n := len(sorted)
	idx := int(p*float64(n) + 0.9999999) // ceil(p*n)
	if idx < 1 {
		idx = 1
	}
	if idx > n {
		idx = n
	}
	return sorted[idx-1]
}
