package benchlib

import "testing"

func TestFromSamplesPercentiles(t *testing.T) {
	// 1..100: nearest-rank p50 = 50th value, p99 = 99th, max = 100th.
	samples := make([]int64, 100)
	for i := range samples {
		samples[i] = int64(i + 1)
	}
	s := fromSamples(samples)
	if s.Samples != 100 {
		t.Fatalf("Samples = %d, want 100", s.Samples)
	}
	if s.MinNs != 1 {
		t.Errorf("Min = %d, want 1", s.MinNs)
	}
	if s.P50Ns != 50 {
		t.Errorf("P50 = %d, want 50", s.P50Ns)
	}
	if s.P99Ns != 99 {
		t.Errorf("P99 = %d, want 99", s.P99Ns)
	}
	if s.MaxNs != 100 {
		t.Errorf("Max = %d, want 100", s.MaxNs)
	}
	if s.MeanNs != 50 { // (1+..+100)/100 = 5050/100 = 50 (integer)
		t.Errorf("Mean = %d, want 50", s.MeanNs)
	}
}

func TestFromSamplesUnsorted(t *testing.T) {
	// The input order must not matter: fromSamples sorts a copy.
	s := fromSamples([]int64{9, 1, 5, 3, 7})
	if s.MinNs != 1 || s.MaxNs != 9 || s.P50Ns != 5 {
		t.Fatalf("got min=%d p50=%d max=%d, want 1/5/9", s.MinNs, s.P50Ns, s.MaxNs)
	}
}

func TestFromSamplesEmpty(t *testing.T) {
	if got := fromSamples(nil); got.Samples != 0 {
		t.Fatalf("empty input: Samples = %d, want 0", got.Samples)
	}
}

func TestMeasureRecordsSamples(t *testing.T) {
	n := 0
	s := Measure(2000, func() { n++ })
	if s.Samples != 2000 {
		t.Fatalf("Samples = %d, want 2000", s.Samples)
	}
	// 2000 measured + warmup (200) + overhead probe calls do not touch n beyond
	// the measured+warmup of the body.
	if n < 2000 {
		t.Fatalf("body ran %d times, want at least the 2000 measured", n)
	}
	if s.P50Ns < 0 || s.MaxNs < s.P50Ns {
		t.Fatalf("incoherent stats: p50=%d max=%d", s.P50Ns, s.MaxNs)
	}
}
