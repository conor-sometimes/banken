package main

import (
	"reflect"
	"testing"
)

func TestParseCounts(t *testing.T) {
	ok := []struct {
		in   string
		want []int
	}{
		{"100000,250000,500000", []int{100000, 250000, 500000}},
		{" 1000 , 2000 ", []int{1000, 2000}}, // surrounding whitespace is trimmed
		{"5000,,10000", []int{5000, 10000}},  // empty entries are skipped, not errors
		{"42", []int{42}},                    // a single count is fine
		{"10,10", []int{10, 10}},             // duplicates are kept (the caller's sweep)
	}
	for _, c := range ok {
		got, err := parseCounts(c.in)
		if err != nil {
			t.Fatalf("parseCounts(%q): unexpected error %v", c.in, err)
		}
		if !reflect.DeepEqual(got, c.want) {
			t.Fatalf("parseCounts(%q) = %v, want %v", c.in, got, c.want)
		}
	}

	bad := []string{
		"",       // nothing to parse
		"   ",    // only whitespace
		",,",     // only empty entries
		"abc",    // not a number
		"1000,x", // one bad entry fails the whole list
		"0",      // zero is not a positive count
		"-5",     // negative is not a positive count
		"1.5",    // not an integer
	}
	for _, in := range bad {
		if got, err := parseCounts(in); err == nil {
			t.Fatalf("parseCounts(%q) = %v, want error", in, got)
		}
	}
}
