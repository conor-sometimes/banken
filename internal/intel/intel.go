// Package intel ingests threat-intelligence feeds in the standard formats --
// STIX 2.1 bundles, TAXII 2.1 collections and MISP JSON exports -- and
// normalises every indicator into banken's existing IOC model (internal/ioc),
// so the match engine consumes a feed exactly as it consumes a hand-written
// rules/ioc/*.txt list. Nothing here matches events: the parsers turn a feed
// into a slice of normalised Indicators, and AddToSet hands those values to an
// ioc.Set, where they are classified by shape and matched by the same O(1)
// lookup / domain-suffix / substring tests the flat lists already use.
//
// Design tenets (banken-wide): simple and data-driven (a feed is a file or a
// URL named in config, nothing more); honest scoping (offline bundle parsing
// is fully testable in CI, a live TAXII poll needs a server and is proven only
// against a recorded response -- see taxii.go); never-die (a malformed feed or
// a failed poll is a returned error for the caller to log, never a panic).
package intel

import (
	"fmt"
	"io"
	"strings"

	"github.com/conor-sometimes/banken/internal/ioc"
)

// File-feed format names, as they appear in config (services.banken intel
// feeds). TAXII is a transport, not a file format, and has its own client.
const (
	FormatSTIX = "stix"
	FormatMISP = "misp"
)

// ParseReader parses a file-feed of the named format from r, tagging each
// indicator with source. It is the single entry point the config loader uses
// for on-disk feeds, so adding a format is one case here, not a branch in main.
// An unknown format is an error, never a silent skip -- an operator who wrote
// "stixx" must find out, the same way an unknown jsonl format is a startup error.
func ParseReader(format string, r io.Reader, source string) ([]Indicator, error) {
	switch strings.ToLower(strings.TrimSpace(format)) {
	case FormatSTIX:
		return ParseSTIX(r, source)
	case FormatMISP:
		return ParseMISP(r, source)
	default:
		return nil, fmt.Errorf("intel: unknown feed format %q (want %s or %s)", format, FormatSTIX, FormatMISP)
	}
}

// Type is the normalised category of a threat-intel indicator. It mirrors the
// kinds banken's ioc matcher understands and adds hash/url/file, which the
// matcher treats as substring values. It is carried for provenance and for a
// reader that wants to type an indicator without re-parsing the feed; the
// match itself is driven by the value's shape via internal/ioc, never by this
// field, so an indicator is matched identically whether it arrived from a feed
// or a flat list.
type Type string

const (
	// TypeIPv4 is an IPv4 address literal (ioc classifies it KindIP).
	TypeIPv4 Type = "ipv4"
	// TypeIPv6 is an IPv6 address literal (ioc classifies it KindIP).
	TypeIPv6 Type = "ipv6"
	// TypeDomain is a hostname / domain (ioc classifies it KindDomain:
	// exact host or dot-suffix).
	TypeDomain Type = "domain"
	// TypeURL is a full URL (ioc classifies it KindFilename: substring).
	TypeURL Type = "url"
	// TypeHash is a file hash -- MD5/SHA1/SHA256/... (ioc KindFilename:
	// substring, so it fires when the hash appears in a command line or path).
	TypeHash Type = "hash"
	// TypeFile is a file name or path (ioc KindFilename: substring).
	TypeFile Type = "file"
)

// Indicator is one normalised threat-intel indicator ready to feed an ioc.Set.
// Value is the matchable string; Source is the feed label carried onto every
// alert the indicator fires (so an operator can tell which feed paged them).
// Description and Labels are optional context the feed supplied; they are kept
// for a future consumer but do not affect matching.
type Indicator struct {
	Value       string
	Type        Type
	Source      string
	Description string
	Labels      []string
}

// AddToSet normalises indicators into an existing ioc.Set: each value is handed
// to ioc.Set.Add, which classifies it by shape and files it for the right test.
// This is the whole bridge -- a feed becomes indistinguishable from a flat
// rules/ioc/*.txt list once loaded. Blank values are skipped; a missing Source
// defaults to "intel" so an alert is never sourced to the empty string.
// Duplicate values (across feeds or with an on-disk list) are harmless:
// ioc.Set.Match dedups hits by value+field. It returns the number of values
// added.
func AddToSet(s *ioc.Set, inds []Indicator) int {
	n := 0
	for _, ind := range inds {
		v := strings.TrimSpace(ind.Value)
		if v == "" {
			continue
		}
		src := strings.TrimSpace(ind.Source)
		if src == "" {
			src = "intel"
		}
		s.Add(v, src)
		n++
	}
	return n
}

// dedup collapses indicators that share a (value, type) pair, keeping the first
// occurrence. A feed that lists the same IP in several objects, or a TAXII poll
// that spans pages with overlap, would otherwise yield duplicate Indicators;
// the match side dedups hits anyway, but callers that write the normalised set
// to a file or count it want it clean.
func dedup(inds []Indicator) []Indicator {
	seen := make(map[string]bool, len(inds))
	out := inds[:0]
	for _, ind := range inds {
		key := string(ind.Type) + "\x00" + ind.Value
		if seen[key] {
			continue
		}
		seen[key] = true
		out = append(out, ind)
	}
	return out
}
