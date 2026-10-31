// Package ioc loads the plain indicator lists under rules/ioc/*.txt --
// filenames, IP addresses and domains, one per line -- and matches them
// against an event's fields with a fast lookup. It is the bulk-feed
// counterpart to a Sigma rule: thousands of flat values that would be
// absurd as one YAML file each, checked by set membership and domain-suffix
// rather than by condition logic.
package ioc

import (
	"bufio"
	"io"
	"io/fs"
	"os"
	"path/filepath"
	"regexp"
	"strings"

	"github.com/conor-sometimes/banken/internal/event"
)

// Kind classifies an indicator so matching can pick the right test.
type Kind int

const (
	// KindFilename is a path or file basename: matched as a substring of a
	// file or command field, or as the basename of a path.
	KindFilename Kind = iota
	// KindIP is an IPv4/IPv6 literal: matched as a whole-token substring.
	KindIP
	// KindDomain is a hostname: matched as an exact host or a dot-suffix
	// (so "evil.test" matches "c2.evil.test" but not "notevil.test").
	KindDomain
)

// Indicator is one loaded IOC and its origin, kept so an alert can say
// which feed line fired.
type Indicator struct {
	Value  string
	Kind   Kind
	Source string // the .txt file it came from
}

// Set is a compiled collection of indicators with a fast matcher.
type Set struct {
	all     []Indicator
	exact   map[string]Indicator // value -> indicator, for O(1) token hits
	domains []Indicator          // checked by suffix
	files   []Indicator          // checked by substring/basename
	ips     []Indicator          // checked by token membership
}

// Match is a single indicator hit on an event.
type Match struct {
	Indicator Indicator
	Field     string // which event field it was found in
}

var (
	ipv4Re = regexp.MustCompile(`^\d{1,3}\.\d{1,3}\.\d{1,3}\.\d{1,3}$`)
	// a conservative domain shape: at least one dot, letters/digits/hyphen
	domainRe = regexp.MustCompile(`^[a-zA-Z0-9]([a-zA-Z0-9-]*[a-zA-Z0-9])?(\.[a-zA-Z0-9]([a-zA-Z0-9-]*[a-zA-Z0-9])?)+$`)
	// hostTokenRe pulls candidate host/IP tokens out of a field: a run of
	// hostname characters, so a URL like http://192.0.2.1/x yields the
	// clean tokens "http", "192.0.2.1", "x" rather than one merged string.
	hostTokenRe = regexp.MustCompile(`[A-Za-z0-9]([A-Za-z0-9.-]*[A-Za-z0-9])?`)
)

// LoadTree loads every rules/ioc/*.txt under each dir (looking for an
// "ioc" subdirectory) into one Set. A missing ioc dir is not an error --
// IOC feeds are optional. An I/O error on a file is returned.
func LoadTree(dirs ...string) (*Set, error) {
	s := NewSet()
	for _, dir := range dirs {
		iocDir := filepath.Join(dir, "ioc")
		err := filepath.WalkDir(iocDir, func(path string, d fs.DirEntry, err error) error {
			if err != nil {
				if os.IsNotExist(err) {
					return filepath.SkipDir
				}
				return err
			}
			if d.IsDir() || strings.ToLower(filepath.Ext(path)) != ".txt" {
				return nil
			}
			f, err := os.Open(path) //nolint:gosec // operator-supplied rules dir
			if err != nil {
				return err
			}
			defer func() { _ = f.Close() }()
			s.Read(f, filepath.Base(path))
			return nil
		})
		if err != nil {
			return nil, err
		}
	}
	return s, nil
}

// NewSet returns an empty Set ready for Read/Add.
func NewSet() *Set {
	return &Set{exact: map[string]Indicator{}}
}

// Read parses one indicator list from r, tagging each with source. A blank
// line or a line starting with '#' is a comment and skipped. Classification
// is by shape (IP / domain / otherwise a filename). Never fails: a weird
// line just becomes a filename indicator.
func (s *Set) Read(r io.Reader, source string) {
	sc := bufio.NewScanner(r)
	sc.Buffer(make([]byte, 0, 4096), 1024*1024)
	for sc.Scan() {
		line := strings.TrimSpace(sc.Text())
		if line == "" || strings.HasPrefix(line, "#") {
			continue
		}
		s.Add(line, source)
	}
}

// Add classifies and stores one indicator value.
func (s *Set) Add(value, source string) {
	value = strings.TrimSpace(value)
	if value == "" {
		return
	}
	ind := Indicator{Value: value, Source: source, Kind: classify(value)}
	s.all = append(s.all, ind)
	switch ind.Kind {
	case KindIP:
		s.ips = append(s.ips, ind)
		s.exact[value] = ind
	case KindDomain:
		s.domains = append(s.domains, ind)
		s.exact[strings.ToLower(value)] = ind
	default:
		s.files = append(s.files, ind)
	}
}

// classify guesses an indicator's kind from its shape. It is best-effort:
// a dotted token with no slash (e.g. "loot.tgz") is ambiguous with a
// domain and is treated as a domain, so filename indicators that could
// collide should include a path separator. IPs and slashed paths are
// unambiguous.
func classify(v string) Kind {
	switch {
	case ipv4Re.MatchString(v) || (strings.Contains(v, ":") && looksIPv6(v)):
		return KindIP
	case !strings.ContainsAny(v, "/\\") && domainRe.MatchString(v):
		return KindDomain
	default:
		return KindFilename
	}
}

func looksIPv6(v string) bool {
	// Cheap guard: hex groups and colons only, at least two colons.
	if strings.Count(v, ":") < 2 {
		return false
	}
	for _, r := range v {
		if !isHexOrColon(r) {
			return false
		}
	}
	return true
}

func isHexOrColon(r rune) bool {
	return r == ':' || (r >= '0' && r <= '9') || (r >= 'a' && r <= 'f') || (r >= 'A' && r <= 'F')
}

// Len reports how many indicators are loaded.
func (s *Set) Len() int { return len(s.all) }

// matchedFields are the event fields IOC lookup scans.
func matchedFields(e event.Event) []struct{ name, val string } {
	return []struct{ name, val string }{
		{"CommandLine", e.CommandLine},
		{"Image", e.Image},
		{"TargetFilename", e.TargetFilename},
		{"CurrentDirectory", e.CurrentDirectory},
	}
}

// Match returns every indicator that fires on the event, deduplicated by
// (indicator value, field).
func (s *Set) Match(e event.Event) []Match {
	var hits []Match
	seen := map[string]bool{}
	add := func(ind Indicator, field string) {
		key := ind.Value + "\x00" + field
		if seen[key] {
			return
		}
		seen[key] = true
		hits = append(hits, Match{Indicator: ind, Field: field})
	}

	for _, f := range matchedFields(e) {
		if f.val == "" {
			continue
		}
		lower := strings.ToLower(f.val)
		hostTokens := hostTokenRe.FindAllString(f.val, -1)

		// IPs and domains: match whole host tokens (and domain dot-suffix),
		// never a loose substring -- 192.0.2.1 must not fire on 192.0.2.100.
		for _, tok := range hostTokens {
			if ind, ok := s.exact[tok]; ok && ind.Kind == KindIP {
				add(ind, f.name)
			}
			ltok := strings.ToLower(tok)
			for _, d := range s.domains {
				dv := strings.ToLower(d.Value)
				if ltok == dv || strings.HasSuffix(ltok, "."+dv) {
					add(d, f.name)
				}
			}
		}
		// Filenames: plain substring (a path or name appearing anywhere).
		for _, fi := range s.files {
			if strings.Contains(lower, strings.ToLower(fi.Value)) {
				add(fi, f.name)
			}
		}
	}
	return hits
}
