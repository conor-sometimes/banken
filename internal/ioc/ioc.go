// Package ioc loads the plain indicator lists under rules/ioc/*.txt --
// filenames, IP addresses and domains, one per line -- and matches them
// against an event's fields with a fast lookup whose per-event cost does not
// grow with the number of indicators. It is the bulk-feed counterpart to a
// Sigma rule: thousands of flat values that would be absurd as one YAML file
// each.
//
// Each kind is matched the way its shape warrants, and none by a per-event
// linear scan of the feed:
//
//   - IP indicators: exact set membership of a whole host token (so 192.0.2.1
//     never fires on 192.0.2.100).
//   - Domain indicators: a label-suffix lookup in an exact map, so a feed
//     domain matches the host and any subdomain (evil.test matches c2.evil.test
//     but not notevil.test) in time proportional to the token's label count,
//     not to the feed size.
//   - Filename/path indicators: one shared Aho-Corasick automaton
//     (internal/acmatch, the same literal-set matcher the Sigma prefilter uses)
//     finds every indicator present as a substring of a field in a single pass,
//     independent of how many indicators were loaded.
//
// Indicator values are folded to lower case once, at Add time, not per event.
// The maps and the automaton are built once, lazily, on the first Match and
// then only read, so a published Set is safe for concurrent matching.
package ioc

import (
	"bufio"
	"errors"
	"io"
	"io/fs"
	"os"
	"path"
	"path/filepath"
	"regexp"
	"sort"
	"strings"
	"sync"

	"github.com/conor-sometimes/banken/internal/acmatch"
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
	all   []Indicator
	exact map[string]Indicator // IP value -> indicator, for O(1) whole-token hits
	doms  []loweredInd         // domain indicators, value pre-lowered at Add
	files []loweredInd         // filename/path indicators, value pre-lowered at Add

	// Built once on the first Match, then only read (see compile). domainIx maps
	// a lowered feed domain to its indicator for the label-suffix lookup; fileAC
	// is the Aho-Corasick automaton over the distinct lowered file values, whose
	// literal ids index fileInds.
	compileOnce sync.Once
	domainIx    map[string]Indicator
	fileAC      *acmatch.Matcher
	fileInds    []Indicator
}

// loweredInd keeps an indicator alongside its value folded to lower case once,
// so matching never lower-cases the indicator per event.
type loweredInd struct {
	ind   Indicator
	lower string
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

// ReadFS loads every <root>/ioc/*.txt from an fs.FS into the set (for the
// baseline feeds embedded with //go:embed). A missing ioc dir is fine --
// feeds are optional. Values duplicated with an on-disk feed are harmless:
// Match deduplicates hits by (value, field).
func (s *Set) ReadFS(fsys fs.FS, roots ...string) error {
	for _, root := range roots {
		iocDir := path.Join(root, "ioc")
		err := fs.WalkDir(fsys, iocDir, func(p string, d fs.DirEntry, err error) error {
			if err != nil {
				if errors.Is(err, fs.ErrNotExist) {
					return fs.SkipDir
				}
				return err
			}
			if d.IsDir() || strings.ToLower(path.Ext(p)) != ".txt" {
				return nil
			}
			f, err := fsys.Open(p)
			if err != nil {
				return err
			}
			defer func() { _ = f.Close() }()
			s.Read(f, path.Base(p))
			return nil
		})
		if err != nil {
			return err
		}
	}
	return nil
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
		s.exact[value] = ind
	case KindDomain:
		s.doms = append(s.doms, loweredInd{ind: ind, lower: strings.ToLower(value)})
	default:
		s.files = append(s.files, loweredInd{ind: ind, lower: strings.ToLower(value)})
	}
}

// compile builds the domain-suffix map and the filename automaton from the
// loaded indicators. It runs once, under compileOnce, on the first Match: the
// documented lifecycle is build (Read/Add) then publish then match, so a Set is
// never added to after it is first matched, and the sync.Once gives every
// concurrent first Match a consistent, fully built view. On a reload the engine
// swaps in a freshly built Set, so a mutated feed is always a new Set.
func (s *Set) compile() {
	s.domainIx = make(map[string]Indicator, len(s.doms))
	for _, d := range s.doms {
		// First load of a value wins, so the reported Source matches the feed
		// order a linear scan would have reported.
		if _, ok := s.domainIx[d.lower]; !ok {
			s.domainIx[d.lower] = d.ind
		}
	}

	patID := make(map[string]int, len(s.files))
	patterns := make([][]byte, 0, len(s.files))
	for _, fi := range s.files {
		if _, ok := patID[fi.lower]; ok {
			continue // a repeated value is one literal; its first load keeps the id
		}
		patID[fi.lower] = len(patterns)
		patterns = append(patterns, []byte(fi.lower))
		s.fileInds = append(s.fileInds, fi.ind)
	}
	s.fileAC = acmatch.New(patterns)
}

// Classify reports an indicator value's kind from its shape, by the same
// rule the loader uses. It is exported so an alert consumer (the OCSF
// encoder) can type an IOC observable from the indicator string alone,
// without the alert having to carry the Kind.
func Classify(v string) Kind { return classify(v) }

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
	s.compileOnce.Do(s.compile)

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
			// A domain indicator matches the token exactly or as a dot-suffix.
			// The label-suffix chain of the token (host, then every parent
			// domain) is exactly the set of values that satisfy that rule, so
			// looking each up in domainIx replaces the per-event scan of every
			// loaded domain with a lookup per label.
			for suffix := strings.ToLower(tok); ; {
				if ind, ok := s.domainIx[suffix]; ok {
					add(ind, f.name)
				}
				dot := strings.IndexByte(suffix, '.')
				if dot < 0 {
					break
				}
				suffix = suffix[dot+1:]
			}
		}

		// Filenames: a substring of the field anywhere. The automaton reports
		// which loaded file values occur in one pass over the field, so the cost
		// is the field length, not the indicator count. Reported in id order
		// (load order) for a stable hit sequence.
		present := make(map[int]struct{})
		s.fileAC.ScanInto(lower, present)
		if len(present) > 0 {
			ids := make([]int, 0, len(present))
			for id := range present {
				ids = append(ids, id)
			}
			sort.Ints(ids)
			for _, id := range ids {
				add(s.fileInds[id], f.name)
			}
		}
	}
	return hits
}
