package intel

import (
	"encoding/json"
	"fmt"
	"io"
	"regexp"
	"strings"
)

// STIX 2.1 ingestion. banken consumes two object shapes that carry indicators:
//
//   - indicator SDOs, whose "pattern" (pattern_type "stix") is a comparison
//     expression such as [ipv4-addr:value = '198.51.100.23'] or
//     [file:hashes.'SHA-256' = 'ab..']. banken extracts the value from every
//     equality comparison in the pattern. OR/AND joins are handled (each
//     comparison yields one indicator); the match side does not care how the
//     feed grouped them.
//   - Cyber-observable objects (SCOs) that appear directly in the bundle --
//     ipv4-addr, ipv6-addr, domain-name, url, file -- which carry their value
//     in a field rather than a pattern. TAXII collections commonly return these.
//
// Honest scope: banken extracts "=" comparisons, the form essentially every
// IOC feed uses. It does not evaluate MATCHES/LIKE/IN or pattern qualifiers
// (WITHIN/REPEATS/START/STOP) -- those describe behaviour over observations, not
// a flat indicator, and have no place in a set-membership matcher. Unknown
// object/property types are skipped, never an error: a bundle banken only
// partly understands still yields the indicators it does understand.

// stixObject is the subset of a STIX 2.1 object banken reads. Everything else
// in the object is ignored. A bundle and a TAXII envelope both carry their
// objects under an "objects" array, so one shape decodes both.
type stixObject struct {
	Type        string   `json:"type"`
	Pattern     string   `json:"pattern"`
	PatternType string   `json:"pattern_type"`
	Labels      []string `json:"labels"`
	Description string   `json:"description"`
	// SCO value fields: ipv4-addr/ipv6-addr/domain-name/url all use "value".
	Value  string            `json:"value"`
	Hashes map[string]string `json:"hashes"` // file SCO: {"SHA-256": "..."}
	Name   string            `json:"name"`   // file SCO: file name
}

type stixEnvelope struct {
	Objects []stixObject `json:"objects"`
}

// ParseSTIX reads a STIX 2.1 bundle (or any JSON document with an "objects"
// array of STIX objects) and returns the normalised indicators, tagged with
// source. It is the offline, fully-CI-testable path. A JSON syntax error is
// returned; an object banken does not understand is skipped.
func ParseSTIX(r io.Reader, source string) ([]Indicator, error) {
	var env stixEnvelope
	if err := json.NewDecoder(r).Decode(&env); err != nil {
		return nil, fmt.Errorf("stix: decode: %w", err)
	}
	return indicatorsFromSTIX(env.Objects, source), nil
}

// indicatorsFromSTIX turns decoded STIX objects into normalised indicators.
// Shared by the bundle parser and the TAXII client (a TAXII envelope is just
// STIX objects over HTTP).
func indicatorsFromSTIX(objs []stixObject, source string) []Indicator {
	var out []Indicator
	for _, o := range objs {
		switch o.Type {
		case "indicator":
			// Only STIX-patterning indicators carry a pattern banken reads.
			// pattern_type may be omitted in older bundles; treat empty as stix.
			if o.PatternType != "" && !strings.EqualFold(o.PatternType, "stix") {
				continue
			}
			for _, ind := range indicatorsFromPattern(o.Pattern, source) {
				ind.Description = o.Description
				ind.Labels = o.Labels
				out = append(out, ind)
			}
		case "ipv4-addr":
			out = appendIfValue(out, o.Value, TypeIPv4, source, o)
		case "ipv6-addr":
			out = appendIfValue(out, o.Value, TypeIPv6, source, o)
		case "domain-name":
			out = appendIfValue(out, o.Value, TypeDomain, source, o)
		case "url":
			out = appendIfValue(out, o.Value, TypeURL, source, o)
		case "file":
			for _, h := range o.Hashes {
				out = appendIfValue(out, h, TypeHash, source, o)
			}
			if o.Name != "" {
				out = appendIfValue(out, o.Name, TypeFile, source, o)
			}
		}
	}
	return dedup(out)
}

func appendIfValue(out []Indicator, value string, t Type, source string, o stixObject) []Indicator {
	value = strings.TrimSpace(value)
	if value == "" {
		return out
	}
	return append(out, Indicator{Value: value, Type: t, Source: source, Description: o.Description, Labels: o.Labels})
}

// stixComparison matches one equality comparison in a STIX pattern:
// object-type:property = 'value' (or "value"). The property is captured so a
// file-hash path (hashes.'SHA-256', hashes.MD5) can be told from file:name.
// The value alternation allows backslash escapes inside either quote style.
var stixComparison = regexp.MustCompile(`([a-zA-Z0-9_-]+):([^\s=<>!]+)\s*=\s*('(?:[^'\\]|\\.)*'|"(?:[^"\\]|\\.)*")`)

// indicatorsFromPattern pulls every equality comparison out of a STIX pattern
// and maps the known object types to normalised indicators. An object type
// banken does not match on (e.g. windows-registry-key) is skipped.
func indicatorsFromPattern(pattern, source string) []Indicator {
	var out []Indicator
	for _, m := range stixComparison.FindAllStringSubmatch(pattern, -1) {
		objType := strings.ToLower(m[1])
		prop := strings.ToLower(m[2])
		value := unquoteSTIX(m[3])
		if value == "" {
			continue
		}
		var t Type
		switch objType {
		case "ipv4-addr":
			t = TypeIPv4
		case "ipv6-addr":
			t = TypeIPv6
		case "domain-name", "hostname":
			t = TypeDomain
		case "url":
			t = TypeURL
		case "file":
			switch {
			case strings.HasPrefix(prop, "hashes"):
				t = TypeHash
			case prop == "name":
				t = TypeFile
			default:
				continue
			}
		default:
			continue
		}
		out = append(out, Indicator{Value: value, Type: t, Source: source})
	}
	return out
}

// unquoteSTIX strips the surrounding quotes from a STIX string literal and
// unescapes the two escapes STIX defines inside one: \' (or \") and \\. Any
// other backslash sequence is left as written, which is lossless for the IOC
// values banken cares about (IPs, domains, URLs, hashes, paths).
func unquoteSTIX(lit string) string {
	if len(lit) < 2 {
		return ""
	}
	q := lit[0]
	body := lit[1 : len(lit)-1]
	var b strings.Builder
	b.Grow(len(body))
	for i := 0; i < len(body); i++ {
		if body[i] == '\\' && i+1 < len(body) {
			next := body[i+1]
			if next == '\\' || next == q {
				b.WriteByte(next)
				i++
				continue
			}
		}
		b.WriteByte(body[i])
	}
	return strings.TrimSpace(b.String())
}
