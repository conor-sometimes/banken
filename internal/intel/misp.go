package intel

import (
	"encoding/json"
	"fmt"
	"io"
	"strings"
)

// MISP ingestion. banken reads the two JSON shapes a MISP instance hands out:
//
//   - an event export: {"Event": {"Attribute": [...], "Object": [{"Attribute":
//     [...]}], ...}}, optionally wrapped as {"response": [{"Event": {...}}]}
//     when several events are returned;
//   - an attribute search (restSearch, returnFormat json):
//     {"response": {"Attribute": [...]}}.
//
// All three decode into one permissive struct, and banken collects attributes
// from the event's own Attribute list and from each Object's nested Attribute
// list. Only the attribute types that map onto something banken can match are
// kept; an unknown type is skipped, never an error.
//
// to_ids semantics: a MISP attribute flagged to_ids=false is explicitly marked
// "not for detection" by the analyst, so banken drops it. An attribute with
// to_ids=true or with the field absent is kept -- absent is the common case in
// hand-written samples and small exports, and dropping those would silently
// lose indicators.

// mispAttribute is the subset of a MISP attribute banken reads.
type mispAttribute struct {
	Type    string `json:"type"`
	Value   string `json:"value"`
	Comment string `json:"comment"`
	ToIDS   *bool  `json:"to_ids"`
}

type mispObject struct {
	Attribute []mispAttribute `json:"Attribute"`
}

type mispEvent struct {
	Info      string          `json:"info"`
	Attribute []mispAttribute `json:"Attribute"`
	Object    []mispObject    `json:"Object"`
}

// mispDoc decodes every shape: Response is json.RawMessage because it is an
// array of {Event} in an event export but an object with Attribute in a search
// result, so it is decoded in a second step once its shape is known.
type mispDoc struct {
	Event    *mispEvent      `json:"Event"`
	Response json.RawMessage `json:"response"`
}

// ParseMISP reads a MISP JSON export (event or attribute-search shape) and
// returns the normalised indicators, tagged with source. Offline and fully
// CI-testable. A JSON syntax error is returned; an unmatchable attribute type
// is skipped.
func ParseMISP(r io.Reader, source string) ([]Indicator, error) {
	data, err := io.ReadAll(r)
	if err != nil {
		return nil, fmt.Errorf("misp: read: %w", err)
	}
	var doc mispDoc
	if err := json.Unmarshal(data, &doc); err != nil {
		return nil, fmt.Errorf("misp: decode: %w", err)
	}

	var attrs []mispAttribute
	if doc.Event != nil {
		attrs = append(attrs, collectEventAttrs(*doc.Event)...)
	}
	if len(doc.Response) > 0 {
		attrs = append(attrs, attrsFromResponse(doc.Response)...)
	}

	var out []Indicator
	for _, a := range attrs {
		if a.ToIDS != nil && !*a.ToIDS {
			continue // analyst marked it not-for-detection
		}
		out = append(out, indicatorsFromMISPAttr(a, source)...)
	}
	return dedup(out), nil
}

// attrsFromResponse handles the two "response" shapes: an array of {"Event":
// {...}} (several events) or a single object carrying an Attribute list (a
// restSearch result). Anything else yields nothing rather than an error.
func attrsFromResponse(raw json.RawMessage) []mispAttribute {
	var attrs []mispAttribute
	var events []struct {
		Event mispEvent `json:"Event"`
	}
	if err := json.Unmarshal(raw, &events); err == nil && len(events) > 0 {
		for _, e := range events {
			attrs = append(attrs, collectEventAttrs(e.Event)...)
		}
		return attrs
	}
	var search struct {
		Attribute []mispAttribute `json:"Attribute"`
	}
	if err := json.Unmarshal(raw, &search); err == nil {
		attrs = append(attrs, search.Attribute...)
	}
	return attrs
}

func collectEventAttrs(e mispEvent) []mispAttribute {
	attrs := append([]mispAttribute(nil), e.Attribute...)
	for _, o := range e.Object {
		attrs = append(attrs, o.Attribute...)
	}
	return attrs
}

// indicatorsFromMISPAttr maps one MISP attribute to zero or more normalised
// indicators. Composite types (filename|md5, domain|ip, ip-dst|port) carry two
// values joined by '|'; banken emits each matchable half. A type banken has no
// match for (regkey, email-src, mutex, ...) yields nothing.
func indicatorsFromMISPAttr(a mispAttribute, source string) []Indicator {
	value := strings.TrimSpace(a.Value)
	if value == "" {
		return nil
	}
	typ := strings.ToLower(strings.TrimSpace(a.Type))

	// Composite types: "left|right". Split and classify each half by the
	// composite type's two parts.
	if left, right, ok := strings.Cut(typ, "|"); ok {
		lv, rv, hasVal := strings.Cut(value, "|")
		if !hasVal {
			// Declared composite but single value: treat the whole value as the
			// left part's type.
			return mispSimple(left, value, a, source)
		}
		out := mispSimple(left, lv, a, source)
		out = append(out, mispSimple(right, rv, a, source)...)
		return out
	}
	return mispSimple(typ, value, a, source)
}

// mispSimple maps one simple MISP attribute type + value to an indicator.
func mispSimple(typ, value string, a mispAttribute, source string) []Indicator {
	value = strings.TrimSpace(value)
	if value == "" {
		return nil
	}
	var t Type
	switch typ {
	case "ip-src", "ip-dst", "ip":
		t = ipType(value)
	case "domain", "hostname":
		t = TypeDomain
	case "url", "uri", "link":
		t = TypeURL
	case "md5", "sha1", "sha224", "sha256", "sha384", "sha512",
		"sha512/224", "sha512/256", "ssdeep", "imphash", "pehash",
		"authentihash", "tlsh", "vhash":
		t = TypeHash
	case "filename", "filepath":
		t = TypeFile
	case "port":
		return nil // a bare port is not a matchable indicator on its own
	default:
		return nil
	}
	return []Indicator{{Value: value, Type: t, Source: source, Description: a.Comment}}
}

// ipType tells an IPv6 literal from IPv4 by the presence of a colon, so the
// normalised Type is right; ioc classifies both as KindIP regardless.
func ipType(v string) Type {
	if strings.Contains(v, ":") {
		return TypeIPv6
	}
	return TypeIPv4
}
