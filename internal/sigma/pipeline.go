package sigma

import (
	_ "embed"
	"fmt"
	"strings"

	"gopkg.in/yaml.v3"
)

// This file implements the Sigma logsource -> sensor routing pipeline. See
// pipeline.yml for the shipped routing table and the rationale; the design
// note is docs/design/sigma-pipelines.md. The pipeline is declarative and
// data-driven: adding a sensor or retargeting a logsource is a table edit, not
// a code change, honouring the "simple is good / no rough edges" tenets.

//go:embed pipeline.yml
var pipelineYAML []byte

// logSource is a rule's declared logsource, lower-cased for matching.
type logSource struct {
	Category string
	Product  string
	Service  string
}

func (ls logSource) empty() bool {
	return ls.Category == "" && ls.Product == "" && ls.Service == ""
}

// pipelineEntry is one routing rule: a logsource condition and what it maps to.
type pipelineEntry struct {
	Name    string            `yaml:"name"`
	When    logSourceCond     `yaml:"when"`
	Sources []string          `yaml:"sources"`
	Rename  map[string]string `yaml:"rename"`
}

// logSourceCond is a pipeline entry's `when`: an omitted (empty) field is a
// wildcard, a set field must equal the rule's value.
type logSourceCond struct {
	Category string `yaml:"category"`
	Product  string `yaml:"product"`
	Service  string `yaml:"service"`
}

func (c logSourceCond) matches(ls logSource) bool {
	if c.Category != "" && !strings.EqualFold(c.Category, ls.Category) {
		return false
	}
	if c.Product != "" && !strings.EqualFold(c.Product, ls.Product) {
		return false
	}
	if c.Service != "" && !strings.EqualFold(c.Service, ls.Service) {
		return false
	}
	return true
}

// pipeline is an ordered set of routing entries.
type pipeline struct {
	Entries []pipelineEntry `yaml:"pipelines"`
}

// route resolves a rule's logsource to the sources it applies to and the field
// renames to apply. matched is false when no entry matched (the caller leaves
// the rule unrestricted). The returned sources slice is non-nil when matched,
// even if empty, so the caller can distinguish "restricted to nothing live"
// from "unrestricted".
func (p *pipeline) route(ls logSource) (sources []string, renames map[string]string, matched bool) {
	if ls.empty() {
		return nil, nil, false
	}
	for _, e := range p.Entries {
		if e.When.matches(ls) {
			srcs := e.Sources
			if srcs == nil {
				srcs = []string{} // matched, but restricted to nothing live
			}
			return srcs, e.Rename, true
		}
	}
	return nil, nil, false
}

// defaultPipeline is the shipped routing table, parsed once at init. A parse
// failure is a build-time bug in pipeline.yml, so it panics rather than
// shipping a binary that silently routes nothing.
var defaultPipeline = mustParsePipeline(pipelineYAML)

func mustParsePipeline(data []byte) *pipeline {
	p, err := parsePipeline(data)
	if err != nil {
		panic("sigma: invalid embedded pipeline.yml: " + err.Error())
	}
	return p
}

func parsePipeline(data []byte) (*pipeline, error) {
	var p pipeline
	if err := yaml.Unmarshal(data, &p); err != nil {
		return nil, fmt.Errorf("parse pipeline: %w", err)
	}
	if len(p.Entries) == 0 {
		return nil, fmt.Errorf("pipeline has no entries")
	}
	return &p, nil
}

// applyRenames rewrites field names in every selection of the rule per the
// pipeline's rename map for this logsource. A field-less (keyword) matcher has
// no name and is left alone.
func (r *Rule) applyRenames(renames map[string]string) {
	if len(renames) == 0 {
		return
	}
	for name, sel := range r.selections {
		for ai := range sel.alts {
			for fi := range sel.alts[ai].fields {
				f := &sel.alts[ai].fields[fi]
				if f.field == "" {
					continue
				}
				if to, ok := renames[f.field]; ok {
					f.field = to
				}
			}
		}
		r.selections[name] = sel
	}
}
