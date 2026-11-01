// Command attack-layer emits an ATT&CK Navigator layer (JSON) for the techniques banken's rules
// detect, so anyone can open the standard heatmap of banken's coverage at
// https://mitre-attack.github.io/attack-navigator/ . Each technique's score is the number of rules
// that carry it, so hot cells are the well-covered techniques. It reads banken's own rule tree
// (the attack.tXXXX tags) and writes the layer to stdout:
//
//	go run ./tools/attack-layer rules > banken.layer.json
package main

import (
	"encoding/json"
	"fmt"
	"io/fs"
	"os"
	"path/filepath"
	"regexp"
	"sort"
	"strings"

	"github.com/conor-sometimes/banken/internal/sigma"
)

// attack.t1059 or attack.t1059.004 (case-insensitive); the tactic tags (attack.execution) are not
// techniques and are skipped.
var techTag = regexp.MustCompile(`(?i)^attack\.(t\d+(?:\.\d+)?)$`)

type layer struct {
	Name        string            `json:"name"`
	Versions    map[string]string `json:"versions"`
	Domain      string            `json:"domain"`
	Description string            `json:"description"`
	Techniques  []technique       `json:"techniques"`
	Gradient    gradient          `json:"gradient"`
	Sorting     int               `json:"sorting"`
}

type technique struct {
	TechniqueID string `json:"techniqueID"`
	Score       int    `json:"score"`
	Enabled     bool   `json:"enabled"`
	Comment     string `json:"comment,omitempty"`
}

type gradient struct {
	Colors   []string `json:"colors"`
	MinValue int      `json:"minValue"`
	MaxValue int      `json:"maxValue"`
}

func main() {
	dirs := os.Args[1:]
	if len(dirs) == 0 {
		dirs = []string{"rules"}
	}

	counts := map[string]int{}   // technique id -> number of rules
	rulesFor := map[string][]string{} // technique id -> rule names
	for _, dir := range dirs {
		_ = filepath.WalkDir(dir, func(p string, d fs.DirEntry, err error) error {
			if err != nil || d.IsDir() {
				return nil //nolint:nilerr
			}
			if ext := strings.ToLower(filepath.Ext(p)); ext != ".yml" && ext != ".yaml" {
				return nil
			}
			data, e := os.ReadFile(p) //nolint:gosec // a rule tree the operator pointed us at
			if e != nil {
				return nil
			}
			r, e := sigma.Compile(data)
			if e != nil {
				return nil
			}
			for _, tag := range r.Tags {
				if m := techTag.FindStringSubmatch(tag); m != nil {
					id := strings.ToUpper(m[1])
					counts[id]++
					rulesFor[id] = append(rulesFor[id], r.Name)
				}
			}
			return nil
		})
	}

	ids := make([]string, 0, len(counts))
	max := 0
	for id, c := range counts {
		ids = append(ids, id)
		if c > max {
			max = c
		}
	}
	sort.Strings(ids)

	techs := make([]technique, 0, len(ids))
	for _, id := range ids {
		names := rulesFor[id]
		sort.Strings(names)
		techs = append(techs, technique{
			TechniqueID: id,
			Score:       counts[id],
			Enabled:     true,
			Comment:     "banken rules: " + strings.Join(names, ", "),
		})
	}

	l := layer{
		Name:        "banken coverage",
		Versions:    map[string]string{"attack": "15", "navigator": "5.0.0", "layer": "4.5"},
		Domain:      "enterprise-attack",
		Description: fmt.Sprintf("ATT&CK techniques banken detects, generated from its Sigma rules (%d techniques, %d rules).", len(ids), func() int { n := 0; for _, c := range counts { n += c }; return n }()),
		Techniques:  techs,
		Gradient:    gradient{Colors: []string{"#ffffff", "#66b1ff", "#1f6fd0"}, MinValue: 0, MaxValue: max},
		Sorting:     3, // descending by score
	}

	enc := json.NewEncoder(os.Stdout)
	enc.SetIndent("", "  ")
	if err := enc.Encode(l); err != nil {
		fmt.Fprintln(os.Stderr, "attack-layer:", err)
		os.Exit(1)
	}
	fmt.Fprintf(os.Stderr, "attack-layer: %d techniques across %d rules\n", len(ids), func() int { n := 0; for _, c := range counts { n += c }; return n }())
}
