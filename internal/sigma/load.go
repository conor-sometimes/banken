package sigma

import (
	"errors"
	"fmt"
	"io/fs"
	"os"
	"path"
	"path/filepath"
	"regexp"
	"sort"
	"strings"

	"gopkg.in/yaml.v3"
)

// RuleError pairs a rule file with why it could not be loaded.
type RuleError struct {
	Path string
	Err  error
}

func (e RuleError) Error() string { return fmt.Sprintf("%s: %v", e.Path, e.Err) }
func (e RuleError) Unwrap() error { return e.Err }

// LoadTree walks each dir for *.yml / *.yaml files under any subdirectory
// (ioc/ is skipped -- those are plain IOC lists, not Sigma) and compiles
// them. It returns every rule that compiled and a slice of RuleError for
// every file that did not: a bad rule is reported, never silently
// dropped, and one bad rule never stops the good ones from loading. The
// caller decides whether a non-empty problem list is fatal.
func LoadTree(dirs ...string) ([]*Rule, []RuleError) {
	var rules []*Rule
	var problems []RuleError
	seen := map[string]bool{}

	for _, dir := range dirs {
		_ = filepath.WalkDir(dir, func(path string, d fs.DirEntry, err error) error {
			if err != nil {
				problems = append(problems, RuleError{Path: path, Err: err})
				return nil
			}
			if d.IsDir() {
				if d.Name() == "ioc" {
					return filepath.SkipDir
				}
				return nil
			}
			ext := strings.ToLower(filepath.Ext(path))
			if ext != ".yml" && ext != ".yaml" {
				return nil
			}
			if seen[path] {
				return nil
			}
			seen[path] = true

			rule, perr := LoadFile(path)
			if perr != nil {
				problems = append(problems, RuleError{Path: path, Err: perr})
				return nil
			}
			rules = append(rules, rule)
			return nil
		})
	}

	sort.Slice(rules, func(i, j int) bool { return rules[i].Name < rules[j].Name })
	return rules, problems
}

// LoadFS is LoadTree over an fs.FS instead of the real filesystem, so the
// binary can carry a baseline ruleset embedded with //go:embed and still be
// read by the same compiler. roots are directories within fsys (slash
// paths). Same contract as LoadTree: every rule that compiled, plus a
// RuleError per file that did not; ioc/ is skipped.
func LoadFS(fsys fs.FS, roots ...string) ([]*Rule, []RuleError) {
	var rules []*Rule
	var problems []RuleError
	seen := map[string]bool{}

	for _, root := range roots {
		_ = fs.WalkDir(fsys, root, func(p string, d fs.DirEntry, err error) error {
			if err != nil {
				problems = append(problems, RuleError{Path: p, Err: err})
				return nil
			}
			if d.IsDir() {
				if d.Name() == "ioc" {
					return fs.SkipDir
				}
				return nil
			}
			ext := strings.ToLower(path.Ext(p))
			if ext != ".yml" && ext != ".yaml" {
				return nil
			}
			if seen[p] {
				return nil
			}
			seen[p] = true

			data, rerr := fs.ReadFile(fsys, p)
			if rerr != nil {
				problems = append(problems, RuleError{Path: p, Err: rerr})
				return nil
			}
			rule, perr := Compile(data)
			if perr != nil {
				problems = append(problems, RuleError{Path: p, Err: perr})
				return nil
			}
			rule.Path = p
			rule.Name = strings.TrimSuffix(path.Base(p), path.Ext(p))
			rules = append(rules, rule)
			return nil
		})
	}

	sort.Slice(rules, func(i, j int) bool { return rules[i].Name < rules[j].Name })
	return rules, problems
}

// rawRule is the YAML shape before compilation.
type rawRule struct {
	Title       string               `yaml:"title"`
	ID          string               `yaml:"id"`
	Level       string               `yaml:"level"`
	Description string               `yaml:"description"`
	Detection   map[string]yaml.Node `yaml:"detection"`
}

// LoadFile reads and compiles one Sigma rule file.
func LoadFile(path string) (*Rule, error) {
	data, err := os.ReadFile(path) //nolint:gosec // operator-supplied rules dir, not an untrusted caller's path
	if err != nil {
		return nil, err
	}
	rule, err := Compile(data)
	if err != nil {
		return nil, err
	}
	rule.Path = path
	rule.Name = strings.TrimSuffix(filepath.Base(path), filepath.Ext(path))
	return rule, nil
}

// Compile parses and compiles rule YAML from bytes (used by LoadFile and
// directly by tests/fuzzing).
func Compile(data []byte) (*Rule, error) {
	var raw rawRule
	if err := yaml.Unmarshal(data, &raw); err != nil {
		return nil, fmt.Errorf("invalid YAML: %w", err)
	}
	if len(raw.Detection) == 0 {
		return nil, errors.New("rule has no detection block")
	}
	condNode, ok := raw.Detection["condition"]
	if !ok {
		return nil, errors.New("detection block has no condition")
	}
	var condStr string
	if err := condNode.Decode(&condStr); err != nil || strings.TrimSpace(condStr) == "" {
		return nil, errors.New("condition must be a non-empty string")
	}

	rule := &Rule{
		Title:       raw.Title,
		ID:          raw.ID,
		Level:       raw.Level,
		Description: raw.Description,
		selections:  map[string]selection{},
	}

	selNames := map[string]struct{}{}
	for name, node := range raw.Detection {
		if name == "condition" {
			continue
		}
		sel, err := compileSelection(node)
		if err != nil {
			return nil, fmt.Errorf("selection %q: %w", name, err)
		}
		rule.selections[name] = sel
		selNames[name] = struct{}{}
	}
	if len(selNames) == 0 {
		return nil, errors.New("detection block has no selections")
	}

	cond, err := parseCondition(condStr, selNames)
	if err != nil {
		return nil, fmt.Errorf("condition: %w", err)
	}
	rule.cond = cond
	return rule, nil
}

func compileSelection(node yaml.Node) (selection, error) {
	switch node.Kind {
	case yaml.MappingNode:
		m, err := compileSelMap(node)
		if err != nil {
			return selection{}, err
		}
		return selection{alts: []selMap{m}}, nil
	case yaml.SequenceNode:
		var alts []selMap
		for i := range node.Content {
			child := node.Content[i]
			if child.Kind != yaml.MappingNode {
				return selection{}, fmt.Errorf("list selection entry %d is not a mapping", i)
			}
			m, err := compileSelMap(*child)
			if err != nil {
				return selection{}, err
			}
			alts = append(alts, m)
		}
		if len(alts) == 0 {
			return selection{}, errors.New("empty list selection")
		}
		return selection{alts: alts}, nil
	default:
		return selection{}, errors.New("selection must be a mapping or a list of mappings")
	}
}

func compileSelMap(node yaml.Node) (selMap, error) {
	var m selMap
	if len(node.Content)%2 != 0 {
		return selMap{}, errors.New("malformed mapping")
	}
	for i := 0; i < len(node.Content); i += 2 {
		key := node.Content[i].Value
		valNode := node.Content[i+1]
		fm, err := compileField(key, valNode)
		if err != nil {
			return selMap{}, err
		}
		m.fields = append(m.fields, fm)
	}
	if len(m.fields) == 0 {
		return selMap{}, errors.New("empty selection mapping")
	}
	return m, nil
}

func compileField(key string, valNode *yaml.Node) (fieldMatch, error) {
	parts := strings.Split(key, "|")
	fm := fieldMatch{field: parts[0], op: opEquals}
	if fm.field == "" {
		return fieldMatch{}, errors.New("empty field name")
	}
	for _, mod := range parts[1:] {
		switch strings.ToLower(mod) {
		case "contains":
			fm.op = opContains
		case "startswith":
			fm.op = opStartsWith
		case "endswith":
			fm.op = opEndsWith
		case "re", "regex":
			fm.op = opRegexp
		case "all":
			fm.all = true
		default:
			return fieldMatch{}, fmt.Errorf("unsupported modifier %q on field %q", mod, fm.field)
		}
	}

	values, err := yamlValues(valNode)
	if err != nil {
		return fieldMatch{}, fmt.Errorf("field %q: %w", fm.field, err)
	}
	if len(values) == 0 {
		return fieldMatch{}, fmt.Errorf("field %q has no values", fm.field)
	}
	fm.values = values

	switch {
	case fm.op == opRegexp:
		fm.res = make([]*regexp.Regexp, len(values))
		for i, v := range values {
			re, err := regexp.Compile(v)
			if err != nil {
				return fieldMatch{}, fmt.Errorf("field %q: invalid regexp %q: %w", fm.field, v, err)
			}
			fm.res[i] = re
		}
	case fm.op == opEquals && needsGlobCompile(values):
		// A plain (unmodified) value containing a Sigma wildcard (* or ?) or a
		// backslash escape is a glob, not a plain literal -- matching it
		// literally would silently never fire (or keep the backslash), so
		// compile the whole field to anchored, case-insensitive regexps that
		// resolve the escapes. A value with no metacharacters in the same list
		// becomes an exact-match regexp, preserving its equality semantics.
		fm.op = opRegexp
		fm.res = make([]*regexp.Regexp, len(values))
		for i, v := range values {
			re, err := regexp.Compile(sigmaGlobToRegexp(v))
			if err != nil {
				return fieldMatch{}, fmt.Errorf("field %q: bad wildcard pattern %q: %w", fm.field, v, err)
			}
			fm.res[i] = re
		}
	}
	return fm, nil
}

// needsGlobCompile reports whether any value carries a Sigma wildcard (* or ?)
// or a backslash escape, meaning the field must be compiled as a pattern
// rather than matched as a plain literal.
func needsGlobCompile(values []string) bool {
	for _, v := range values {
		if strings.ContainsAny(v, `*?\`) {
			return true
		}
	}
	return false
}

// sigmaGlobToRegexp compiles a Sigma value into an anchored, case-insensitive
// regexp pattern: `*` -> `.*`, `?` -> `.`, `\x` -> literal x, every other
// character quoted. A value with no wildcards becomes an exact (anchored)
// match, so equality still means equality. Matching the whole field (anchored)
// is Sigma's wildcard semantics.
func sigmaGlobToRegexp(s string) string {
	var b strings.Builder
	b.WriteString("(?i)^")
	esc := false
	for _, r := range s {
		switch {
		case esc:
			b.WriteString(regexp.QuoteMeta(string(r)))
			esc = false
		case r == '\\':
			esc = true
		case r == '*':
			b.WriteString(".*")
		case r == '?':
			b.WriteString(".")
		default:
			b.WriteString(regexp.QuoteMeta(string(r)))
		}
	}
	if esc { // a trailing backslash with nothing to escape -> treat as literal
		b.WriteString(regexp.QuoteMeta("\\"))
	}
	b.WriteString("$")
	return b.String()
}

// yamlValues reads a scalar or a sequence of scalars as []string, rendering
// numbers and bools as their literal text.
func yamlValues(node *yaml.Node) ([]string, error) {
	switch node.Kind {
	case yaml.ScalarNode:
		s, err := scalarString(node)
		if err != nil {
			return nil, err
		}
		return []string{s}, nil
	case yaml.SequenceNode:
		out := make([]string, 0, len(node.Content))
		for _, c := range node.Content {
			if c.Kind != yaml.ScalarNode {
				return nil, errors.New("value list entries must be scalars")
			}
			s, err := scalarString(c)
			if err != nil {
				return nil, err
			}
			out = append(out, s)
		}
		return out, nil
	default:
		return nil, errors.New("value must be a scalar or a list of scalars")
	}
}

// scalarString returns a scalar's literal text. A null is rejected rather than
// coerced to "": a `Field: null` matcher would silently never fire (an empty
// string never matches a present field), so it is reported at load time
// instead of becoming a silently-dead detection. (Sigma's null = "field
// absent" semantics are not yet implemented; see the roadmap.)
func scalarString(node *yaml.Node) (string, error) {
	if node.Tag == "!!null" {
		return "", errors.New("null value is not supported (it would never match); give the field a value or remove it")
	}
	// yaml.v3 leaves Value as the literal source text for every scalar kind
	// (string, int, bool), which is exactly what a matcher wants.
	return node.Value, nil
}
