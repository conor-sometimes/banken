package sigma

import (
	"errors"
	"fmt"
	"io/fs"
	"net/netip"
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
	Tags        []string             `yaml:"tags"`
	Optional    bool                 `yaml:"optional"`
	LogSource   rawLogSource         `yaml:"logsource"`
	Detection   map[string]yaml.Node `yaml:"detection"`
}

// rawLogSource is the `logsource:` block. Unknown keys (definition, ...) are
// ignored; only the three Sigma routing dimensions are read.
type rawLogSource struct {
	Category string `yaml:"category"`
	Product  string `yaml:"product"`
	Service  string `yaml:"service"`
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
// directly by tests/fuzzing), routing its logsource through the shipped
// pipeline.
func Compile(data []byte) (*Rule, error) {
	return compile(data, defaultPipeline)
}

// compile is Compile with an explicit pipeline, so tests can exercise routing
// and field aliases against a custom table.
func compile(data []byte, p *pipeline) (*Rule, error) {
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
		Description: strings.TrimSpace(raw.Description), // YAML's folded `>` leaves a trailing newline
		Tags:        raw.Tags,
		Optional:    raw.Optional,
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

	// Route the logsource through the pipeline: restrict the rule to the sensor
	// sources its logsource maps to, and apply any field aliases for them.
	ls := logSource{
		Category: raw.LogSource.Category,
		Product:  raw.LogSource.Product,
		Service:  raw.LogSource.Service,
	}
	if sources, renames, matched := p.route(ls); matched {
		rule.Sources = sources
		rule.applyRenames(renames)
	}
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
	case yaml.ScalarNode:
		// A lone string under a selection is a single keyword.
		return compileKeywordSelection(&node)
	case yaml.SequenceNode:
		if len(node.Content) == 0 {
			return selection{}, errors.New("empty list selection")
		}
		// A list of scalars is a Sigma "keyword" selection (match any string in
		// any field); a list of mappings is OR'd field conditions.
		if node.Content[0].Kind == yaml.ScalarNode {
			return compileKeywordSelection(&node)
		}
		alts := make([]selMap, 0, len(node.Content))
		for i := range node.Content {
			child := node.Content[i]
			if child.Kind != yaml.MappingNode {
				return selection{}, fmt.Errorf("list selection entry %d is neither a mapping nor a scalar keyword", i)
			}
			m, err := compileSelMap(*child)
			if err != nil {
				return selection{}, err
			}
			alts = append(alts, m)
		}
		return selection{alts: alts}, nil
	default:
		return selection{}, errors.New("selection must be a mapping, a list of mappings, or a list of keywords")
	}
}

// compileKeywordSelection builds a keyword selection from a scalar or a
// sequence of scalars.
func compileKeywordSelection(node *yaml.Node) (selection, error) {
	values, err := yamlValues(node)
	if err != nil {
		return selection{}, err
	}
	fm, err := compileKeywords(values)
	if err != nil {
		return selection{}, err
	}
	return selection{alts: []selMap{{fields: []fieldMatch{fm}}}}, nil
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
	b64 := b64None
	exists := false
	// An empty field (a bare modifier key like `|all`) is a keyword matcher
	// over all fields (Sigma's modifier-only keyword form), handled by the
	// field-less path in fieldMatch.match.
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
		case "cidr":
			fm.op = opCIDR
		case "all":
			fm.all = true
		case "base64":
			b64 = b64Plain
		case "base64offset":
			b64 = b64Offset
		case "exists":
			exists = true
		default:
			return fieldMatch{}, fmt.Errorf("unsupported modifier %q on field %q", mod, fm.field)
		}
	}

	// `field: null` with no comparison modifier is Sigma's field-absence test
	// (equivalent to `field|exists: false`). Catch it before yamlValues, which
	// rejects a null scalar.
	if !exists && isNullScalar(valNode) {
		if b64 != b64None || fm.op != opEquals || fm.all {
			return fieldMatch{}, fmt.Errorf("field %q: null is only valid as a bare `%s: null` absence test", fm.field, fm.field)
		}
		if fm.field == "" {
			return fieldMatch{}, errors.New("null needs a field name (a bare `null` keyword is meaningless)")
		}
		return fieldMatch{field: fm.field, op: opExists, existsWant: false, values: []string{"\x00exists"}}, nil
	}

	values, err := yamlValues(valNode)
	if err != nil {
		return fieldMatch{}, fmt.Errorf("field %q: %w", fm.field, err)
	}
	if len(values) == 0 {
		return fieldMatch{}, fmt.Errorf("field %q has no values", fm.field)
	}

	// `field|exists: true|false` is the explicit presence test. It takes a
	// single boolean and no other comparison/transform modifier.
	if exists {
		if b64 != b64None || fm.op != opEquals || fm.all || fm.field == "" {
			return fieldMatch{}, fmt.Errorf("field %q: |exists takes a single true/false and no other modifier", fm.field)
		}
		if len(values) != 1 {
			return fieldMatch{}, fmt.Errorf("field %q: |exists takes exactly one true/false value", fm.field)
		}
		want, perr := parseExistsBool(values[0])
		if perr != nil {
			return fieldMatch{}, fmt.Errorf("field %q: %w", fm.field, perr)
		}
		return fieldMatch{field: fm.field, op: opExists, existsWant: want, values: []string{"\x00exists"}}, nil
	}

	// base64 value transforms (|base64, |base64offset) rewrite the values to
	// their encoding(s) before the comparison op is applied, matching pySigma:
	// the trailing op (contains/startswith/endswith/equals) then compares the
	// ENCODED value. base64offset expands each value into three offset
	// encodings that are OR'd in with the field's existing any-match semantics.
	if b64 != b64None {
		enc, berr := applyBase64(b64, fm, values)
		if berr != nil {
			return fieldMatch{}, berr
		}
		values = enc
	}
	fm.values = values

	// A field-less key (a bare modifier like `|all`) is a keyword matcher: its
	// default is substring (contains), and its wildcards are unanchored, so
	// route the common forms through compileKeywords and carry the |all flag.
	if fm.field == "" && (fm.op == opEquals || fm.op == opContains) {
		kw, err := compileKeywords(values)
		if err != nil {
			return fieldMatch{}, err
		}
		kw.all = fm.all
		return kw, nil
	}

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
	case fm.op == opCIDR:
		fm.nets = make([]netip.Prefix, len(values))
		for i, v := range values {
			p, err := netip.ParsePrefix(strings.TrimSpace(v))
			if err != nil {
				return fieldMatch{}, fmt.Errorf("field %q: invalid CIDR %q: %w", fm.field, v, err)
			}
			fm.nets[i] = p
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
			re, err := regexp.Compile(sigmaGlobToRegexp(v, true)) // field wildcards match the whole field
			if err != nil {
				return fieldMatch{}, fmt.Errorf("field %q: bad wildcard pattern %q: %w", fm.field, v, err)
			}
			fm.res[i] = re
		}
	}
	return fm, nil
}

// compileKeywords builds a field-less matcher from a Sigma keyword list (a
// bare list of strings under a selection): it matches if any value appears in
// any of the event's text fields. Plain values use a substring (contains)
// test; a value with a wildcard becomes an unanchored regexp (a keyword is a
// substring match, not a whole-field match).
func compileKeywords(values []string) (fieldMatch, error) {
	if len(values) == 0 {
		return fieldMatch{}, errors.New("empty keyword list")
	}
	fm := fieldMatch{field: "", op: opContains, values: values}
	if needsGlobCompile(values) {
		fm.op = opRegexp
		fm.res = make([]*regexp.Regexp, len(values))
		for i, v := range values {
			re, err := regexp.Compile(sigmaGlobToRegexp(v, false)) // keyword = substring, unanchored
			if err != nil {
				return fieldMatch{}, fmt.Errorf("bad keyword pattern %q: %w", v, err)
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
func sigmaGlobToRegexp(s string, anchored bool) string {
	var b strings.Builder
	b.WriteString("(?i)")
	if anchored {
		b.WriteString("^")
	}
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
	if anchored {
		b.WriteString("$")
	}
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

// scalarString returns a scalar's literal text. A null scalar is rejected
// here: the only meaningful place for a null is a bare `field: null` absence
// test, which compileField catches before reaching this path. A null anywhere
// else (e.g. inside a value list) has no defined Sigma meaning for a value
// comparison and would silently never fire, so it is reported at load time.
func scalarString(node *yaml.Node) (string, error) {
	if node.Tag == "!!null" {
		return "", errors.New("null value is only valid as a bare `field: null` absence test, not inside a value list")
	}
	// yaml.v3 leaves Value as the literal source text for every scalar kind
	// (string, int, bool), which is exactly what a matcher wants.
	return node.Value, nil
}

// isNullScalar reports whether a YAML node is a null scalar (`field: null`,
// `field: ~`, or an empty value), which Sigma reads as a field-absence test.
func isNullScalar(node *yaml.Node) bool {
	return node != nil && node.Kind == yaml.ScalarNode && node.Tag == "!!null"
}

// parseExistsBool reads the true/false value of a |exists modifier. Sigma
// writes it as a YAML boolean; accept the common spellings.
func parseExistsBool(s string) (bool, error) {
	switch strings.ToLower(strings.TrimSpace(s)) {
	case "true", "yes", "1":
		return true, nil
	case "false", "no", "0":
		return false, nil
	default:
		return false, fmt.Errorf("|exists wants true or false, got %q", s)
	}
}

// applyBase64 rewrites a field's values to their base64 encoding(s) for the
// |base64 / |base64offset modifiers, mirroring pySigma. A value carrying a
// Sigma wildcard is rejected: pySigma forbids it (the encoding of a pattern is
// meaningless), and silently encoding the literal `*` would be a dead rule.
func applyBase64(mode b64Mode, fm fieldMatch, values []string) ([]string, error) {
	if fm.op == opRegexp || fm.op == opCIDR {
		return nil, fmt.Errorf("field %q: base64 cannot combine with |re or |cidr", fm.field)
	}
	for _, v := range values {
		if strings.ContainsAny(v, "*?") {
			return nil, fmt.Errorf("field %q: base64 encoding of a value with a wildcard is not allowed", fm.field)
		}
	}
	switch mode {
	case b64Plain:
		out := make([]string, len(values))
		for i, v := range values {
			out[i] = base64Encode(v)
		}
		return out, nil
	case b64Offset:
		out := make([]string, 0, len(values)*3)
		for _, v := range values {
			out = append(out, base64OffsetEncodings(v)...)
		}
		return out, nil
	default:
		return values, nil
	}
}
