// Package config is banken's on-disk configuration: which log sources to
// read and which alert sinks to enable. It is YAML (matching the NixOS
// module's options), with flag overrides applied on top in main. Secrets
// are never in here -- the webhook URL is a file path, read at runtime.
package config

import (
	"fmt"
	"os"

	"gopkg.in/yaml.v3"

	"github.com/conor-sometimes/banken/internal/alert"
)

// Config is the whole configuration.
type Config struct {
	// Rules are the rule-tree directories to load (Sigma + ioc/).
	Rules []string `yaml:"rules"`
	// RefreshDirs are rule-tree directories that are refreshable at runtime:
	// loaded exactly like Rules (recursive, *.yml / *.yaml, ioc/ carrying IOC
	// lists) but at the highest precedence (they win a name clash over the
	// embedded baseline and over Rules), and, on NixOS, NOT copied into the Nix
	// store -- a real on-disk path banken reads live. This is the fleet's
	// rules-repo checkout: a separate puller unit lands a git checkout here and
	// SIGHUPs the daemon, which rebuilds its rule set from these dirs without a
	// binary redeploy (see docs/design/rule-refresh.md). Empty is the common
	// case and keeps today's behaviour (baseline + Rules, no runtime refresh).
	RefreshDirs []string `yaml:"refreshDirs"`
	// OptionalRules names the opt-in (optional: true) rules to activate, by
	// rule name (file basename), or "*" for all of them. Optional rules are
	// policy detections that ship in the binary but held back by default
	// because they are noisy or environment-specific (netcat use, a password
	// cracker); an operator turns on the ones their host wants. A name here
	// that matches no optional rule is warned about at startup, not silently
	// ignored -- a mis-typed enable is a detection that silently is not running.
	OptionalRules []string `yaml:"optionalRules"`
	// ObserveRules names optional rules to run in observe mode, by rule name
	// or "*": they evaluate and their hits are recorded (jsonl, run summary)
	// but marked "observed" so the paging sinks (journal, webhook) skip them.
	// It lets a host measure a rule's noise before letting it page. A rule
	// named in both optionalRules and observeRules pages (the explicit enable
	// wins). Names that match no optional rule are warned about at startup.
	ObserveRules []string `yaml:"observeRules"`
	// StatePath is where the cursor is persisted.
	StatePath string `yaml:"statePath"`
	// Sources are the log inputs to scan.
	Sources []Source `yaml:"sources"`
	// Intel are threat-intel feeds (STIX 2.1 / MISP files, TAXII 2.1
	// collections) whose indicators are normalised into the same IOC set the
	// rules/ioc/*.txt lists feed, so the match engine consumes them unchanged.
	// Empty is the common case: an operator with no external feed still gets
	// the embedded baseline and any on-disk rules/ioc lists. A feed that fails
	// to load or poll is warned about and the run continues (never-die); it is
	// not a startup error, so one dead TAXII server cannot stop detection.
	Intel []IntelFeed `yaml:"intel"`
	// Alerts configures the sinks.
	Alerts Alerts `yaml:"alerts"`
}

// IntelFeed is one threat-intel feed. Type selects the ingest path:
//   - "stix" / "misp": Path is a local bundle/export file, parsed each run.
//   - "taxii": URL is the TAXII 2.1 API root and Collection the collection id,
//     polled each run. TokenFile (bearer) or Username/Password (basic) carry
//     optional auth; a secret lives in TokenFile (a credential path), never
//     inline, the same rule the webhook URL follows.
//
// Name labels every indicator the feed contributes, so an alert says which
// feed paged. An empty Name defaults to the file base name or the feed type.
type IntelFeed struct {
	Type       string `yaml:"type"`
	Name       string `yaml:"name"`
	Path       string `yaml:"path"`
	URL        string `yaml:"url"`
	Collection string `yaml:"collection"`
	TokenFile  string `yaml:"tokenFile"`
	Username   string `yaml:"username"`
	Password   string `yaml:"password"`
}

// Source is one log input.
type Source struct {
	// Type selects the parser: laurel | auditd | journald | syslog.
	Type string `yaml:"type"`
	// Path is the file to read.
	Path string `yaml:"path"`
}

// Alerts groups the sink configs.
type Alerts struct {
	Journal JournalConfig `yaml:"journal"`
	JSONL   JSONLConfig   `yaml:"jsonl"`
	Webhook WebhookConfig `yaml:"webhook"`
	OTLP    OTLPConfig    `yaml:"otlp"`
}

// OTLPConfig configures the OpenTelemetry (OTLP/HTTP) log exporter. OCSF is the schema, OTLP the
// pipe: point Endpoint at a collector's logs URL and any OTel backend ingests banken's findings.
type OTLPConfig struct {
	Enable   bool   `yaml:"enable"`
	Endpoint string `yaml:"endpoint"` // full logs URL, e.g. http://collector:4318/v1/logs
	// Headers are optional request headers (e.g. auth for a hosted collector). A secret here comes
	// from the operator's config/credential, never the Nix store.
	Headers map[string]string `yaml:"headers"`
}

// JournalConfig configures the journal sink.
type JournalConfig struct {
	Enable bool `yaml:"enable"`
}

// JSONLConfig configures the jsonl sink.
type JSONLConfig struct {
	Enable        bool   `yaml:"enable"`
	Dir           string `yaml:"dir"`
	RetentionDays int    `yaml:"retentionDays"`
	// Format is the on-disk encoding: "" or "banken" for the native shape,
	// "ocsf" for OCSF Detection Findings, "ecs" for Elastic Common Schema. An
	// unknown value is a startup error (buildSinks), never a silent fallback --
	// an operator who asked for OCSF and got banken JSON would only find out
	// from their SIEM.
	Format string `yaml:"format"`
}

// WebhookConfig configures the webhook sink.
type WebhookConfig struct {
	Enable  bool   `yaml:"enable"`
	URLFile string `yaml:"urlFile"`
	// URL is the webhook URL inline, used only when URLFile is unset. Most webhook URLs embed a
	// secret token (Slack, Discord), which belongs in URLFile (a credential), never here where it
	// lands in the Nix store; URL is for a genuinely non-secret receiver.
	URL   string `yaml:"url"`
	Style string `yaml:"style"`
}

// Default returns a config with sensible defaults for a one-shot run. The
// defaults are the whole point of the zero-fiddle goal: with no config file
// and no flags, banken loads its embedded baseline rules plus /etc/banken/rules
// if present, auto-detects the host's log source (see AutoDetectSources),
// and alerts to the journal.
func Default() Config {
	return Config{
		Rules:     []string{"/etc/banken/rules"},
		StatePath: "/var/lib/banken/cursor.json",
		Alerts: Alerts{
			Journal: JournalConfig{Enable: true},
		},
	}
}

// candidateSources are the known host log locations, in preference order:
// Laurel's enriched JSON first, then the raw audit log. They carry the same
// events (Laurel is auditd -> JSON), so AutoDetectSources picks the first that
// exists rather than reading both and double-alerting.
var candidateSources = []Source{
	{Type: "laurel", Path: "/var/log/laurel/audit.log"},
	{Type: "auditd", Path: "/var/log/audit/audit.log"},
}

// AutoDetectSources returns the first candidate log source that exists and is
// readable, or nil if none do. It is used when neither the config nor the
// flags name any source, so `banken` with no arguments still finds the host's
// audit log on a normal system. statFn is injected for testing; pass nil for
// the real filesystem.
func AutoDetectSources(statFn func(string) (os.FileInfo, error)) []Source {
	if statFn == nil {
		statFn = os.Stat
	}
	for _, s := range candidateSources {
		if fi, err := statFn(s.Path); err == nil && !fi.IsDir() {
			return []Source{s}
		}
	}
	return nil
}

// Load reads and parses a YAML config file.
func Load(path string) (Config, error) {
	data, err := os.ReadFile(path) //nolint:gosec // operator-supplied config path
	if err != nil {
		return Config{}, fmt.Errorf("config: read %s: %w", path, err)
	}
	cfg := Default()
	if err := yaml.Unmarshal(data, &cfg); err != nil {
		return Config{}, fmt.Errorf("config: parse %s: %w", path, err)
	}
	return cfg, nil
}

// WebhookStyle maps the config string to the alert package's style,
// defaulting to generic for an empty or unknown value.
func (w WebhookConfig) WebhookStyle() alert.WebhookStyle {
	switch alert.WebhookStyle(w.Style) {
	case alert.StyleSlack:
		return alert.StyleSlack
	case alert.StyleDiscord:
		return alert.StyleDiscord
	case alert.StyleNtfy:
		return alert.StyleNtfy
	case alert.StyleOCSF:
		return alert.StyleOCSF
	default:
		return alert.StyleGeneric
	}
}
