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
	// StatePath is where the cursor is persisted.
	StatePath string `yaml:"statePath"`
	// Sources are the log inputs to scan.
	Sources []Source `yaml:"sources"`
	// Alerts configures the sinks.
	Alerts Alerts `yaml:"alerts"`
}

// Source is one log input.
type Source struct {
	// Type selects the parser: laurel | auditd | generic | sysmon (journald,
	// syslog are stubs). See parser.Registry.
	Type string `yaml:"type"`
	// Path is the file to read.
	Path string `yaml:"path"`
}

// Alerts groups the sink configs.
type Alerts struct {
	Journal JournalConfig `yaml:"journal"`
	JSONL   JSONLConfig   `yaml:"jsonl"`
	Webhook WebhookConfig `yaml:"webhook"`
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
	// "ocsf" for OCSF Detection Findings. An unknown value is a startup error
	// (buildSinks), never a silent fallback -- an operator who asked for OCSF
	// and got banken JSON would only find out from their SIEM.
	Format string `yaml:"format"`
}

// WebhookConfig configures the webhook sink.
type WebhookConfig struct {
	Enable  bool   `yaml:"enable"`
	URLFile string `yaml:"urlFile"`
	Style   string `yaml:"style"`
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
