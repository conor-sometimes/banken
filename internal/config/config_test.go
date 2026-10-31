package config

import (
	"os"
	"path/filepath"
	"testing"

	"github.com/conor-sometimes/banken/internal/alert"
)

func TestLoadMergesOntoDefaults(t *testing.T) {
	dir := t.TempDir()
	path := filepath.Join(dir, "banken.yml")
	yml := `rules:
  - /etc/banken/rules
sources:
  - type: laurel
    path: /var/log/laurel/audit.log
alerts:
  jsonl:
    enable: true
    dir: /var/lib/banken/alerts
    retentionDays: 14
  webhook:
    enable: true
    urlFile: /run/secrets/hook
    style: slack
`
	if err := os.WriteFile(path, []byte(yml), 0o600); err != nil {
		t.Fatal(err)
	}
	cfg, err := Load(path)
	if err != nil {
		t.Fatalf("Load: %v", err)
	}
	if len(cfg.Rules) != 1 || cfg.Rules[0] != "/etc/banken/rules" {
		t.Errorf("Rules = %v", cfg.Rules)
	}
	if len(cfg.Sources) != 1 || cfg.Sources[0].Type != "laurel" {
		t.Errorf("Sources = %+v", cfg.Sources)
	}
	// Journal default (true) survives since the file did not mention it.
	if !cfg.Alerts.Journal.Enable {
		t.Error("journal default (enabled) should persist when config omits it")
	}
	if cfg.Alerts.JSONL.RetentionDays != 14 {
		t.Errorf("retentionDays = %d", cfg.Alerts.JSONL.RetentionDays)
	}
	if cfg.Alerts.Webhook.WebhookStyle() != alert.StyleSlack {
		t.Errorf("style = %v", cfg.Alerts.Webhook.WebhookStyle())
	}
}

func TestWebhookStyleDefaultsToGeneric(t *testing.T) {
	for _, s := range []string{"", "bogus"} {
		if got := (WebhookConfig{Style: s}).WebhookStyle(); got != alert.StyleGeneric {
			t.Errorf("style %q -> %v, want generic", s, got)
		}
	}
}

func TestLoadMissingFileIsError(t *testing.T) {
	if _, err := Load("/no/such/config.yml"); err == nil {
		t.Error("expected error for missing config file")
	}
}
