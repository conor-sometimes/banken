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

func TestAutoDetectSources(t *testing.T) {
	// A fake filesystem: only the paths in `present` exist (as files).
	fake := func(present ...string) func(string) (os.FileInfo, error) {
		set := map[string]bool{}
		for _, p := range present {
			set[p] = true
		}
		return func(p string) (os.FileInfo, error) {
			if set[p] {
				fi, err := os.Stat(os.DevNull) // a real non-dir FileInfo
				return fi, err
			}
			return nil, os.ErrNotExist
		}
	}

	cases := []struct {
		name    string
		present []string
		wantTyp string // "" = expect no source
	}{
		{"none", nil, ""},
		{"laurel only", []string{"/var/log/laurel/audit.log"}, "laurel"},
		{"auditd only", []string{"/var/log/audit/audit.log"}, "auditd"},
		{"both prefers laurel", []string{"/var/log/laurel/audit.log", "/var/log/audit/audit.log"}, "laurel"},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			got := AutoDetectSources(fake(tc.present...))
			if tc.wantTyp == "" {
				if len(got) != 0 {
					t.Fatalf("expected no source, got %+v", got)
				}
				return
			}
			if len(got) != 1 || got[0].Type != tc.wantTyp {
				t.Fatalf("got %+v, want one %q source", got, tc.wantTyp)
			}
		})
	}
}

func TestAutoDetectSkipsADirectory(t *testing.T) {
	// A candidate path that exists but is a directory must be skipped.
	statFn := func(p string) (os.FileInfo, error) {
		if p == "/var/log/laurel/audit.log" {
			return os.Stat(t.TempDir()) // a dir
		}
		return nil, os.ErrNotExist
	}
	if got := AutoDetectSources(statFn); len(got) != 0 {
		t.Fatalf("a directory candidate should be skipped, got %+v", got)
	}
}
