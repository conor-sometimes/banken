package alert

import (
	"bytes"
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"net/http"
	"os"
	"strings"
	"time"
)

// WebhookStyle shapes the POST body for a particular receiver.
type WebhookStyle string

const (
	// StyleGeneric posts the raw Alert JSON.
	StyleGeneric WebhookStyle = "generic"
	// StyleSlack posts {"text": ...} (Slack/Mattermost incoming webhook).
	StyleSlack WebhookStyle = "slack"
	// StyleDiscord posts {"content": ...} (Discord webhook).
	StyleDiscord WebhookStyle = "discord"
	// StyleNtfy posts a plain-text body (ntfy topic).
	StyleNtfy WebhookStyle = "ntfy"
	// StyleOCSF posts the OCSF Detection Finding JSON (application/json), for
	// a generic OCSF HTTP receiver, Datadog log intake, or Splunk HEC /raw.
	StyleOCSF WebhookStyle = "ocsf"
)

// WebhookSink POSTs each alert to a URL. The URL is a secret and is read
// from a file path (a systemd credential, sops/agenix output), never held
// inline in config or the Nix store. Shaping is per-style so Slack/Discord/
// ntfy get a body they render, while generic receivers get the full Alert
// JSON.
type WebhookSink struct {
	url    string
	style  WebhookStyle
	client *http.Client
	ocsf   OCSFOptions // used only by StyleOCSF
}

// WebhookConfig configures a WebhookSink.
type WebhookConfig struct {
	// URLFile is the path the webhook URL is read from (required).
	URLFile string
	// URL, if set, is used directly and URLFile is ignored -- for tests
	// pointing at an httptest server. Production always uses URLFile.
	URL string
	// Style selects the body shaping (defaults to generic).
	Style WebhookStyle
	// Client is the HTTP client (defaults to a 10s-timeout client).
	Client *http.Client
	// OCSF is the per-deployment context for StyleOCSF (ignored otherwise).
	OCSF OCSFOptions
}

// NewWebhookSink reads the URL from the configured file (or uses the inline
// URL for tests) and returns a ready sink.
func NewWebhookSink(cfg WebhookConfig) (*WebhookSink, error) {
	url := strings.TrimSpace(cfg.URL)
	if url == "" {
		if cfg.URLFile == "" {
			return nil, errors.New("webhook: no urlFile configured")
		}
		data, err := os.ReadFile(cfg.URLFile) //nolint:gosec // operator-supplied secret path
		if err != nil {
			return nil, fmt.Errorf("webhook: read urlFile %s: %w", cfg.URLFile, err)
		}
		url = strings.TrimSpace(string(data))
		if url == "" {
			return nil, fmt.Errorf("webhook: urlFile %s is empty", cfg.URLFile)
		}
	}
	style := cfg.Style
	if style == "" {
		style = StyleGeneric
	}
	client := cfg.Client
	if client == nil {
		client = &http.Client{Timeout: 10 * time.Second}
	}
	return &WebhookSink{url: url, style: style, client: client, ocsf: cfg.OCSF}, nil
}

// Name implements Sink.
func (*WebhookSink) Name() string { return "webhook" }

// Emit implements Sink: shapes and POSTs the alert, treating any non-2xx
// response as an error. An observe-mode hit is skipped: the webhook is a
// notify path, and observe mode is "recorded, never paged".
func (s *WebhookSink) Emit(a Alert) error {
	if a.Observed {
		return nil
	}
	body, contentType, err := s.shape(a)
	if err != nil {
		return err
	}
	ctx, cancel := context.WithTimeout(context.Background(), 15*time.Second)
	defer cancel()
	req, err := http.NewRequestWithContext(ctx, http.MethodPost, s.url, bytes.NewReader(body))
	if err != nil {
		return fmt.Errorf("webhook: build request: %w", err)
	}
	req.Header.Set("Content-Type", contentType)
	resp, err := s.client.Do(req)
	if err != nil {
		return fmt.Errorf("webhook: POST: %w", err)
	}
	defer func() { _ = resp.Body.Close() }()
	if resp.StatusCode < 200 || resp.StatusCode >= 300 {
		return fmt.Errorf("webhook: POST returned %s", resp.Status)
	}
	return nil
}

// Close implements Sink (nothing to release).
func (*WebhookSink) Close() error { return nil }

// shape builds the request body for the configured style.
func (s *WebhookSink) shape(a Alert) (body []byte, contentType string, err error) {
	switch s.style {
	case StyleSlack:
		b, e := json.Marshal(map[string]string{"text": summaryLine(a)})
		return b, "application/json", e
	case StyleDiscord:
		b, e := json.Marshal(map[string]string{"content": summaryLine(a)})
		return b, "application/json", e
	case StyleNtfy:
		return []byte(summaryLine(a)), "text/plain", nil
	case StyleOCSF:
		b, e := EncodeOCSF(s.ocsf)(a)
		return b, "application/json", e
	default: // generic
		b, e := json.Marshal(a)
		return b, "application/json", e
	}
}

// summaryLine is the one-line human form used by the chat/ntfy styles.
func summaryLine(a Alert) string {
	b := &strings.Builder{}
	fmt.Fprintf(b, "[banken %s] %s", strings.ToUpper(a.Level), a.Title)
	if a.Event.Image != "" {
		fmt.Fprintf(b, " — %s", a.Event.Image)
	}
	if a.Event.CommandLine != "" {
		fmt.Fprintf(b, " (%s)", a.Event.CommandLine)
	}
	if a.IOC != "" {
		fmt.Fprintf(b, " ioc=%s", a.IOC)
	}
	return b.String()
}
