package alert

import (
	"encoding/json"
	"io"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
	"time"

	"github.com/conor-sometimes/banken/internal/event"
)

func TestOTLPSinkEmitsValidLogRecord(t *testing.T) {
	var got []byte
	var gotCT, gotAuth string
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		got, _ = io.ReadAll(r.Body)
		gotCT = r.Header.Get("Content-Type")
		gotAuth = r.Header.Get("Authorization")
		w.WriteHeader(http.StatusOK)
	}))
	defer srv.Close()

	s, err := NewOTLPSink(OTLPConfig{
		Endpoint: srv.URL,
		Headers:  map[string]string{"Authorization": "Bearer tok"},
		Host:     "host1",
		Version:  "test",
	})
	if err != nil {
		t.Fatal(err)
	}
	a := Alert{
		Time: time.Unix(0, 1_700_000_000_000_000_000),
		Kind: KindSigma, Rule: "reverse_shell", RuleID: "id-1", Title: "Reverse shell spawned",
		Level: "critical", Source: "mimi", Tags: []string{"attack.t1059.004"},
		Event: event.Event{Image: "/usr/bin/bash", CommandLine: "bash -c exec 3<>/dev/tcp/x", User: "0", PID: 42, PPID: 7},
	}
	if err := s.Emit(a); err != nil {
		t.Fatalf("Emit: %v", err)
	}
	// Delivery is asynchronous; Close flushes the queue so the collector has the
	// record (and reports no loss for this 200-returning server).
	if err := s.Close(); err != nil {
		t.Fatalf("Close: %v", err)
	}
	if gotCT != "application/json" {
		t.Errorf("Content-Type = %q, want application/json", gotCT)
	}
	if gotAuth != "Bearer tok" {
		t.Errorf("Authorization = %q, want the configured header", gotAuth)
	}

	var doc otlpLogs
	if err := json.Unmarshal(got, &doc); err != nil {
		t.Fatalf("posted body is not JSON: %v\n%s", err, got)
	}
	if len(doc.ResourceLogs) != 1 || len(doc.ResourceLogs[0].ScopeLogs) != 1 ||
		len(doc.ResourceLogs[0].ScopeLogs[0].LogRecords) != 1 {
		t.Fatalf("unexpected OTLP shape: %s", got)
	}
	lr := doc.ResourceLogs[0].ScopeLogs[0].LogRecords[0]
	if lr.SeverityNumber != 21 || lr.SeverityText != "critical" {
		t.Errorf("severity = %d/%q, want 21/critical", lr.SeverityNumber, lr.SeverityText)
	}
	if lr.TimeUnixNano != "1700000000000000000" {
		t.Errorf("timeUnixNano = %q", lr.TimeUnixNano)
	}
	if lr.Body.StringValue == nil || !strings.Contains(*lr.Body.StringValue, "Reverse shell") {
		t.Errorf("body = %v, want the summary line", lr.Body.StringValue)
	}
	// Scope + a resource service.name, and the key attributes present.
	if doc.ResourceLogs[0].ScopeLogs[0].Scope.Name != "banken" {
		t.Errorf("scope name = %q", doc.ResourceLogs[0].ScopeLogs[0].Scope.Name)
	}
	want := map[string]string{"banken.rule": "reverse_shell", "process.command_line": "bash -c exec 3<>/dev/tcp/x"}
	wantInt := map[string]string{"process.pid": "42"}
	for _, kv := range lr.Attributes {
		if w, ok := want[kv.Key]; ok {
			if kv.Value.StringValue == nil || *kv.Value.StringValue != w {
				t.Errorf("attr %s = %v, want %q", kv.Key, kv.Value.StringValue, w)
			}
			delete(want, kv.Key)
		}
		if w, ok := wantInt[kv.Key]; ok {
			if kv.Value.IntValue == nil || *kv.Value.IntValue != w {
				t.Errorf("attr %s intValue = %v, want %q (OTLP encodes int64 as string)", kv.Key, kv.Value.IntValue, w)
			}
			delete(wantInt, kv.Key)
		}
	}
	if len(want) != 0 || len(wantInt) != 0 {
		t.Errorf("missing attributes: %v %v", want, wantInt)
	}
}

func TestOTLPSinkSkipsObserved(t *testing.T) {
	posted := false
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		posted = true
		w.WriteHeader(http.StatusOK)
	}))
	defer srv.Close()
	s, err := NewOTLPSink(OTLPConfig{Endpoint: srv.URL})
	if err != nil {
		t.Fatal(err)
	}
	if err := s.Emit(Alert{Level: "high", Rule: "netcat", Observed: true}); err != nil {
		t.Fatalf("Emit: %v", err)
	}
	if err := s.Close(); err != nil {
		t.Fatalf("Close: %v", err)
	}
	if posted {
		t.Error("an observe-mode hit must not be exported (observe is recorded, never paged)")
	}
}
