package alert

import (
	"bytes"
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"net/http"
	"strconv"
	"strings"
	"time"
)

// OTLPSink exports each alert as an OpenTelemetry log record over OTLP/HTTP (JSON), POSTed to a
// collector's logs endpoint (e.g. http://collector:4318/v1/logs). OCSF is banken's schema; OTLP is
// the pipe, so any OTel-aware backend (Grafana, Datadog, Splunk, Elastic) ingests banken's findings
// with no glue. It is hand-rolled JSON with no OpenTelemetry SDK, to keep banken's dependency
// surface at zero -- the OTLP/HTTP logs body is a small, stable shape.
//
// The POST runs on a background sender (see asyncSender), not inline in Emit, so
// a slow or hung collector can never stall the detection path; past the bounded
// queue it drops visibly with a count. Close flushes and reports any loss.
type OTLPSink struct {
	endpoint string
	headers  map[string]string
	host     string
	version  string
	client   *http.Client
	async    *asyncSender
}

// OTLPConfig configures an OTLPSink.
type OTLPConfig struct {
	// Endpoint is the full logs URL, e.g. http://host:4318/v1/logs (required). It is not a secret
	// (it is a collector address), so unlike the webhook URL it is passed directly.
	Endpoint string
	// Headers are optional request headers, e.g. {"Authorization": "Bearer ..."} for a hosted
	// collector. A secret belongs in a systemd credential the operator reads into this, not the Nix
	// store.
	Headers map[string]string
	// Host and Version populate the resource/scope (host.name, service.version).
	Host    string
	Version string
	// Client is the HTTP client (defaults to a 10s-timeout client).
	Client *http.Client
}

// NewOTLPSink returns a ready OTLP sink.
func NewOTLPSink(cfg OTLPConfig) (*OTLPSink, error) {
	ep := strings.TrimSpace(cfg.Endpoint)
	if ep == "" {
		return nil, errors.New("otlp: no endpoint configured")
	}
	client := cfg.Client
	if client == nil {
		client = &http.Client{Timeout: 10 * time.Second}
	}
	s := &OTLPSink{endpoint: ep, headers: cfg.Headers, host: cfg.Host, version: cfg.Version, client: client}
	s.async = newAsyncSender("otlp", asyncQueueDepth, s.post)
	return s, nil
}

// Name implements Sink.
func (*OTLPSink) Name() string { return "otlp" }

// Close implements Sink: flushes the queued records (bounded by
// asyncFlushTimeout) and reports any that were dropped or failed to send.
func (s *OTLPSink) Close() error { return s.async.close() }

// Emit implements Sink: it hands the alert to the background sender and returns
// at once, so a slow collector never delays dispatch. An observe-mode hit is
// skipped (OTLP is a notify/export path). A full queue returns a drop error; the
// POST and its outcome happen on the sender, surfaced by Close.
func (s *OTLPSink) Emit(a Alert) error {
	if a.Observed {
		return nil
	}
	return s.async.enqueue(a)
}

// post encodes one alert as an OTLP log record and POSTs it, treating any
// non-2xx as an error. It runs on the background sender, never inline in Emit.
func (s *OTLPSink) post(a Alert) error {
	body, err := s.encode(a)
	if err != nil {
		return err
	}
	ctx, cancel := context.WithTimeout(context.Background(), 15*time.Second)
	defer cancel()
	req, err := http.NewRequestWithContext(ctx, http.MethodPost, s.endpoint, bytes.NewReader(body))
	if err != nil {
		return fmt.Errorf("otlp: build request: %w", err)
	}
	req.Header.Set("Content-Type", "application/json")
	for k, v := range s.headers {
		req.Header.Set(k, v)
	}
	resp, err := s.client.Do(req)
	if err != nil {
		return fmt.Errorf("otlp: POST: %w", err)
	}
	defer func() { _ = resp.Body.Close() }()
	if resp.StatusCode < 200 || resp.StatusCode >= 300 {
		return fmt.Errorf("otlp: POST returned %s", resp.Status)
	}
	return nil
}

// --- OTLP/HTTP logs JSON (ExportLogsServiceRequest), the subset banken emits. int64 fields are
// encoded as strings, per the protobuf-JSON mapping OTLP uses. ---

type otlpLogs struct {
	ResourceLogs []otlpResourceLogs `json:"resourceLogs"`
}

type otlpResourceLogs struct {
	Resource  otlpResource    `json:"resource"`
	ScopeLogs []otlpScopeLogs `json:"scopeLogs"`
}

type otlpResource struct {
	Attributes []otlpKV `json:"attributes,omitempty"`
}

type otlpScopeLogs struct {
	Scope      otlpScope       `json:"scope"`
	LogRecords []otlpLogRecord `json:"logRecords"`
}

type otlpScope struct {
	Name    string `json:"name"`
	Version string `json:"version,omitempty"`
}

type otlpLogRecord struct {
	TimeUnixNano         string       `json:"timeUnixNano"`
	ObservedTimeUnixNano string       `json:"observedTimeUnixNano"`
	SeverityNumber       int          `json:"severityNumber"`
	SeverityText         string       `json:"severityText"`
	Body                 otlpAnyValue `json:"body"`
	Attributes           []otlpKV     `json:"attributes,omitempty"`
}

type otlpKV struct {
	Key   string       `json:"key"`
	Value otlpAnyValue `json:"value"`
}

type otlpAnyValue struct {
	StringValue *string `json:"stringValue,omitempty"`
	IntValue    *string `json:"intValue,omitempty"`
}

func otlpStr(k, v string) otlpKV { return otlpKV{Key: k, Value: otlpAnyValue{StringValue: &v}} }
func otlpInt(k string, v int) otlpKV {
	s := strconv.Itoa(v)
	return otlpKV{Key: k, Value: otlpAnyValue{IntValue: &s}}
}

// otlpSeverity maps a banken level to an OTLP SeverityNumber (and keeps the level as the text): the
// finding severities sit in OTLP's WARN..FATAL bands, so a backend's severity filters line up.
func otlpSeverity(level string) (int, string) {
	switch strings.ToLower(level) {
	case "critical":
		return 21, level // FATAL
	case "high":
		return 18, level // ERROR2
	case "medium":
		return 17, level // ERROR
	case "low":
		return 13, level // WARN
	case "informational", "info":
		return 9, level // INFO
	default:
		return 17, level
	}
}

// encode builds the OTLP/HTTP logs JSON for one alert: one LogRecord in one resource/scope batch.
func (s *OTLPSink) encode(a Alert) ([]byte, error) {
	ns := strconv.FormatInt(a.Time.UnixNano(), 10)
	sevN, sevT := otlpSeverity(a.Level)

	attrs := []otlpKV{otlpStr("banken.rule", a.Rule)}
	if a.RuleID != "" {
		attrs = append(attrs, otlpStr("banken.rule.id", a.RuleID))
	}
	if a.Source != "" {
		attrs = append(attrs, otlpStr("banken.source", a.Source))
	}
	if len(a.Tags) > 0 {
		attrs = append(attrs, otlpStr("banken.attack", strings.Join(a.Tags, ",")))
	}
	if a.IOC != "" {
		attrs = append(attrs, otlpStr("banken.ioc", a.IOC))
	}
	if a.Event.Image != "" {
		attrs = append(attrs, otlpStr("process.executable.path", a.Event.Image))
	}
	if a.Event.CommandLine != "" {
		attrs = append(attrs, otlpStr("process.command_line", a.Event.CommandLine))
	}
	if a.Event.User != "" {
		attrs = append(attrs, otlpStr("user.id", a.Event.User))
	}
	if a.Event.PID != 0 {
		attrs = append(attrs, otlpInt("process.pid", a.Event.PID))
	}
	if a.Event.PPID != 0 {
		attrs = append(attrs, otlpInt("process.parent_pid", a.Event.PPID))
	}

	res := []otlpKV{otlpStr("service.name", "banken")}
	if s.version != "" {
		res = append(res, otlpStr("service.version", s.version))
	}
	if s.host != "" {
		res = append(res, otlpStr("host.name", s.host))
	}

	body := summaryLine(a)
	doc := otlpLogs{ResourceLogs: []otlpResourceLogs{{
		Resource: otlpResource{Attributes: res},
		ScopeLogs: []otlpScopeLogs{{
			Scope: otlpScope{Name: "banken", Version: s.version},
			LogRecords: []otlpLogRecord{{
				TimeUnixNano:         ns,
				ObservedTimeUnixNano: ns,
				SeverityNumber:       sevN,
				SeverityText:         sevT,
				Body:                 otlpAnyValue{StringValue: &body},
				Attributes:           attrs,
			}},
		}},
	}}}
	return json.Marshal(doc)
}
