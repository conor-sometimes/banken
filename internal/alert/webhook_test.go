package alert

import (
	"encoding/json"
	"io"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
)

// capture spins a one-request server and returns what the sink POSTed to it.
func capture(t *testing.T, style WebhookStyle, a Alert) (body []byte, contentType string, posted bool) {
	t.Helper()
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		body, _ = io.ReadAll(r.Body)
		contentType = r.Header.Get("Content-Type")
		posted = true
		w.WriteHeader(http.StatusOK)
	}))
	defer srv.Close()
	s, err := NewWebhookSink(WebhookConfig{URL: srv.URL, Style: style})
	if err != nil {
		t.Fatalf("NewWebhookSink: %v", err)
	}
	if err := s.Emit(a); err != nil {
		t.Fatalf("Emit: %v", err)
	}
	return body, contentType, posted
}

func TestWebhookDeliversPerStyle(t *testing.T) {
	a := sampleAlert("critical")

	t.Run("generic", func(t *testing.T) {
		body, ct, posted := capture(t, StyleGeneric, a)
		if !posted || ct != "application/json" {
			t.Fatalf("posted=%v content-type=%q", posted, ct)
		}
		var got Alert
		if err := json.Unmarshal(body, &got); err != nil {
			t.Fatalf("generic body is not Alert JSON: %v\n%s", err, body)
		}
		if got.Rule != "reverse_shell" || got.Event.CommandLine != a.Event.CommandLine {
			t.Errorf("generic body lost fields: %+v", got)
		}
	})

	t.Run("slack", func(t *testing.T) {
		body, _, _ := capture(t, StyleSlack, a)
		var m map[string]string
		if err := json.Unmarshal(body, &m); err != nil || m["text"] == "" {
			t.Fatalf("slack body not {text:...}: %v\n%s", err, body)
		}
		if !strings.Contains(m["text"], "Reverse shell") {
			t.Errorf("slack text missing the title: %q", m["text"])
		}
	})

	t.Run("ocsf", func(t *testing.T) {
		body, ct, _ := capture(t, StyleOCSF, a)
		if ct != "application/json" {
			t.Errorf("ocsf content-type %q", ct)
		}
		var f OCSFFinding
		if err := json.Unmarshal(body, &f); err != nil {
			t.Fatalf("ocsf body not an OCSF finding: %v\n%s", err, body)
		}
		if f.ClassUID != 2004 || f.FindingInfo.Analytic.Name != "reverse_shell" {
			t.Errorf("ocsf finding wrong: class=%d rule=%q", f.ClassUID, f.FindingInfo.Analytic.Name)
		}
	})
}

// TestWebhookSkipsObserved: an observe-mode hit is recorded, never paged, so the webhook (a notify
// path) must not fire for it.
func TestWebhookSkipsObserved(t *testing.T) {
	a := sampleAlert("critical")
	a.Observed = true
	_, _, posted := capture(t, StyleGeneric, a)
	if posted {
		t.Error("observe-mode hit was POSTed; it must be skipped")
	}
}

// TestWebhookNon2xxIsError: a receiver returning non-2xx must surface as an error, not be swallowed.
func TestWebhookNon2xxIsError(t *testing.T) {
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		w.WriteHeader(http.StatusInternalServerError)
	}))
	defer srv.Close()
	s, err := NewWebhookSink(WebhookConfig{URL: srv.URL})
	if err != nil {
		t.Fatal(err)
	}
	if err := s.Emit(sampleAlert("critical")); err == nil {
		t.Error("a 500 from the receiver must be an error")
	}
}
