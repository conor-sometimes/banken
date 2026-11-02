package intel

import (
	"context"
	"net/http"
	"net/http/httptest"
	"os"
	"strings"
	"testing"
)

// TestTAXIIPollAgainstStub exercises the real client against a local stub that
// serves two recorded TAXII 2.1 envelopes. It proves offline: the objects URL
// path, the TAXII 2.1 Accept media type, bearer auth, envelope decoding, and
// more/next pagination. A live third-party TAXII server is not reachable from
// the walled test host and is deliberately not contacted.
func TestTAXIIPollAgainstStub(t *testing.T) {
	page1 := mustRead(t, "testdata/taxii_objects_page1.json")
	page2 := mustRead(t, "testdata/taxii_objects_page2.json")

	const collection = "91a7b528-80eb-42ed-a74d-c6fbd5a26116"
	wantPath := "/taxii2/api1/collections/" + collection + "/objects/"

	var sawAccept, sawAuth string
	var pathHits []string
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		sawAccept = r.Header.Get("Accept")
		sawAuth = r.Header.Get("Authorization")
		pathHits = append(pathHits, r.URL.Path)
		if r.URL.Path != wantPath {
			http.Error(w, "wrong path", http.StatusNotFound)
			return
		}
		w.Header().Set("Content-Type", taxiiMediaType)
		// First request has no "next"; the follow-up carries the page-1 token.
		if r.URL.Query().Get("next") == "" {
			_, _ = w.Write(page1)
			return
		}
		_, _ = w.Write(page2)
	}))
	defer srv.Close()

	c := &TAXIIClient{
		BaseURL: srv.URL + "/taxii2/api1/",
		Source:  "taxii-sample",
		Token:   "s3cr3t-token",
	}
	inds, err := c.PollCollection(context.Background(), collection)
	if err != nil {
		t.Fatalf("PollCollection: %v", err)
	}

	if !strings.HasPrefix(sawAccept, "application/taxii+json") || !strings.Contains(sawAccept, "version=2.1") {
		t.Errorf("Accept header = %q, want TAXII 2.1 media type", sawAccept)
	}
	if sawAuth != "Bearer s3cr3t-token" {
		t.Errorf("Authorization = %q, want bearer token", sawAuth)
	}
	if len(pathHits) != 2 {
		t.Errorf("made %d requests %v, want 2 (pagination)", len(pathHits), pathHits)
	}

	want := map[string]Type{
		"198.51.100.123":    TypeIPv4,
		"poll.evil.example": TypeDomain,
		"b5a2c96250612366ea272ffac6d9744aaf4b45aacd96aa7cfcb931ee3b558259": TypeHash,
	}
	assertIndicators(t, indexByValue(inds), want)
}

func TestTAXIIBasicAuthAndURL(t *testing.T) {
	var sawAuth, sawPath string
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		sawAuth = r.Header.Get("Authorization")
		sawPath = r.URL.Path
		w.Header().Set("Content-Type", taxiiMediaType)
		_, _ = w.Write([]byte(`{"more":false,"objects":[]}`))
	}))
	defer srv.Close()

	// A trailing slash on BaseURL must not double up in the objects URL.
	c := &TAXIIClient{BaseURL: srv.URL + "/root/", Username: "u", Password: "p"}
	if _, err := c.PollCollection(context.Background(), "col1"); err != nil {
		t.Fatalf("PollCollection: %v", err)
	}
	if sawPath != "/root/collections/col1/objects/" {
		t.Errorf("objects path = %q", sawPath)
	}
	if !strings.HasPrefix(sawAuth, "Basic ") {
		t.Errorf("Authorization = %q, want basic auth", sawAuth)
	}
}

func TestTAXIIHTTPError(t *testing.T) {
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		http.Error(w, "forbidden", http.StatusForbidden)
	}))
	defer srv.Close()
	c := &TAXIIClient{BaseURL: srv.URL}
	if _, err := c.PollCollection(context.Background(), "c"); err == nil {
		t.Fatal("expected an error on HTTP 403")
	}
}

func mustRead(t *testing.T, path string) []byte {
	t.Helper()
	b, err := os.ReadFile(path)
	if err != nil {
		t.Fatal(err)
	}
	return b
}
