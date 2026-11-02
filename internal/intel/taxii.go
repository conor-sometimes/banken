package intel

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"net/http"
	"net/url"
	"strings"
	"time"
)

// TAXII 2.1 client. TAXII is the transport; STIX is the payload. banken polls a
// collection's objects endpoint and feeds the returned STIX objects through the
// same extractor the offline bundle parser uses, so a polled feed and a file
// feed normalise identically.
//
// What is proven offline (taxii_test.go, against an httptest server serving a
// recorded TAXII 2.1 envelope): the request path, the TAXII 2.1 Accept media
// type, bearer/basic auth, envelope decoding, and "more"/"next" pagination.
// What needs a live server: reaching a real third-party TAXII endpoint. banken
// does not fake that -- the walled test host has no egress to a TAXII server,
// so the client is exercised against a local stub and the live path is left to
// an operator with a reachable server.

// taxiiMediaType is the TAXII 2.1 media type, sent in Accept and matched on the
// response Content-Type. The 2.1 spec drops the "charset" the 2.0 type carried.
const taxiiMediaType = "application/taxii+json;version=2.1"

// defaultTAXIIPageLimit caps how many pages a single poll follows, so a server
// that always reports more=true cannot spin banken forever.
const defaultTAXIIPageLimit = 100

// TAXIIClient polls one TAXII 2.1 server. BaseURL is the API root (the URL that
// has a collections/ child), e.g. https://example.test/taxii2/api1/. Auth is
// optional: a bearer Token wins over Username/Password basic auth. HTTPClient
// defaults to a client with a sane timeout; Source labels every indicator.
type TAXIIClient struct {
	BaseURL    string
	Source     string
	Token      string
	Username   string
	Password   string
	HTTPClient *http.Client
	// PageLimit caps followed pages (0 -> defaultTAXIIPageLimit).
	PageLimit int
}

// taxiiEnvelope is a TAXII 2.1 response envelope: a page of STIX objects plus
// the pagination signal. "next" is echoed back as a query parameter to fetch
// the following page.
type taxiiEnvelope struct {
	More    bool         `json:"more"`
	Next    string       `json:"next"`
	Objects []stixObject `json:"objects"`
}

// PollCollection fetches every object in the given collection (following
// pagination) and returns the normalised indicators. Context cancellation and
// HTTP/decoding errors are returned; the caller logs a failed poll and carries
// on with whatever other feeds loaded (never-die).
func (c *TAXIIClient) PollCollection(ctx context.Context, collectionID string) ([]Indicator, error) {
	if strings.TrimSpace(c.BaseURL) == "" {
		return nil, errors.New("taxii: empty BaseURL")
	}
	if strings.TrimSpace(collectionID) == "" {
		return nil, errors.New("taxii: empty collection id")
	}
	endpoint, err := c.objectsURL(collectionID)
	if err != nil {
		return nil, err
	}
	client := c.HTTPClient
	if client == nil {
		client = &http.Client{Timeout: 30 * time.Second}
	}
	limit := c.PageLimit
	if limit <= 0 {
		limit = defaultTAXIIPageLimit
	}

	var out []Indicator
	next := ""
	for page := 0; page < limit; page++ {
		env, err := c.fetchPage(ctx, client, endpoint, next)
		if err != nil {
			return nil, err
		}
		out = append(out, indicatorsFromSTIX(env.Objects, c.source())...)
		if !env.More || env.Next == "" {
			break
		}
		next = env.Next
	}
	return dedup(out), nil
}

func (c *TAXIIClient) fetchPage(ctx context.Context, client *http.Client, endpoint, next string) (taxiiEnvelope, error) {
	reqURL := endpoint
	if next != "" {
		u, err := url.Parse(endpoint)
		if err != nil {
			return taxiiEnvelope{}, fmt.Errorf("taxii: parse url: %w", err)
		}
		q := u.Query()
		q.Set("next", next)
		u.RawQuery = q.Encode()
		reqURL = u.String()
	}
	req, err := http.NewRequestWithContext(ctx, http.MethodGet, reqURL, nil)
	if err != nil {
		return taxiiEnvelope{}, fmt.Errorf("taxii: new request: %w", err)
	}
	req.Header.Set("Accept", taxiiMediaType)
	switch {
	case c.Token != "":
		req.Header.Set("Authorization", "Bearer "+c.Token)
	case c.Username != "" || c.Password != "":
		req.SetBasicAuth(c.Username, c.Password)
	}

	resp, err := client.Do(req)
	if err != nil {
		return taxiiEnvelope{}, fmt.Errorf("taxii: get %s: %w", reqURL, err)
	}
	defer func() { _ = resp.Body.Close() }()
	if resp.StatusCode != http.StatusOK {
		body, _ := io.ReadAll(io.LimitReader(resp.Body, 512))
		return taxiiEnvelope{}, fmt.Errorf("taxii: %s returned %d: %s", reqURL, resp.StatusCode, strings.TrimSpace(string(body)))
	}
	var env taxiiEnvelope
	if err := json.NewDecoder(resp.Body).Decode(&env); err != nil {
		return taxiiEnvelope{}, fmt.Errorf("taxii: decode envelope: %w", err)
	}
	return env, nil
}

// objectsURL builds {BaseURL}/collections/{id}/objects/ with the single slash
// TAXII mandates, regardless of whether BaseURL has a trailing slash.
func (c *TAXIIClient) objectsURL(collectionID string) (string, error) {
	base := strings.TrimRight(c.BaseURL, "/")
	full := base + "/collections/" + url.PathEscape(collectionID) + "/objects/"
	if _, err := url.Parse(full); err != nil {
		return "", fmt.Errorf("taxii: bad url %q: %w", full, err)
	}
	return full, nil
}

func (c *TAXIIClient) source() string {
	if s := strings.TrimSpace(c.Source); s != "" {
		return s
	}
	return "taxii"
}
