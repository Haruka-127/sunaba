package webgateway

import (
	"context"
	"io"
	"net/http"
	"strings"
	"testing"
	"time"
)

func TestBlocklistFetchDigestExpiryAndStrictParsing(t *testing.T) {
	data := "# maintained hosts\n0.0.0.0 malware.example\n127.0.0.1 sub.bad.example # reason\n"
	client := &http.Client{Transport: roundTripFunc(func(request *http.Request) (*http.Response, error) {
		if request.UserAgent() != "sunaba-web-blocklist/1" || request.Header.Get("Accept") != "text/plain" {
			t.Errorf("unexpected fetch headers: %v", request.Header)
		}
		return &http.Response{StatusCode: http.StatusOK, Header: make(http.Header), Body: io.NopCloser(strings.NewReader(data)), Request: request}, nil
	})}
	now := time.Unix(1_800_000_000, 0)
	snapshot, err := FetchBlocklist(context.Background(), client, "https://blocklist.example/urlhaus.hosts", now, 24*time.Hour)
	if err != nil {
		t.Fatal(err)
	}
	if strings.Join(snapshot.Domains, ",") != "malware.example,sub.bad.example" || snapshot.Manifest.SHA256 == "" {
		t.Fatalf("unexpected snapshot: %+v", snapshot)
	}
	encoded, err := snapshot.Manifest.Marshal()
	if err != nil {
		t.Fatal(err)
	}
	manifest, err := ParseBlocklistManifest(encoded)
	if err != nil {
		t.Fatal(err)
	}
	if _, err := LoadBlocklist(manifest, snapshot.Data, now.Add(23*time.Hour)); err != nil {
		t.Fatal(err)
	}
	tampered := append([]byte(nil), snapshot.Data...)
	tampered[len(tampered)-2] ^= 1
	if _, err := LoadBlocklist(manifest, tampered, now); err == nil {
		t.Fatal("tampered blocklist was accepted")
	}
	if _, err := LoadBlocklist(manifest, snapshot.Data, now.Add(24*time.Hour)); err == nil {
		t.Fatal("expired blocklist was accepted")
	}
}

func TestBlocklistFailsClosedOnRedirectAndMalformedInput(t *testing.T) {
	redirectClient := &http.Client{Transport: roundTripFunc(func(request *http.Request) (*http.Response, error) {
		return &http.Response{StatusCode: http.StatusFound, Header: http.Header{"Location": []string{"https://other.example/list"}}, Body: io.NopCloser(strings.NewReader("")), Request: request}, nil
	})}
	if _, err := FetchBlocklist(context.Background(), redirectClient, "https://blocklist.example/list", time.Now(), time.Hour); err == nil {
		t.Fatal("blocklist redirect was accepted")
	}
	for _, invalid := range []string{
		"malware.example\n",
		"1.2.3.4 malware.example\n",
		"0.0.0.0 évil.example\n",
		"0.0.0.0 127.0.0.1\n",
	} {
		if _, err := parseHostsBlocklist([]byte(invalid)); err == nil {
			t.Fatalf("malformed blocklist was accepted: %q", invalid)
		}
	}
}

type roundTripFunc func(*http.Request) (*http.Response, error)

func (f roundTripFunc) RoundTrip(request *http.Request) (*http.Response, error) { return f(request) }

func TestBlocklistManifestRejectsUnknownFieldsAndMutableURLFeatures(t *testing.T) {
	if _, err := ParseBlocklistManifest([]byte(`{"schema_version":1,"unknown":true}`)); err == nil {
		t.Fatal("unknown manifest field was accepted")
	}
	for _, source := range []string{"http://example.com/list", "https://user@example.com/list", "https://example.com:8443/list", "https://example.com/list?q=x"} {
		if _, err := validateBlocklistSource(source); err == nil {
			t.Fatalf("unsafe source URL accepted: %s", source)
		}
	}
}
