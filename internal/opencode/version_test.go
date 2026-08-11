package opencode

import (
	"context"
	"net/http"
	"net/http/httptest"
	"testing"
)

func TestCompareVersion(t *testing.T) {
	cases := []struct {
		a, b string
		want int
	}{
		{"1.18.16", "1.18.16", 0},
		{"v1.18.17", "1.18.16", 1},
		{"1.19.0", "1.18.99", 1},
		{"1.18.15", "1.18.16", -1},
	}
	for _, tc := range cases {
		if got := CompareVersion(tc.a, tc.b); got != tc.want {
			t.Fatalf("CompareVersion(%q,%q)=%d", tc.a, tc.b, got)
		}
	}
}

func TestFirstSemanticVersion(t *testing.T) {
	for input, want := range map[string]string{
		"container CLI version 1.2.2 (build: release)": "1.2.2",
		"v2.3":    "2.3",
		"unknown": "",
	} {
		if got := firstSemanticVersion(input); got != want {
			t.Fatalf("firstSemanticVersion(%q)=%q, want %q", input, got, want)
		}
	}
}

func TestValidateAppleContainerVersion(t *testing.T) {
	for _, tc := range []struct {
		name    string
		output  string
		wantErr bool
	}{
		{name: "minimum", output: "container CLI version 1.2.2 (build: release)"},
		{name: "newer", output: "container CLI version 1.3.0 (build: release)", wantErr: true},
		{name: "too old", output: "container CLI version 1.2.1 (build: release)", wantErr: true},
		{name: "invalid", output: "container CLI version unknown", wantErr: true},
	} {
		t.Run(tc.name, func(t *testing.T) {
			err := validateAppleContainerVersion(tc.output)
			if (err != nil) != tc.wantErr {
				t.Fatalf("validateAppleContainerVersion(%q) error = %v, wantErr %v", tc.output, err, tc.wantErr)
			}
		})
	}
}

func TestValidateOpenCodeVersion(t *testing.T) {
	for _, tc := range []struct {
		version string
		wantErr bool
	}{
		{version: "1.18.16"},
		{version: "v1.18.16"},
		{version: "1.18.15", wantErr: true},
		{version: "2.0.0", wantErr: true},
	} {
		if err := validateOpenCodeVersion(tc.version); (err != nil) != tc.wantErr {
			t.Fatalf("validateOpenCodeVersion(%q) error=%v, wantErr=%t", tc.version, err, tc.wantErr)
		}
	}
}

func TestDirectHTTPClientBypassesProxy(t *testing.T) {
	t.Setenv("HTTP_PROXY", "http://127.0.0.1:1")
	t.Setenv("NO_PROXY", "")
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		_, _ = w.Write([]byte(`{"version":"1.2.3"}`))
	}))
	defer server.Close()
	transport, ok := DirectHTTPClient(0).Transport.(*http.Transport)
	if !ok || transport.Proxy != nil {
		t.Fatalf("direct client has a proxy function: %#v", transport)
	}

	if _, err := GetHealth(context.Background(), server.URL, "secret"); err != nil {
		t.Fatalf("direct health request used host proxy: %v", err)
	}
}

func TestAttachEnvironmentAddsServerToNoProxy(t *testing.T) {
	env := attachEnvironment([]string{
		"NO_PROXY=localhost",
		"no_proxy=old",
		"HTTP_PROXY=http://proxy.example",
		"OPENCODE_SERVER_PASSWORD=old",
	}, "http://192.168.64.2:4096", "new-secret")
	if got := environmentValue(env, "NO_PROXY"); got != "localhost,old,192.168.64.2" {
		t.Fatalf("NO_PROXY=%q", got)
	}
	if got := environmentValue(env, "no_proxy"); got != "localhost,old,192.168.64.2" {
		t.Fatalf("no_proxy=%q", got)
	}
	if got := environmentValue(env, "OPENCODE_SERVER_PASSWORD"); got != "new-secret" {
		t.Fatalf("password=%q", got)
	}
	if got := environmentValue(env, "HTTP_PROXY"); got != "" {
		t.Fatalf("HTTP_PROXY was retained: %q", got)
	}
}
