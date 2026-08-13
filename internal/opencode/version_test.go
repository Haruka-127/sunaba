package opencode

import (
	"context"
	"net/http"
	"net/http/httptest"
	"sync/atomic"
	"testing"
	"time"

	"sunaba/internal/dependency"
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
		{version: dependency.OpenCodeVersion},
		{version: "v" + dependency.OpenCodeVersion},
		{version: "1.18.16", wantErr: true},
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

func TestWaitHealthRetriesWithoutMultiSecondPollingDelay(t *testing.T) {
	var requests atomic.Int32
	server := httptest.NewServer(http.HandlerFunc(func(response http.ResponseWriter, _ *http.Request) {
		if requests.Add(1) == 1 {
			http.Error(response, "starting", http.StatusServiceUnavailable)
			return
		}
		_, _ = response.Write([]byte(`{"version":"1.18.16"}`))
	}))
	defer server.Close()

	started := time.Now()
	health, err := WaitHealth(context.Background(), server.URL, "secret", time.Second)
	if err != nil {
		t.Fatal(err)
	}
	if health.Version != "1.18.16" || requests.Load() < 2 {
		t.Fatalf("health=%+v requests=%d", health, requests.Load())
	}
	if elapsed := time.Since(started); elapsed >= 500*time.Millisecond {
		t.Fatalf("health retry took %s; local readiness polling regressed", elapsed)
	}
}

func TestWaitHealthBoundsAStalledStartupProbe(t *testing.T) {
	var requests atomic.Int32
	server := httptest.NewServer(http.HandlerFunc(func(response http.ResponseWriter, request *http.Request) {
		if requests.Add(1) == 1 {
			<-request.Context().Done()
			return
		}
		_, _ = response.Write([]byte(`{"version":"1.18.16"}`))
	}))
	defer server.Close()

	started := time.Now()
	health, err := WaitHealth(context.Background(), server.URL, "secret", 2*time.Second)
	if err != nil {
		t.Fatal(err)
	}
	if health.Version != "1.18.16" || requests.Load() < 2 {
		t.Fatalf("health=%+v requests=%d", health, requests.Load())
	}
	if elapsed := time.Since(started); elapsed >= time.Second {
		t.Fatalf("stalled readiness probe consumed %s", elapsed)
	}
}
