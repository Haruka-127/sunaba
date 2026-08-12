package attachrelay

import (
	"bytes"
	"compress/gzip"
	"compress/zlib"
	"context"
	"io"
	"net"
	"net/http"
	"os"
	"path/filepath"
	"strconv"
	"strings"
	"sync/atomic"
	"testing"
	"time"
)

const relayTestPassword = "relay-password-0123456789abcdef0123456789"

func TestRelayAuthenticatesFiltersAndSanitizes(t *testing.T) {
	root, err := os.MkdirTemp("/private/tmp", "sunaba-attach-test-")
	if err != nil {
		t.Fatal(err)
	}
	defer os.RemoveAll(root)
	unixListener, err := net.Listen("unix", filepath.Join(root, "attach.sock"))
	if err != nil {
		t.Fatal(err)
	}
	var forbiddenReached atomic.Bool
	var identityRequested atomic.Bool
	guestServer := &http.Server{Handler: http.HandlerFunc(func(response http.ResponseWriter, request *http.Request) {
		switch request.URL.Path {
		case "/global/health":
			identityRequested.Store(request.Header.Get("Accept-Encoding") == "identity")
			response.Header().Set("Content-Type", "application/json")
			_, _ = io.WriteString(response, `{"healthy":true,"version":"1.18.16","message":"evil\u001b]52;c;Y2xpcA==\u0007"}`)
		case "/global/event":
			response.Header().Set("Content-Type", "text/event-stream")
			flusher := response.(http.Flusher)
			_, _ = io.WriteString(response, "data: {\"payload\":{\"type\":\"tui.command.execute\",\"properties\":{\"command\":\"editor.open\"}}}\n\n")
			_, _ = io.WriteString(response, "data: {\"payload\":{\"type\":\"tui.toast.show\",\"properties\":{\"message\":\"bad\\u001b[31m\",\"variant\":\"error\"}}}\n\n")
			flusher.Flush()
		case "/tui/execute-command":
			forbiddenReached.Store(true)
			response.WriteHeader(http.StatusOK)
		default:
			http.NotFound(response, request)
		}
	})}
	go func() { _ = guestServer.Serve(unixListener) }()
	defer guestServer.Close()

	ctx, cancel := context.WithCancel(context.Background())
	endpoint, done, err := (Relay{
		UnixSocketPath: unixListener.Addr().String(), Username: "opencode", Password: relayTestPassword,
	}).ListenAndServe(ctx)
	if err != nil {
		t.Fatal(err)
	}
	unauthorized, err := http.Get(endpoint + "/global/health")
	if err != nil {
		t.Fatal(err)
	}
	_ = unauthorized.Body.Close()
	if unauthorized.StatusCode != http.StatusUnauthorized {
		t.Fatalf("unauthorized status=%d", unauthorized.StatusCode)
	}
	healthRequest, _ := http.NewRequest(http.MethodGet, endpoint+"/global/health", nil)
	healthRequest.SetBasicAuth("opencode", relayTestPassword)
	health, err := http.DefaultClient.Do(healthRequest)
	if err != nil {
		t.Fatal(err)
	}
	healthBody, _ := io.ReadAll(health.Body)
	_ = health.Body.Close()
	if strings.ContainsRune(string(healthBody), '\x1b') || !strings.Contains(string(healthBody), "<U+001B>") || !strings.Contains(string(healthBody), "<U+0007>") {
		t.Fatalf("health response was not sanitized: %q", healthBody)
	}
	if !identityRequested.Load() {
		t.Fatal("attach relay did not request an identity response from the guest")
	}
	forbiddenRequest, _ := http.NewRequest(http.MethodPost, endpoint+"/tui/execute-command", strings.NewReader(`{"command":"editor.open"}`))
	forbiddenRequest.SetBasicAuth("opencode", relayTestPassword)
	forbiddenResponse, err := http.DefaultClient.Do(forbiddenRequest)
	if err != nil {
		t.Fatal(err)
	}
	_ = forbiddenResponse.Body.Close()
	if forbiddenResponse.StatusCode != http.StatusNotFound || forbiddenReached.Load() {
		t.Fatalf("unsafe TUI endpoint status=%d reached=%t", forbiddenResponse.StatusCode, forbiddenReached.Load())
	}
	eventRequest, _ := http.NewRequest(http.MethodGet, endpoint+"/global/event", nil)
	eventRequest.SetBasicAuth("opencode", relayTestPassword)
	events, err := http.DefaultClient.Do(eventRequest)
	if err != nil {
		t.Fatal(err)
	}
	eventBody, _ := io.ReadAll(events.Body)
	_ = events.Body.Close()
	if strings.Contains(string(eventBody), "editor.open") || strings.ContainsRune(string(eventBody), '\x1b') || !strings.Contains(string(eventBody), "<U+001B>") {
		t.Fatalf("event stream was not filtered: %q", eventBody)
	}
	cancel()
	select {
	case err := <-done:
		if err != nil {
			t.Fatal(err)
		}
	case <-time.After(5 * time.Second):
		t.Fatal("relay did not stop after cancellation")
	}
}

func TestSanitizeTerminalTextEscapesBidiAndInvalidUTF8(t *testing.T) {
	input := "ok\u202e" + string([]byte{0xff})
	output := sanitizeTerminalText(input)
	if output != "ok<U+202E><INVALID-UTF8>" {
		t.Fatalf("output=%q", output)
	}
}

func TestSanitizeJSONEscapesDiffAndFilenameControls(t *testing.T) {
	encoded := []byte(`{"file":"evil\u001b]52;c;Y2xpcA==\u0007\u202e.txt","before":"old\u001b[31m","after":"new"}`)
	sanitized, keep, err := sanitizeJSON(encoded)
	if err != nil || !keep {
		t.Fatalf("keep=%t error=%v", keep, err)
	}
	text := string(sanitized)
	for _, expected := range []string{"<U+001B>", "<U+0007>", "<U+202E>"} {
		if !strings.Contains(text, expected) {
			t.Fatalf("sanitized diff=%q missing %q", text, expected)
		}
	}
	if strings.ContainsRune(text, '\x1b') {
		t.Fatalf("sanitized diff retained ESC: %q", text)
	}
}

func TestSanitizeResponseDecodesCompressedJSON(t *testing.T) {
	for _, encoding := range []string{"gzip", "deflate"} {
		t.Run(encoding, func(t *testing.T) {
			var encoded bytes.Buffer
			var compressor io.WriteCloser
			if encoding == "gzip" {
				compressor = gzip.NewWriter(&encoded)
			} else {
				compressor = zlib.NewWriter(&encoded)
			}
			if _, err := io.WriteString(compressor, `{"message":"evil\u001b[31m"}`); err != nil {
				t.Fatal(err)
			}
			if err := compressor.Close(); err != nil {
				t.Fatal(err)
			}
			response := &http.Response{
				Header: http.Header{
					"Content-Type":     []string{"application/json"},
					"Content-Encoding": []string{encoding},
					"Content-Length":   []string{"999"},
				},
				Body:          io.NopCloser(bytes.NewReader(encoded.Bytes())),
				ContentLength: int64(encoded.Len()),
			}
			if err := sanitizeResponse(response, nil); err != nil {
				t.Fatal(err)
			}
			body, err := io.ReadAll(response.Body)
			if err != nil {
				t.Fatal(err)
			}
			if got := string(body); !strings.Contains(got, "<U+001B>") || strings.ContainsRune(got, '\x1b') {
				t.Fatalf("compressed JSON was not sanitized: %q", got)
			}
			if got := response.Header.Get("Content-Encoding"); got != "" {
				t.Fatalf("content encoding=%q, want identity", got)
			}
			if response.ContentLength != int64(len(body)) || response.Header.Get("Content-Length") != strconv.Itoa(len(body)) {
				t.Fatalf("content length field=%d header=%q body=%d", response.ContentLength, response.Header.Get("Content-Length"), len(body))
			}
		})
	}
}
