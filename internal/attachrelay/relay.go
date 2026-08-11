package attachrelay

import (
	"bufio"
	"bytes"
	"context"
	"crypto/sha256"
	"crypto/subtle"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"net"
	"net/http"
	"net/http/httputil"
	"net/url"
	"os"
	"strconv"
	"strings"
	"time"
	"unicode/utf8"
)

const maximumJSONResponse = 16 << 20

type Relay struct {
	UnixSocketPath string
	Username       string
	Password       string
	MaxConnections int
	DialTimeout    time.Duration
	OnConnect      func()
	OnReject       func(string)
	OnRequest      func(string, string)
}

func (r Relay) ListenAndServe(ctx context.Context) (string, <-chan error, error) {
	if r.UnixSocketPath == "" || r.Username != "opencode" || len(r.Password) < 32 {
		return "", nil, fmt.Errorf("attach relay requires the session Unix socket and Basic authentication")
	}
	info, err := os.Lstat(r.UnixSocketPath)
	if err != nil {
		return "", nil, fmt.Errorf("inspect attach Unix socket: %w", err)
	}
	if info.Mode()&os.ModeSocket == 0 {
		return "", nil, fmt.Errorf("attach endpoint is not a Unix socket")
	}
	listener, err := net.Listen("tcp4", "127.0.0.1:0")
	if err != nil {
		return "", nil, err
	}
	maximum := r.MaxConnections
	if maximum <= 0 {
		maximum = 16
	}
	timeout := r.DialTimeout
	if timeout <= 0 {
		timeout = 3 * time.Second
	}
	transport := &http.Transport{
		Proxy: nil, DisableCompression: true, MaxConnsPerHost: maximum,
		DialContext: func(ctx context.Context, _, _ string) (net.Conn, error) {
			connection, err := (&net.Dialer{Timeout: timeout}).DialContext(ctx, "unix", r.UnixSocketPath)
			if err == nil && r.OnConnect != nil {
				r.OnConnect()
			}
			return connection, err
		},
	}
	target := &url.URL{Scheme: "http", Host: "sunaba-guest"}
	proxy := httputil.NewSingleHostReverseProxy(target)
	proxy.Transport = transport
	proxy.ModifyResponse = func(response *http.Response) error { return sanitizeResponse(response, r.OnReject) }
	proxy.ErrorHandler = func(response http.ResponseWriter, _ *http.Request, _ error) {
		http.Error(response, http.StatusText(http.StatusBadGateway), http.StatusBadGateway)
	}
	semaphore := make(chan struct{}, maximum)
	handler := http.HandlerFunc(func(response http.ResponseWriter, request *http.Request) {
		if !authorized(request, r.Username, r.Password) {
			response.Header().Set("WWW-Authenticate", `Basic realm="sunaba"`)
			http.Error(response, http.StatusText(http.StatusUnauthorized), http.StatusUnauthorized)
			return
		}
		if !allowedRequest(request.Method, request.URL.Path) {
			http.NotFound(response, request)
			return
		}
		if r.OnRequest != nil {
			r.OnRequest(request.Method, request.URL.Path)
		}
		select {
		case semaphore <- struct{}{}:
			defer func() { <-semaphore }()
			proxy.ServeHTTP(response, request)
		default:
			http.Error(response, http.StatusText(http.StatusTooManyRequests), http.StatusTooManyRequests)
		}
	})
	server := &http.Server{
		Handler: handler, ReadHeaderTimeout: 5 * time.Second,
		ReadTimeout: 30 * time.Second, IdleTimeout: 30 * time.Second,
	}
	done := make(chan error, 1)
	go func() {
		err := server.Serve(listener)
		if errors.Is(err, http.ErrServerClosed) {
			err = nil
		}
		done <- err
		close(done)
	}()
	go func() {
		<-ctx.Done()
		shutdown, cancel := context.WithTimeout(context.Background(), 3*time.Second)
		defer cancel()
		_ = server.Shutdown(shutdown)
		transport.CloseIdleConnections()
	}()
	return "http://" + listener.Addr().String(), done, nil
}

func authorized(request *http.Request, username, password string) bool {
	presentedUser, presentedPassword, ok := request.BasicAuth()
	if !ok {
		return false
	}
	wantUser, gotUser := sha256.Sum256([]byte(username)), sha256.Sum256([]byte(presentedUser))
	wantPassword, gotPassword := sha256.Sum256([]byte(password)), sha256.Sum256([]byte(presentedPassword))
	return subtle.ConstantTimeCompare(wantUser[:], gotUser[:]) == 1 && subtle.ConstantTimeCompare(wantPassword[:], gotPassword[:]) == 1
}

func allowedRequest(method, requestPath string) bool {
	if method != http.MethodGet && method != http.MethodHead && method != http.MethodPost && method != http.MethodPatch && method != http.MethodDelete {
		return false
	}
	for _, forbidden := range []string{"/tui", "/auth", "/instance", "/log", "/doc"} {
		if requestPath == forbidden || strings.HasPrefix(requestPath, forbidden+"/") {
			return false
		}
	}
	for _, allowed := range []string{
		"/global/health", "/global/event", "/event", "/project", "/path", "/vcs", "/config",
		"/provider", "/session", "/command", "/find", "/file", "/experimental/tool",
		"/lsp", "/formatter", "/mcp", "/agent", "/permission",
	} {
		if requestPath == allowed || strings.HasPrefix(requestPath, allowed+"/") {
			return true
		}
	}
	return false
}

func sanitizeResponse(response *http.Response, onReject func(string)) error {
	contentType := strings.ToLower(response.Header.Get("Content-Type"))
	if strings.HasPrefix(contentType, "text/event-stream") {
		response.Body = newSSEFilter(response.Body, onReject)
		response.ContentLength = -1
		response.Header.Del("Content-Length")
		return nil
	}
	if !strings.Contains(contentType, "json") {
		return nil
	}
	body, err := io.ReadAll(io.LimitReader(response.Body, maximumJSONResponse+1))
	_ = response.Body.Close()
	if err != nil {
		return err
	}
	if len(body) > maximumJSONResponse {
		return fmt.Errorf("attach JSON response exceeds limit")
	}
	if len(bytes.TrimSpace(body)) == 0 {
		response.Body = io.NopCloser(bytes.NewReader(nil))
		response.ContentLength = 0
		response.Header.Set("Content-Length", "0")
		return nil
	}
	sanitized, keep, err := sanitizeJSON(body)
	if err != nil {
		return err
	}
	if !keep {
		if onReject != nil {
			onReject("unsafe_tui_command")
		}
		sanitized = []byte(`{"type":"sunaba.event.rejected"}`)
	}
	response.Body = io.NopCloser(bytes.NewReader(sanitized))
	response.ContentLength = int64(len(sanitized))
	response.Header.Set("Content-Length", strconv.Itoa(len(sanitized)))
	return nil
}

func newSSEFilter(source io.ReadCloser, onReject func(string)) io.ReadCloser {
	reader, writer := io.Pipe()
	go func() {
		defer source.Close()
		buffered := bufio.NewReader(source)
		for {
			record, err := readSSERecord(buffered)
			if len(record) != 0 {
				sanitized, keep, sanitizeErr := sanitizeSSERecord(record)
				if sanitizeErr != nil {
					_ = writer.CloseWithError(sanitizeErr)
					return
				}
				if keep {
					if _, writeErr := writer.Write(sanitized); writeErr != nil {
						return
					}
				} else if onReject != nil {
					onReject("unsafe_tui_command")
				}
			}
			if err != nil {
				if errors.Is(err, io.EOF) {
					_ = writer.Close()
				} else {
					_ = writer.CloseWithError(err)
				}
				return
			}
		}
	}()
	return reader
}

func readSSERecord(reader *bufio.Reader) ([]byte, error) {
	var record []byte
	for len(record) <= 1<<20 {
		line, err := reader.ReadBytes('\n')
		record = append(record, line...)
		if bytes.Equal(line, []byte("\n")) || bytes.Equal(line, []byte("\r\n")) || err != nil {
			return record, err
		}
	}
	return nil, fmt.Errorf("attach SSE record exceeds limit")
}

func sanitizeSSERecord(record []byte) ([]byte, bool, error) {
	lines := bytes.Split(record, []byte("\n"))
	for index, line := range lines {
		if !bytes.HasPrefix(line, []byte("data:")) {
			continue
		}
		prefixLength := len("data:")
		for prefixLength < len(line) && line[prefixLength] == ' ' {
			prefixLength++
		}
		sanitized, keep, err := sanitizeJSON(line[prefixLength:])
		if err != nil || !keep {
			return nil, keep, err
		}
		lines[index] = append(append([]byte(nil), line[:prefixLength]...), sanitized...)
	}
	return bytes.Join(lines, []byte("\n")), true, nil
}

func sanitizeJSON(encoded []byte) ([]byte, bool, error) {
	var value any
	decoder := json.NewDecoder(bytes.NewReader(encoded))
	decoder.UseNumber()
	if err := decoder.Decode(&value); err != nil {
		return nil, false, fmt.Errorf("decode attach response JSON: %w", err)
	}
	if !allowedTUIEvent(value) {
		return nil, false, nil
	}
	value = sanitizeValue(value)
	var output bytes.Buffer
	encoder := json.NewEncoder(&output)
	encoder.SetEscapeHTML(false)
	if err := encoder.Encode(value); err != nil {
		return nil, false, err
	}
	return bytes.TrimSuffix(output.Bytes(), []byte("\n")), true, nil
}

var safeTUICommands = map[string]struct{}{
	"session.list": {}, "session.new": {}, "session.interrupt": {}, "session.compact": {},
	"session.page.up": {}, "session.page.down": {}, "session.half.page.up": {}, "session.half.page.down": {},
	"session.first": {}, "session.last": {}, "prompt.clear": {}, "agent.cycle": {},
}

func allowedTUIEvent(value any) bool {
	object, ok := value.(map[string]any)
	if !ok {
		return true
	}
	if payload, ok := object["payload"].(map[string]any); ok {
		object = payload
	}
	eventType, _ := object["type"].(string)
	if eventType != "tui.command.execute" {
		return true
	}
	properties, _ := object["properties"].(map[string]any)
	command, _ := properties["command"].(string)
	_, allowed := safeTUICommands[command]
	return allowed
}

func sanitizeValue(value any) any {
	switch typed := value.(type) {
	case string:
		return sanitizeTerminalText(typed)
	case []any:
		for index := range typed {
			typed[index] = sanitizeValue(typed[index])
		}
		return typed
	case map[string]any:
		for key, item := range typed {
			delete(typed, key)
			typed[sanitizeTerminalText(key)] = sanitizeValue(item)
		}
		return typed
	default:
		return value
	}
}

func sanitizeTerminalText(text string) string {
	var output strings.Builder
	for len(text) > 0 {
		r, size := utf8.DecodeRuneInString(text)
		if r == utf8.RuneError && size == 1 {
			output.WriteString("<INVALID-UTF8>")
			text = text[size:]
			continue
		}
		if unsafeTerminalRune(r) {
			fmt.Fprintf(&output, "<U+%04X>", r)
		} else {
			output.WriteRune(r)
		}
		text = text[size:]
	}
	return output.String()
}

func unsafeTerminalRune(r rune) bool {
	if (r >= 0 && r < 0x20 && r != '\n' && r != '\t') || (r >= 0x7f && r <= 0x9f) {
		return true
	}
	return r == 0x200e || r == 0x200f || (r >= 0x202a && r <= 0x202e) || (r >= 0x2066 && r <= 0x2069)
}
