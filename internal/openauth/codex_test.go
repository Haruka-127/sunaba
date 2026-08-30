package openauth

import (
	"context"
	"crypto/sha256"
	"encoding/base64"
	"encoding/json"
	"io"
	"net/http"
	"net/http/httptest"
	"os"
	"path/filepath"
	"strings"
	"sync"
	"sync/atomic"
	"testing"
	"time"

	"sunaba/internal/secretstore"
)

type roundTripFunc func(*http.Request) (*http.Response, error)

func (function roundTripFunc) RoundTrip(request *http.Request) (*http.Response, error) {
	return function(request)
}

type memoryStore struct {
	credential secretstore.CodexOAuthCredential
	loads      int
	saves      int
}

func (s *memoryStore) Load(context.Context) (secretstore.CodexOAuthCredential, error) {
	s.loads++
	return s.credential, nil
}

func (s *memoryStore) Save(_ context.Context, credential secretstore.CodexOAuthCredential) error {
	s.credential = credential
	s.saves++
	return nil
}

func (s *memoryStore) Update(ctx context.Context, update func(secretstore.CodexOAuthCredential) (secretstore.CodexOAuthCredential, error)) (secretstore.CodexOAuthCredential, error) {
	s.loads++
	credential, err := update(s.credential)
	if err != nil {
		return secretstore.CodexOAuthCredential{}, err
	}
	s.credential = credential
	s.saves++
	return credential, nil
}

func TestDeviceLoginUsesFixedFlowAndStoresCredential(t *testing.T) {
	verifier := strings.Repeat("v", 43)
	challengeHash := sha256.Sum256([]byte(verifier))
	challenge := base64.RawURLEncoding.EncodeToString(challengeHash[:])
	idToken := testIDToken(t, "account-device")
	server := httptest.NewServer(http.HandlerFunc(func(response http.ResponseWriter, request *http.Request) {
		switch request.URL.Path {
		case "/usercode":
			assertJSONClientID(t, request)
			_, _ = io.WriteString(response, `{"device_auth_id":"device-auth-123","user_code":"ABCD-EFGH","interval":1}`)
		case "/device":
			_, _ = io.WriteString(response, `{"authorization_code":"authorization-code","code_verifier":"`+verifier+`","code_challenge":"`+challenge+`"}`)
		case "/token":
			if err := request.ParseForm(); err != nil || request.Form.Get("client_id") != clientID || request.Form.Get("redirect_uri") != deviceRedirectURI || request.Form.Get("code_verifier") != verifier {
				t.Errorf("token form=%v err=%v", request.Form, err)
			}
			json.NewEncoder(response).Encode(map[string]any{"access_token": "access-token-123", "refresh_token": "refresh-token-123", "id_token": idToken})
		default:
			http.NotFound(response, request)
		}
	}))
	defer server.Close()
	now := time.Unix(1_800_000_000, 0)
	client := &Client{httpClient: server.Client(), userCodeURL: server.URL + "/usercode", deviceURL: server.URL + "/device", tokenURL: server.URL + "/token", verification: deviceVerifyURL, now: func() time.Time { return now }}
	store := &memoryStore{}
	manager := &Manager{client: client, store: store}
	var output strings.Builder
	if err := manager.Login(context.Background(), &output); err != nil {
		t.Fatal(err)
	}
	if store.saves != 1 || store.credential.AccountID != "account-device" || store.credential.ExpiresAt != now.Add(time.Hour).Unix() || !strings.Contains(output.String(), deviceVerifyURL) || !strings.Contains(output.String(), "ABCD-EFGH") {
		t.Fatalf("store=%+v output=%q", store, output.String())
	}
}

func TestManagerRefreshesExpiredCredentialAndPersistsRotation(t *testing.T) {
	now := time.Unix(1_800_000_000, 0)
	idToken := testIDToken(t, "account-refreshed")
	server := httptest.NewServer(http.HandlerFunc(func(response http.ResponseWriter, request *http.Request) {
		if err := request.ParseForm(); err != nil || request.Form.Get("grant_type") != "refresh_token" || request.Form.Get("refresh_token") != "old-refresh-token" {
			t.Errorf("refresh form=%v err=%v", request.Form, err)
		}
		json.NewEncoder(response).Encode(map[string]any{"access_token": "new-access-token", "refresh_token": "new-refresh-token", "id_token": idToken, "expires_in": 1800})
	}))
	defer server.Close()
	store := &memoryStore{credential: secretstore.CodexOAuthCredential{AccessToken: "old-access-token", RefreshToken: "old-refresh-token", IDToken: testIDToken(t, "old-account"), AccountID: "old-account", ExpiresAt: now.Unix()}}
	manager := &Manager{client: &Client{httpClient: server.Client(), tokenURL: server.URL, now: func() time.Time { return now }}, store: store}
	access, err := manager.AccessToken(context.Background())
	if err != nil {
		t.Fatal(err)
	}
	if access.Token != "new-access-token" || access.AccountID != "account-refreshed" || store.saves != 1 || store.credential.RefreshToken != "new-refresh-token" {
		t.Fatalf("access=%+v store=%+v", access, store)
	}
	if _, err := manager.AccessToken(context.Background()); err != nil || store.loads != 2 || store.saves != 1 {
		t.Fatalf("cached access reloaded credential file: store=%+v error=%v", store, err)
	}
}

func TestManagerRefreshPreservesTokensOmittedByResponse(t *testing.T) {
	now := time.Unix(1_800_000_000, 0)
	oldIDToken := testIDToken(t, "old-account")
	server := httptest.NewServer(http.HandlerFunc(func(response http.ResponseWriter, request *http.Request) {
		if err := request.ParseForm(); err != nil || request.Form.Get("grant_type") != "refresh_token" || request.Form.Get("refresh_token") != "old-refresh-token" {
			t.Errorf("refresh form=%v err=%v", request.Form, err)
		}
		json.NewEncoder(response).Encode(map[string]any{"access_token": "new-access-token"})
	}))
	defer server.Close()
	store := &memoryStore{credential: secretstore.CodexOAuthCredential{AccessToken: "old-access-token", RefreshToken: "old-refresh-token", IDToken: oldIDToken, AccountID: "old-account", ExpiresAt: now.Unix()}}
	manager := &Manager{client: &Client{httpClient: server.Client(), tokenURL: server.URL, now: func() time.Time { return now }}, store: store}
	access, err := manager.AccessToken(context.Background())
	if err != nil {
		t.Fatal(err)
	}
	if access.Token != "new-access-token" || access.AccountID != "old-account" || store.saves != 1 {
		t.Fatalf("access=%+v store=%+v", access, store)
	}
	if store.credential.RefreshToken != "old-refresh-token" || store.credential.IDToken != oldIDToken || store.credential.ExpiresAt != now.Add(time.Hour).Unix() {
		t.Fatalf("omitted refresh values were not preserved: %+v", store.credential)
	}
}

func TestManagersSerializeRefreshRotationThroughCredentialFile(t *testing.T) {
	root, err := filepath.EvalSymlinks(t.TempDir())
	if err != nil {
		t.Fatal(err)
	}
	if err := os.Chmod(root, 0700); err != nil {
		t.Fatal(err)
	}
	t.Setenv("XDG_DATA_HOME", root)
	now := time.Unix(1_800_000_000, 0)
	old := secretstore.CodexOAuthCredential{
		AccessToken: "old-access-token", RefreshToken: "old-refresh-token",
		IDToken: testIDToken(t, "old-account"), AccountID: "old-account", ExpiresAt: now.Unix(),
	}
	if err := secretstore.StoreOpenAIKey(context.Background(), "sk-preserved-01234567890123456789"); err != nil {
		t.Fatal(err)
	}
	if err := secretstore.StoreCodexOAuth(context.Background(), old); err != nil {
		t.Fatal(err)
	}
	newIDToken := testIDToken(t, "new-account")
	var requests atomic.Int32
	transport := roundTripFunc(func(request *http.Request) (*http.Response, error) {
		requests.Add(1)
		if err := request.ParseForm(); err != nil || request.Form.Get("refresh_token") != old.RefreshToken {
			t.Errorf("refresh form=%v error=%v", request.Form, err)
		}
		body := `{"access_token":"new-access-token","refresh_token":"new-refresh-token","id_token":"` + newIDToken + `","expires_in":1800}`
		return &http.Response{StatusCode: http.StatusOK, Body: io.NopCloser(strings.NewReader(body)), Header: make(http.Header)}, nil
	})
	newManager := func() *Manager {
		cached := old
		return &Manager{
			client: &Client{httpClient: &http.Client{Transport: transport}, tokenURL: "https://auth.openai.test/token", now: func() time.Time { return now }},
			store:  fileStore{}, cached: &cached,
		}
	}
	managers := []*Manager{newManager(), newManager()}
	accesses := make([]string, len(managers))
	var wait sync.WaitGroup
	for index, manager := range managers {
		wait.Add(1)
		go func(index int, manager *Manager) {
			defer wait.Done()
			access, err := manager.AccessToken(context.Background())
			if err != nil {
				t.Errorf("AccessToken: %v", err)
				return
			}
			accesses[index] = access.Token + "/" + access.AccountID
		}(index, manager)
	}
	wait.Wait()
	if requests.Load() != 1 {
		t.Fatalf("refresh requests=%d, want 1", requests.Load())
	}
	for _, access := range accesses {
		if access != "new-access-token/new-account" {
			t.Fatalf("access=%q", access)
		}
	}
	if key, err := secretstore.LoadOpenAIKey(context.Background()); err != nil || key != "sk-preserved-01234567890123456789" {
		t.Fatalf("refresh rotation changed API key length=%d error=%v", len(key), err)
	}
}

func TestInitialCredentialRejectsExplicitInvalidExpiry(t *testing.T) {
	now := time.Unix(1_800_000_000, 0)
	accessToken, refreshToken, idToken := "access-token", "refresh-token", testIDToken(t, "account-id")
	expiresIn := int64(0)
	client := &Client{now: func() time.Time { return now }}
	_, err := client.initialCredential(oauthTokenResponse{AccessToken: &accessToken, RefreshToken: &refreshToken, IDToken: &idToken, ExpiresIn: &expiresIn})
	if err == nil || !strings.Contains(err.Error(), "expires_in") {
		t.Fatalf("expected an expires_in validation error, got %v", err)
	}
}

func TestInitialCredentialAcceptsExpiryBeyondOneDay(t *testing.T) {
	now := time.Unix(1_800_000_000, 0)
	accessToken, refreshToken, idToken := "access-token", "refresh-token", testIDToken(t, "account-id")
	expiresIn := int64((7 * 24 * time.Hour) / time.Second)
	client := &Client{now: func() time.Time { return now }}
	credential, err := client.initialCredential(oauthTokenResponse{AccessToken: &accessToken, RefreshToken: &refreshToken, IDToken: &idToken, ExpiresIn: &expiresIn})
	if err != nil {
		t.Fatal(err)
	}
	if credential.ExpiresAt != now.Add(7*24*time.Hour).Unix() {
		t.Fatalf("ExpiresAt = %d, want %d", credential.ExpiresAt, now.Add(7*24*time.Hour).Unix())
	}
}

func TestInitialCredentialRejectsExpiryThatOverflowsDuration(t *testing.T) {
	now := time.Unix(1_800_000_000, 0)
	accessToken, refreshToken, idToken := "access-token", "refresh-token", testIDToken(t, "account-id")
	expiresIn := int64(maximumTTLSeconds + 1)
	client := &Client{now: func() time.Time { return now }}
	_, err := client.initialCredential(oauthTokenResponse{AccessToken: &accessToken, RefreshToken: &refreshToken, IDToken: &idToken, ExpiresIn: &expiresIn})
	if err == nil || !strings.Contains(err.Error(), "expires_in") {
		t.Fatalf("expected an expires_in overflow error, got %v", err)
	}
}

func testIDToken(t *testing.T, account string) string {
	t.Helper()
	header := base64.RawURLEncoding.EncodeToString([]byte(`{"alg":"none"}`))
	claims, err := json.Marshal(map[string]any{"https://api.openai.com/auth": map[string]string{"chatgpt_account_id": account}})
	if err != nil {
		t.Fatal(err)
	}
	return header + "." + base64.RawURLEncoding.EncodeToString(claims) + ".signature"
}

func assertJSONClientID(t *testing.T, request *http.Request) {
	t.Helper()
	var body map[string]string
	if err := json.NewDecoder(request.Body).Decode(&body); err != nil || body["client_id"] != clientID {
		t.Errorf("device request=%v err=%v", body, err)
	}
}
