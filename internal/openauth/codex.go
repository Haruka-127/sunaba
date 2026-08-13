package openauth

import (
	"bytes"
	"context"
	"crypto/sha256"
	"encoding/base64"
	"encoding/json"
	"fmt"
	"io"
	"net/http"
	"net/url"
	"strconv"
	"strings"
	"sync"
	"time"

	"sunaba/internal/modelgateway"
	"sunaba/internal/secretstore"
)

const (
	clientID            = "app_EMoamEEZ73f0CkXaXp7hrann"
	deviceUserCodeURL   = "https://auth.openai.com/api/accounts/deviceauth/usercode"
	deviceTokenURL      = "https://auth.openai.com/api/accounts/deviceauth/token"
	tokenURL            = "https://auth.openai.com/oauth/token"
	deviceVerifyURL     = "https://auth.openai.com/codex/device"
	deviceRedirectURI   = "https://auth.openai.com/deviceauth/callback"
	maximumResponseSize = 64 << 10
	defaultTokenTTL     = time.Hour
	maximumTTLSeconds   = (1<<63 - 1) / int64(time.Second)
)

type credentialStore interface {
	Load(context.Context) (secretstore.CodexOAuthCredential, error)
	Save(context.Context, secretstore.CodexOAuthCredential) error
}

type keychainStore struct{}

func (keychainStore) Load(ctx context.Context) (secretstore.CodexOAuthCredential, error) {
	return secretstore.LoadCodexOAuth(ctx)
}

func (keychainStore) Save(ctx context.Context, credential secretstore.CodexOAuthCredential) error {
	return secretstore.StoreCodexOAuth(ctx, credential)
}

type Client struct {
	httpClient   *http.Client
	userCodeURL  string
	deviceURL    string
	tokenURL     string
	verification string
	now          func() time.Time
}

func NewClient() *Client {
	transport := http.DefaultTransport.(*http.Transport).Clone()
	transport.Proxy = nil
	return &Client{
		httpClient: &http.Client{
			Transport: transport, Timeout: 30 * time.Second,
			CheckRedirect: func(_ *http.Request, _ []*http.Request) error { return http.ErrUseLastResponse },
		},
		userCodeURL: deviceUserCodeURL, deviceURL: deviceTokenURL, tokenURL: tokenURL,
		verification: deviceVerifyURL, now: time.Now,
	}
}

type Manager struct {
	mu     sync.Mutex
	client *Client
	store  credentialStore
	cached *secretstore.CodexOAuthCredential
}

func NewManager() *Manager {
	return &Manager{client: NewClient(), store: keychainStore{}}
}

func (m *Manager) Login(ctx context.Context, output io.Writer) error {
	credential, err := m.client.deviceLogin(ctx, output)
	if err != nil {
		return err
	}
	if err := m.store.Save(ctx, credential); err != nil {
		return err
	}
	m.mu.Lock()
	m.cached = &credential
	m.mu.Unlock()
	return nil
}

func (m *Manager) AccessToken(ctx context.Context) (modelgateway.OAuthAccess, error) {
	m.mu.Lock()
	defer m.mu.Unlock()
	var credential secretstore.CodexOAuthCredential
	if m.cached == nil {
		loaded, err := m.store.Load(ctx)
		if err != nil {
			return modelgateway.OAuthAccess{}, err
		}
		credential = loaded
	} else {
		credential = *m.cached
	}
	if m.client.now().Add(time.Minute).Unix() >= credential.ExpiresAt {
		refreshed, err := m.client.refresh(ctx, credential)
		if err != nil {
			return modelgateway.OAuthAccess{}, err
		}
		credential = refreshed
		storeContext, cancel := context.WithTimeout(context.WithoutCancel(ctx), 10*time.Second)
		defer cancel()
		if err := m.store.Save(storeContext, credential); err != nil {
			return modelgateway.OAuthAccess{}, err
		}
	}
	m.cached = &credential
	return modelgateway.OAuthAccess{Token: credential.AccessToken, AccountID: credential.AccountID}, nil
}

type userCodeResponse struct {
	DeviceAuthID string          `json:"device_auth_id"`
	UserCode     string          `json:"user_code"`
	UserCodeAlt  string          `json:"usercode"`
	Interval     json.RawMessage `json:"interval"`
}

type deviceTokenResponse struct {
	AuthorizationCode string `json:"authorization_code"`
	CodeVerifier      string `json:"code_verifier"`
	CodeChallenge     string `json:"code_challenge"`
}

type oauthTokenResponse struct {
	AccessToken  *string `json:"access_token"`
	RefreshToken *string `json:"refresh_token"`
	IDToken      *string `json:"id_token"`
	ExpiresIn    *int64  `json:"expires_in"`
}

func (c *Client) deviceLogin(ctx context.Context, output io.Writer) (secretstore.CodexOAuthCredential, error) {
	body, _ := json.Marshal(map[string]string{"client_id": clientID})
	var code userCodeResponse
	if err := c.doJSON(ctx, c.userCodeURL, bytes.NewReader(body), &code); err != nil {
		return secretstore.CodexOAuthCredential{}, fmt.Errorf("request Codex device code: %w", err)
	}
	userCode := strings.TrimSpace(code.UserCode)
	if userCode == "" {
		userCode = strings.TrimSpace(code.UserCodeAlt)
	}
	if !safeValue(code.DeviceAuthID, 8, 4096) || !safeValue(userCode, 4, 256) {
		return secretstore.CodexOAuthCredential{}, fmt.Errorf("Codex device response is invalid")
	}
	fmt.Fprintf(output, "Open %s and enter code: %s\n", c.verification, userCode)
	interval := parseInterval(code.Interval)
	deadline := c.now().Add(15 * time.Minute)
	var device deviceTokenResponse
	for {
		if !c.now().Before(deadline) {
			return secretstore.CodexOAuthCredential{}, fmt.Errorf("Codex device authentication timed out")
		}
		pollBody, _ := json.Marshal(map[string]string{"device_auth_id": code.DeviceAuthID, "user_code": userCode})
		status, err := c.doJSONStatus(ctx, c.deviceURL, bytes.NewReader(pollBody), &device)
		if err == nil && status >= 200 && status < 300 {
			break
		}
		if err != nil || (status != http.StatusForbidden && status != http.StatusNotFound) {
			return secretstore.CodexOAuthCredential{}, fmt.Errorf("poll Codex device authorization: status %d", status)
		}
		timer := time.NewTimer(interval)
		select {
		case <-ctx.Done():
			timer.Stop()
			return secretstore.CodexOAuthCredential{}, ctx.Err()
		case <-timer.C:
		}
	}
	if !safeValue(device.AuthorizationCode, 8, 8192) || !safeValue(device.CodeVerifier, 43, 256) || !safeValue(device.CodeChallenge, 20, 256) {
		return secretstore.CodexOAuthCredential{}, fmt.Errorf("Codex device token response is invalid")
	}
	challenge := sha256.Sum256([]byte(device.CodeVerifier))
	if base64.RawURLEncoding.EncodeToString(challenge[:]) != device.CodeChallenge {
		return secretstore.CodexOAuthCredential{}, fmt.Errorf("Codex device PKCE response is invalid")
	}
	form := url.Values{
		"grant_type": {"authorization_code"}, "client_id": {clientID},
		"code": {device.AuthorizationCode}, "redirect_uri": {deviceRedirectURI}, "code_verifier": {device.CodeVerifier},
	}
	token, err := c.exchange(ctx, form)
	if err != nil {
		return secretstore.CodexOAuthCredential{}, err
	}
	return c.initialCredential(token)
}

func (c *Client) refresh(ctx context.Context, previous secretstore.CodexOAuthCredential) (secretstore.CodexOAuthCredential, error) {
	form := url.Values{
		"client_id": {clientID}, "grant_type": {"refresh_token"},
		"refresh_token": {previous.RefreshToken}, "scope": {"openid profile email"},
	}
	token, err := c.exchange(ctx, form)
	if err != nil {
		return secretstore.CodexOAuthCredential{}, fmt.Errorf("refresh Codex OAuth token: %w", err)
	}
	return c.refreshedCredential(token, previous)
}

func (c *Client) exchange(ctx context.Context, form url.Values) (oauthTokenResponse, error) {
	request, err := http.NewRequestWithContext(ctx, http.MethodPost, c.tokenURL, strings.NewReader(form.Encode()))
	if err != nil {
		return oauthTokenResponse{}, err
	}
	request.Header.Set("Content-Type", "application/x-www-form-urlencoded")
	request.Header.Set("Accept", "application/json")
	response, err := c.httpClient.Do(request)
	if err != nil {
		return oauthTokenResponse{}, err
	}
	defer response.Body.Close()
	if response.StatusCode < 200 || response.StatusCode >= 300 {
		return oauthTokenResponse{}, fmt.Errorf("token endpoint returned status %d", response.StatusCode)
	}
	var token oauthTokenResponse
	if err := decodeBounded(response.Body, &token); err != nil {
		return oauthTokenResponse{}, err
	}
	return token, nil
}

func (c *Client) initialCredential(token oauthTokenResponse) (secretstore.CodexOAuthCredential, error) {
	accessToken, err := requiredTokenValue("access_token", token.AccessToken)
	if err != nil {
		return secretstore.CodexOAuthCredential{}, err
	}
	refreshToken, err := requiredTokenValue("refresh_token", token.RefreshToken)
	if err != nil {
		return secretstore.CodexOAuthCredential{}, err
	}
	idToken, err := requiredTokenValue("id_token", token.IDToken)
	if err != nil {
		return secretstore.CodexOAuthCredential{}, err
	}
	expiresAt, err := c.tokenExpiresAt(token.ExpiresIn)
	if err != nil {
		return secretstore.CodexOAuthCredential{}, err
	}
	accountID, err := accountIDFromJWT(idToken)
	if err != nil || !safeValue(accountID, 8, 1024) {
		return secretstore.CodexOAuthCredential{}, fmt.Errorf("Codex OAuth account identity is unavailable")
	}
	return secretstore.CodexOAuthCredential{
		AccessToken: accessToken, RefreshToken: refreshToken, IDToken: idToken,
		AccountID: accountID, ExpiresAt: expiresAt,
	}, nil
}

func (c *Client) refreshedCredential(token oauthTokenResponse, previous secretstore.CodexOAuthCredential) (secretstore.CodexOAuthCredential, error) {
	accessToken, err := refreshedTokenValue("access_token", token.AccessToken, previous.AccessToken)
	if err != nil {
		return secretstore.CodexOAuthCredential{}, err
	}
	refreshToken, err := refreshedTokenValue("refresh_token", token.RefreshToken, previous.RefreshToken)
	if err != nil {
		return secretstore.CodexOAuthCredential{}, err
	}
	idToken, err := refreshedTokenValue("id_token", token.IDToken, previous.IDToken)
	if err != nil {
		return secretstore.CodexOAuthCredential{}, err
	}
	expiresAt, err := c.tokenExpiresAt(token.ExpiresIn)
	if err != nil {
		return secretstore.CodexOAuthCredential{}, err
	}
	accountID, err := accountIDFromJWT(idToken)
	if err != nil {
		accountID = previous.AccountID
	}
	if !safeValue(accountID, 8, 1024) {
		return secretstore.CodexOAuthCredential{}, fmt.Errorf("Codex OAuth account identity is unavailable")
	}
	return secretstore.CodexOAuthCredential{
		AccessToken: accessToken, RefreshToken: refreshToken, IDToken: idToken,
		AccountID: accountID, ExpiresAt: expiresAt,
	}, nil
}

func requiredTokenValue(field string, value *string) (string, error) {
	if value == nil || !safeValue(*value, 8, 32<<10) {
		return "", fmt.Errorf("Codex OAuth token response has invalid %s", field)
	}
	return *value, nil
}

func refreshedTokenValue(field string, value *string, previous string) (string, error) {
	if value == nil {
		value = &previous
	}
	return requiredTokenValue(field, value)
}

func (c *Client) tokenExpiresAt(expiresIn *int64) (int64, error) {
	ttl := defaultTokenTTL
	if expiresIn != nil {
		if *expiresIn <= 0 || *expiresIn > maximumTTLSeconds {
			return 0, fmt.Errorf("Codex OAuth token response has invalid expires_in")
		}
		ttl = time.Duration(*expiresIn) * time.Second
	}
	return c.now().Add(ttl).Unix(), nil
}

func (c *Client) doJSON(ctx context.Context, endpoint string, body io.Reader, destination any) error {
	status, err := c.doJSONStatus(ctx, endpoint, body, destination)
	if err != nil {
		return err
	}
	if status < 200 || status >= 300 {
		return fmt.Errorf("endpoint returned status %d", status)
	}
	return nil
}

func (c *Client) doJSONStatus(ctx context.Context, endpoint string, body io.Reader, destination any) (int, error) {
	request, err := http.NewRequestWithContext(ctx, http.MethodPost, endpoint, body)
	if err != nil {
		return 0, err
	}
	request.Header.Set("Content-Type", "application/json")
	request.Header.Set("Accept", "application/json")
	response, err := c.httpClient.Do(request)
	if err != nil {
		return 0, err
	}
	defer response.Body.Close()
	if response.StatusCode < 200 || response.StatusCode >= 300 {
		_, _ = io.Copy(io.Discard, io.LimitReader(response.Body, maximumResponseSize))
		return response.StatusCode, nil
	}
	return response.StatusCode, decodeBounded(response.Body, destination)
}

func decodeBounded(reader io.Reader, destination any) error {
	data, err := io.ReadAll(io.LimitReader(reader, maximumResponseSize+1))
	if err != nil || len(data) > maximumResponseSize {
		return fmt.Errorf("OAuth response exceeded the size limit")
	}
	if err := json.Unmarshal(data, destination); err != nil {
		return fmt.Errorf("decode OAuth response: %w", err)
	}
	return nil
}

func accountIDFromJWT(token string) (string, error) {
	parts := strings.Split(token, ".")
	if len(parts) != 3 || len(parts[1]) > maximumResponseSize {
		return "", fmt.Errorf("invalid ID token")
	}
	claims, err := base64.RawURLEncoding.DecodeString(parts[1])
	if err != nil || len(claims) > maximumResponseSize {
		return "", fmt.Errorf("invalid ID token claims")
	}
	var payload struct {
		Auth struct {
			AccountID string `json:"chatgpt_account_id"`
		} `json:"https://api.openai.com/auth"`
	}
	if json.Unmarshal(claims, &payload) != nil || payload.Auth.AccountID == "" {
		return "", fmt.Errorf("ID token does not contain a ChatGPT account")
	}
	return payload.Auth.AccountID, nil
}

func parseInterval(raw json.RawMessage) time.Duration {
	seconds := 5
	var number int
	if json.Unmarshal(raw, &number) == nil {
		seconds = number
	} else {
		var text string
		if json.Unmarshal(raw, &text) == nil {
			if value, err := strconv.Atoi(strings.TrimSpace(text)); err == nil {
				seconds = value
			}
		}
	}
	if seconds < 1 || seconds > 30 {
		seconds = 5
	}
	return time.Duration(seconds) * time.Second
}

func safeValue(value string, minimum, maximum int) bool {
	if len(value) < minimum || len(value) > maximum {
		return false
	}
	for index := 0; index < len(value); index++ {
		if value[index] < 0x20 || value[index] == 0x7f {
			return false
		}
	}
	return true
}
