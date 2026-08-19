package gitgateway

import (
	"crypto/rand"
	"crypto/sha256"
	"crypto/subtle"
	"encoding/base64"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"net/url"
	"regexp"
	"sort"
	"strings"
	"sync"
	"time"

	"sunaba/internal/audit"
)

var ErrPushApprovalInvalid = errors.New("Git push approval is invalid, expired, or already consumed")
var gitIdentityPattern = regexp.MustCompile(`^[a-zA-Z0-9][a-zA-Z0-9._-]{0,127}$`)
var objectIDPattern = regexp.MustCompile(`^(?:[0-9a-f]{40}|[0-9a-f]{64})$`)
var refPattern = regexp.MustCompile(`^refs/[A-Za-z0-9][A-Za-z0-9._/-]{0,999}$`)

type RefUpdate struct {
	Ref    string `json:"ref"`
	Old    string `json:"old"`
	New    string `json:"new"`
	Force  bool   `json:"force"`
	Delete bool   `json:"delete"`
}

type PushBinding struct {
	ProjectID  string      `json:"project_id"`
	Repository string      `json:"repository"`
	RemoteName string      `json:"remote_name"`
	RemoteURL  string      `json:"remote_url"`
	Updates    []RefUpdate `json:"updates"`
}

type PushRequest struct {
	Nonce     string
	Binding   PushBinding
	Digest    string
	ExpiresAt time.Time
}

type PushGrant struct{ id [sha256.Size]byte }

type pendingPush struct {
	binding PushBinding
	digest  string
	expires time.Time
}

type approvedPush struct {
	binding PushBinding
	expires time.Time
}

type PushApprovalManager struct {
	mu      sync.Mutex
	pending map[[sha256.Size]byte]pendingPush
	grants  map[[sha256.Size]byte]approvedPush
	now     func() time.Time
	audit   *audit.Recorder
	vm      string
	session string
}

func NewPushApprovalManager(now func() time.Time, recorder *audit.Recorder, vmID, sessionID string) (*PushApprovalManager, error) {
	if recorder == nil || !gitIdentityPattern.MatchString(vmID) || !gitIdentityPattern.MatchString(sessionID) {
		return nil, fmt.Errorf("Git approval manager requires host audit and bound VM/session identities")
	}
	if now == nil {
		now = time.Now
	}
	return &PushApprovalManager{pending: make(map[[sha256.Size]byte]pendingPush), grants: make(map[[sha256.Size]byte]approvedPush), now: now, audit: recorder, vm: vmID, session: sessionID}, nil
}

func (m *PushApprovalManager) NewRequest(binding PushBinding, lifetime time.Duration) (PushRequest, error) {
	canonical, digest, err := canonicalBinding(binding)
	if err != nil || lifetime <= 0 || lifetime > 5*time.Minute {
		return PushRequest{}, fmt.Errorf("invalid Git push approval request")
	}
	raw := make([]byte, 32)
	if _, err := rand.Read(raw); err != nil {
		return PushRequest{}, err
	}
	nonce := base64.RawURLEncoding.EncodeToString(raw)
	id := sha256.Sum256([]byte(nonce))
	expires := m.now().Add(lifetime)
	if err := m.record("git.push.approval", "started", canonical, digest, nonce); err != nil {
		return PushRequest{}, err
	}
	m.mu.Lock()
	m.pending[id] = pendingPush{binding: canonical, digest: digest, expires: expires}
	m.mu.Unlock()
	return PushRequest{Nonce: nonce, Binding: canonical, Digest: digest, ExpiresAt: expires}, nil
}

func (m *PushApprovalManager) Confirm(nonce string, presented PushBinding) (*PushGrant, error) {
	id := sha256.Sum256([]byte(nonce))
	canonical, digest, err := canonicalBinding(presented)
	m.mu.Lock()
	item, ok := m.pending[id]
	delete(m.pending, id)
	m.mu.Unlock()
	if err != nil || !ok || !m.now().Before(item.expires) || !equalDigest(item.digest, digest) {
		_ = m.record("git.push.approval", "rejected", canonical, digest, nonce)
		return nil, ErrPushApprovalInvalid
	}
	raw := make([]byte, 32)
	if _, err := rand.Read(raw); err != nil {
		return nil, err
	}
	grantID := sha256.Sum256(raw)
	if err := m.record("git.push.approval", "success", item.binding, item.digest, nonce); err != nil {
		return nil, err
	}
	m.mu.Lock()
	m.grants[grantID] = approvedPush{binding: item.binding, expires: item.expires}
	m.mu.Unlock()
	return &PushGrant{id: grantID}, nil
}

// Reject consumes one exact pending request without creating a grant.
func (m *PushApprovalManager) Reject(nonce string, presented PushBinding) error {
	id := sha256.Sum256([]byte(nonce))
	canonical, digest, err := canonicalBinding(presented)
	m.mu.Lock()
	item, ok := m.pending[id]
	delete(m.pending, id)
	m.mu.Unlock()
	if err != nil || !ok || !m.now().Before(item.expires) || !equalDigest(item.digest, digest) {
		_ = m.record("git.push.approval", "rejected", canonical, digest, nonce)
		return ErrPushApprovalInvalid
	}
	return m.record("git.push.approval", "rejected", item.binding, item.digest, nonce)
}

func (m *PushApprovalManager) Consume(grant *PushGrant, current PushBinding) error {
	if grant == nil {
		return ErrPushApprovalInvalid
	}
	canonical, digest, err := canonicalBinding(current)
	m.mu.Lock()
	expected, ok := m.grants[grant.id]
	delete(m.grants, grant.id)
	m.mu.Unlock()
	_, expectedDigest, expectedErr := canonicalBinding(expected.binding)
	if err != nil || expectedErr != nil || !ok || !m.now().Before(expected.expires) || !equalDigest(expectedDigest, digest) {
		_ = m.record("git.push.consume", "rejected", canonical, digest, "")
		return ErrPushApprovalInvalid
	}
	return m.record("git.push.consume", "success", canonical, digest, "")
}

func canonicalBinding(binding PushBinding) (PushBinding, string, error) {
	if !gitIdentityPattern.MatchString(binding.ProjectID) || !gitIdentityPattern.MatchString(binding.Repository) || !gitIdentityPattern.MatchString(binding.RemoteName) || len(binding.Updates) == 0 || len(binding.Updates) > 128 {
		return PushBinding{}, "", fmt.Errorf("invalid Git push identity")
	}
	normalized, err := normalizeRemote(binding.RemoteURL)
	if err != nil {
		return PushBinding{}, "", err
	}
	binding.RemoteURL = normalized
	binding.Updates = append([]RefUpdate(nil), binding.Updates...)
	for i := range binding.Updates {
		update := &binding.Updates[i]
		if !refPattern.MatchString(update.Ref) || !objectIDPattern.MatchString(update.Old) || !objectIDPattern.MatchString(update.New) || len(update.Old) != len(update.New) {
			return PushBinding{}, "", fmt.Errorf("invalid Git ref update")
		}
		zero := strings.Repeat("0", len(update.New))
		if update.Delete != (update.New == zero) || (update.Old == zero && update.Delete) {
			return PushBinding{}, "", fmt.Errorf("inconsistent Git delete update")
		}
	}
	sort.Slice(binding.Updates, func(i, j int) bool { return binding.Updates[i].Ref < binding.Updates[j].Ref })
	for i := 1; i < len(binding.Updates); i++ {
		if binding.Updates[i-1].Ref == binding.Updates[i].Ref {
			return PushBinding{}, "", fmt.Errorf("duplicate Git ref update")
		}
	}
	encoded, _ := json.Marshal(binding)
	sum := sha256.Sum256(encoded)
	return binding, hex.EncodeToString(sum[:]), nil
}

func normalizeRemote(raw string) (string, error) {
	parsed, err := url.Parse(raw)
	if err != nil {
		return "", fmt.Errorf("Git remote must be credential-free fixed HTTPS or SSH URL")
	}
	scheme := strings.ToLower(parsed.Scheme)
	if (scheme != "https" && scheme != "ssh") || parsed.Host == "" || parsed.User != nil || parsed.RawQuery != "" || parsed.Fragment != "" || !strings.HasSuffix(parsed.Path, ".git") {
		return "", fmt.Errorf("Git remote must be credential-free fixed HTTPS or SSH URL")
	}
	parsed.Scheme, parsed.Host = scheme, strings.ToLower(parsed.Host)
	return parsed.String(), nil
}

func equalDigest(left, right string) bool {
	return len(left) == 64 && len(right) == 64 && subtle.ConstantTimeCompare([]byte(left), []byte(right)) == 1
}

func ValidatePushRequest(request PushRequest) error {
	_, digest, err := canonicalBinding(request.Binding)
	if err != nil || len(request.Nonce) < 32 || request.ExpiresAt.IsZero() || !equalDigest(digest, request.Digest) {
		return fmt.Errorf("invalid Git push approval request")
	}
	return nil
}

func (m *PushApprovalManager) record(action, outcome string, binding PushBinding, digest, nonce string) error {
	details := map[string]string{"repository": binding.Repository, "remote_name": binding.RemoteName, "remote_url": binding.RemoteURL, "push_digest": digest}
	if nonce != "" {
		details["nonce"] = nonce
	}
	return m.audit.Append(audit.BoundaryEvent{Category: "git", Action: action, Outcome: outcome, ProjectID: binding.ProjectID, VMID: m.vm, SessionID: m.session, Details: details})
}
