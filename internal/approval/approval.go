package approval

import (
	"crypto/rand"
	"crypto/sha256"
	"crypto/subtle"
	"encoding/base64"
	"errors"
	"fmt"
	"strings"
	"sync"
	"time"
	"unicode/utf8"

	"sunaba/internal/audit"
)

var ErrApprovalInvalid = errors.New("approval is invalid, expired, or already consumed")

type Binding struct {
	ProjectID       string
	BaselineDigest  string
	MergedDigest    string
	ChangeSetDigest string
}

type Request struct {
	Nonce     string
	Binding   Binding
	ExpiresAt time.Time
	Summary   string
	Display   string
}

type Grant struct {
	id      [sha256.Size]byte
	binding Binding
}

type pending struct {
	binding   Binding
	expiresAt time.Time
}

type Manager struct {
	mu      sync.Mutex
	pending map[[sha256.Size]byte]pending
	grants  map[[sha256.Size]byte]Binding
	now     func() time.Time
	audit   *audit.Recorder
	project string
	vm      string
	session string
}

func NewManager(now func() time.Time) *Manager {
	if now == nil {
		now = time.Now
	}
	return &Manager{pending: make(map[[sha256.Size]byte]pending), grants: make(map[[sha256.Size]byte]Binding), now: now}
}

func NewAuditedManager(now func() time.Time, recorder *audit.Recorder, projectID, vmID, sessionID string) (*Manager, error) {
	if recorder == nil || projectID == "" || vmID == "" || sessionID == "" {
		return nil, fmt.Errorf("audited approval manager requires host recorder and bound identities")
	}
	manager := NewManager(now)
	manager.audit, manager.project, manager.vm, manager.session = recorder, projectID, vmID, sessionID
	return manager, nil
}

func (m *Manager) NewRequest(binding Binding, summary string, lifetime time.Duration) (Request, error) {
	if err := validateBinding(binding); err != nil || lifetime <= 0 || lifetime > 10*time.Minute {
		return Request{}, fmt.Errorf("invalid approval request")
	}
	raw := make([]byte, 32)
	if _, err := rand.Read(raw); err != nil {
		return Request{}, err
	}
	nonce := base64.RawURLEncoding.EncodeToString(raw)
	id := sha256.Sum256([]byte(nonce))
	expires := m.now().Add(lifetime)
	m.mu.Lock()
	m.pending[id] = pending{binding: binding, expiresAt: expires}
	m.mu.Unlock()
	if err := m.record("approval.request", "started", binding, map[string]string{
		"nonce": nonce, "summary_digest": fmt.Sprintf("%x", sha256.Sum256([]byte(summary))),
	}); err != nil {
		m.mu.Lock()
		delete(m.pending, id)
		m.mu.Unlock()
		return Request{}, err
	}
	display := fmt.Sprintf("Project: %s\nBaseline: %s\nMerged: %s\nChange Set: %s\nSummary: %s\nNonce: %s",
		SanitizeText(binding.ProjectID), binding.BaselineDigest, binding.MergedDigest, binding.ChangeSetDigest,
		SanitizeText(summary), nonce)
	return Request{Nonce: nonce, Binding: binding, ExpiresAt: expires, Summary: SanitizeText(summary), Display: display}, nil
}

func ValidateBinding(binding Binding) error { return validateBinding(binding) }

func (m *Manager) Confirm(nonce string, presented Binding) (*Grant, error) {
	id := sha256.Sum256([]byte(nonce))
	m.mu.Lock()
	defer m.mu.Unlock()
	item, ok := m.pending[id]
	delete(m.pending, id)
	if !ok || !m.now().Before(item.expiresAt) || !equalBinding(item.binding, presented) {
		_ = m.record("approval.confirm", "rejected", presented, map[string]string{"nonce": nonce, "reason": "invalid_expired_or_substituted"})
		return nil, ErrApprovalInvalid
	}
	grantIDBytes := make([]byte, 32)
	if _, err := rand.Read(grantIDBytes); err != nil {
		return nil, err
	}
	grantID := sha256.Sum256(grantIDBytes)
	if err := m.record("approval.confirm", "success", presented, map[string]string{"nonce": nonce}); err != nil {
		return nil, err
	}
	m.grants[grantID] = item.binding
	return &Grant{id: grantID, binding: item.binding}, nil
}

func (m *Manager) Consume(grant *Grant, expected Binding) error {
	if grant == nil {
		return ErrApprovalInvalid
	}
	m.mu.Lock()
	defer m.mu.Unlock()
	binding, ok := m.grants[grant.id]
	delete(m.grants, grant.id)
	if !ok || !equalBinding(binding, expected) || !equalBinding(grant.binding, expected) {
		_ = m.record("approval.consume", "rejected", expected, map[string]string{"reason": "invalid_or_reused"})
		return ErrApprovalInvalid
	}
	return m.record("approval.consume", "success", expected, nil)
}

func (m *Manager) record(action, outcome string, binding Binding, extra map[string]string) error {
	if m.audit == nil {
		return nil
	}
	if binding.ProjectID != m.project {
		return fmt.Errorf("approval audit Project identity mismatch")
	}
	details := map[string]string{
		"baseline_digest": binding.BaselineDigest, "merged_digest": binding.MergedDigest, "change_set_digest": binding.ChangeSetDigest,
	}
	for key, value := range extra {
		details[key] = value
	}
	return m.audit.Append(audit.BoundaryEvent{
		Category: "approval", Action: action, Outcome: outcome, ProjectID: m.project,
		VMID: m.vm, SessionID: m.session, Details: details,
	})
}

func validateBinding(binding Binding) error {
	if binding.ProjectID == "" || len(binding.BaselineDigest) != 64 || len(binding.MergedDigest) != 64 || len(binding.ChangeSetDigest) != 64 {
		return fmt.Errorf("approval binding is incomplete")
	}
	return nil
}

func equalBinding(left, right Binding) bool {
	leftHash := sha256.Sum256([]byte(left.ProjectID + "\x00" + left.BaselineDigest + "\x00" + left.MergedDigest + "\x00" + left.ChangeSetDigest))
	rightHash := sha256.Sum256([]byte(right.ProjectID + "\x00" + right.BaselineDigest + "\x00" + right.MergedDigest + "\x00" + right.ChangeSetDigest))
	return subtle.ConstantTimeCompare(leftHash[:], rightHash[:]) == 1
}

func SanitizeText(text string) string {
	var output strings.Builder
	for len(text) > 0 {
		r, size := utf8.DecodeRuneInString(text)
		if r == utf8.RuneError && size == 1 {
			output.WriteString("<INVALID-UTF8>")
			text = text[1:]
			continue
		}
		if r == '\n' {
			output.WriteString("<U+000A>")
		} else if r == '\r' || r == '\t' || r == 0x1b || r == 0x7f || (r >= 0 && r < 0x20) || (r >= 0x80 && r <= 0x9f) || r == 0x200e || r == 0x200f || (r >= 0x202a && r <= 0x202e) || (r >= 0x2066 && r <= 0x2069) {
			fmt.Fprintf(&output, "<U+%04X>", r)
		} else {
			output.WriteRune(r)
		}
		text = text[size:]
	}
	return output.String()
}
