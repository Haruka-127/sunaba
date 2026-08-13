package capability

import (
	"crypto/sha256"
	"crypto/subtle"
	"fmt"
	"regexp"
	"sync"
	"sync/atomic"
	"time"
)

var identityPattern = regexp.MustCompile(`^[a-zA-Z0-9][a-zA-Z0-9._-]{0,127}$`)

type Binding struct {
	ProjectID string
	VMID      string
	SessionID string
}

func ValidateBinding(binding Binding) error {
	if !identityPattern.MatchString(binding.ProjectID) || !identityPattern.MatchString(binding.VMID) || !identityPattern.MatchString(binding.SessionID) {
		return fmt.Errorf("capability identity binding is invalid")
	}
	return nil
}

type Authority struct {
	binding   Binding
	tokenHash [sha256.Size]byte
	revoked   atomic.Bool
}

func NewAuthority(token string, binding Binding, expiresAt time.Time) (*Authority, error) {
	if len(token) < 32 || expiresAt.IsZero() || ValidateBinding(binding) != nil {
		return nil, fmt.Errorf("capability requires a high-entropy token, expiry, and canonical identity binding")
	}
	return &Authority{binding: binding, tokenHash: sha256.Sum256([]byte(token))}, nil
}

func (authority *Authority) Matches(binding Binding) bool {
	return authority != nil && authority.binding == binding
}

func (authority *Authority) Revoke() {
	if authority != nil {
		authority.revoked.Store(true)
	}
}

type Status uint8

const (
	Admitted Status = iota
	Revoked
	Expired
	InvalidToken
	RequestQuotaExceeded
	ConcurrencyExceeded
)

type Gate struct {
	authority   *Authority
	expiresAt   time.Time
	maxRequests int64
	requests    atomic.Int64
	concurrency chan struct{}
}

func NewGate(authority *Authority, expiresAt time.Time, maxRequests, maxConcurrent int) (*Gate, error) {
	if authority == nil || expiresAt.IsZero() || maxRequests <= 0 || maxConcurrent <= 0 {
		return nil, fmt.Errorf("capability admission limits are invalid")
	}
	return &Gate{authority: authority, expiresAt: expiresAt, maxRequests: int64(maxRequests), concurrency: make(chan struct{}, maxConcurrent)}, nil
}

func (gate *Gate) Admit(token string, now time.Time) (*Lease, Status) {
	if gate == nil || gate.authority == nil || gate.authority.revoked.Load() {
		return nil, Revoked
	}
	presented := sha256.Sum256([]byte(token))
	if subtle.ConstantTimeCompare(presented[:], gate.authority.tokenHash[:]) != 1 {
		return nil, InvalidToken
	}
	if !now.Before(gate.expiresAt) {
		return nil, Expired
	}
	if gate.requests.Add(1) > gate.maxRequests {
		return nil, RequestQuotaExceeded
	}
	select {
	case gate.concurrency <- struct{}{}:
		return &Lease{release: func() { <-gate.concurrency }}, Admitted
	default:
		return nil, ConcurrencyExceeded
	}
}

func (gate *Gate) Revoke() {
	if gate != nil {
		gate.authority.Revoke()
	}
}

type Lease struct {
	once    sync.Once
	release func()
}

func (lease *Lease) Release() {
	if lease != nil {
		lease.once.Do(lease.release)
	}
}
