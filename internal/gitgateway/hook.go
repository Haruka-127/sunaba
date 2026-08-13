package gitgateway

import (
	"bufio"
	"context"
	"crypto/sha256"
	"crypto/subtle"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"net"
	"os"
	"path/filepath"
	"sort"
	"strings"
	"sync"
	"time"

	"golang.org/x/sys/unix"

	"sunaba/internal/terminal"
)

const maxHookMessageBytes = 256 << 10

type HookRequest struct {
	Token           string              `json:"token"`
	ObjectDirectory string              `json:"object_directory"`
	Updates         []ProposedRefUpdate `json:"updates"`
}

type HookResponse struct {
	Accept  bool   `json:"accept"`
	Message string `json:"message"`
}

type HookBroker struct {
	Approvals *PushApprovalManager
	Executor  PushExecutor
	Lifetime  time.Duration
	Now       func() time.Time

	tokenHash [sha256.Size]byte
	listener  net.Listener
	mu        sync.Mutex
	pending   map[string]PushRequest
	byDigest  map[string]string
	approved  map[string]*PushGrant
	closeOnce sync.Once
	closeErr  error
}

func StartHookBroker(ctx context.Context, socketPath, token string, approvals *PushApprovalManager, executor PushExecutor, lifetime time.Duration, now func() time.Time) (*HookBroker, error) {
	if !filepathIsPrivateSocketParent(socketPath) {
		return nil, fmt.Errorf("Git hook broker requires a private canonical socket parent")
	}
	if len(token) < 32 || approvals == nil || executor.Approvals != approvals || lifetime <= 0 || lifetime > 5*time.Minute {
		return nil, fmt.Errorf("Git hook broker identity, approval manager, or lifetime is invalid")
	}
	if info, err := os.Lstat(socketPath); err == nil {
		if info.Mode()&os.ModeSocket == 0 {
			return nil, fmt.Errorf("Git hook broker socket path was replaced with a non-socket")
		}
		if err := os.Remove(socketPath); err != nil {
			return nil, err
		}
	} else if !errors.Is(err, os.ErrNotExist) {
		return nil, err
	}
	listener, err := net.Listen("unix", socketPath)
	if err != nil {
		return nil, err
	}
	if err := os.Chmod(socketPath, 0600); err != nil {
		listener.Close()
		return nil, err
	}
	if now == nil {
		now = time.Now
	}
	broker := &HookBroker{
		Approvals: approvals, Executor: executor, Lifetime: lifetime, Now: now,
		tokenHash: sha256.Sum256([]byte(token)), listener: listener,
		pending: make(map[string]PushRequest), byDigest: make(map[string]string), approved: make(map[string]*PushGrant),
	}
	go broker.serve(ctx)
	return broker, nil
}

func (b *HookBroker) Pending() []PushRequest {
	b.mu.Lock()
	defer b.mu.Unlock()
	requests := make([]PushRequest, 0, len(b.pending))
	for _, request := range b.pending {
		requests = append(requests, request)
	}
	sort.Slice(requests, func(i, j int) bool { return requests[i].ExpiresAt.Before(requests[j].ExpiresAt) })
	return requests
}

func (b *HookBroker) Confirm(nonce string, presented PushBinding) error {
	b.mu.Lock()
	request, ok := b.pending[nonce]
	if ok {
		delete(b.pending, nonce)
		delete(b.byDigest, request.Digest)
	}
	b.mu.Unlock()
	if !ok {
		return ErrPushApprovalInvalid
	}
	grant, err := b.Approvals.Confirm(nonce, presented)
	if err != nil {
		return err
	}
	b.mu.Lock()
	b.approved[request.Digest] = grant
	b.mu.Unlock()
	return nil
}

func (b *HookBroker) Close() error {
	b.closeOnce.Do(func() { b.closeErr = b.listener.Close() })
	return b.closeErr
}

func (b *HookBroker) serve(ctx context.Context) {
	go func() {
		<-ctx.Done()
		_ = b.Close()
	}()
	for {
		connection, err := b.listener.Accept()
		if err != nil {
			return
		}
		go b.handleConnection(ctx, connection)
	}
}

func (b *HookBroker) handleConnection(ctx context.Context, connection net.Conn) {
	defer connection.Close()
	_ = connection.SetDeadline(time.Now().Add(30 * time.Second))
	decoder := json.NewDecoder(io.LimitReader(connection, maxHookMessageBytes))
	var request HookRequest
	if decoder.Decode(&request) != nil {
		_ = json.NewEncoder(connection).Encode(HookResponse{Message: "sunaba rejected invalid Git hook input"})
		return
	}
	response := b.handle(ctx, request)
	_ = json.NewEncoder(connection).Encode(response)
}

func (b *HookBroker) handle(ctx context.Context, request HookRequest) HookResponse {
	presented := sha256.Sum256([]byte(request.Token))
	if subtle.ConstantTimeCompare(presented[:], b.tokenHash[:]) != 1 || len(request.Updates) == 0 || len(request.Updates) > 128 {
		return HookResponse{Message: "sunaba rejected unauthorized Git hook input"}
	}
	resolver := b.Executor.Resolver
	resolver.ObjectDirectory = request.ObjectDirectory
	binding, err := resolver.Resolve(ctx, request.Updates)
	if err != nil {
		return HookResponse{Message: "sunaba rejected unsafe Git ref update"}
	}
	_, digest, _ := canonicalBinding(binding)
	b.mu.Lock()
	grant := b.approved[digest]
	if grant != nil {
		delete(b.approved, digest)
	}
	b.mu.Unlock()
	if grant != nil {
		executor := b.Executor
		executor.Resolver = resolver
		if err := executor.Execute(ctx, grant, request.Updates); err != nil {
			return HookResponse{Message: "sunaba rejected approved Git push during host revalidation"}
		}
		return HookResponse{Accept: true, Message: "sunaba accepted host-approved Git push"}
	}
	b.mu.Lock()
	now := b.Now()
	if nonce := b.byDigest[digest]; nonce != "" {
		if pending := b.pending[nonce]; now.Before(pending.ExpiresAt) {
			b.mu.Unlock()
			return HookResponse{Message: "sunaba Git push approval pending: " + nonce}
		}
		delete(b.pending, nonce)
		delete(b.byDigest, digest)
	}
	approvalRequest, err := b.Approvals.NewRequest(binding, b.Lifetime)
	if err != nil {
		b.mu.Unlock()
		return HookResponse{Message: "sunaba could not create Git push approval"}
	}
	b.pending[approvalRequest.Nonce] = approvalRequest
	b.byDigest[approvalRequest.Digest] = approvalRequest.Nonce
	b.mu.Unlock()
	return HookResponse{Message: "sunaba Git push approval pending: " + approvalRequest.Nonce}
}

func RunPreReceiveHook(socketPath, token, objectDirectory string, input io.Reader, output io.Writer) error {
	if socketPath == "" || len(token) < 32 {
		return fmt.Errorf("Git hook environment is incomplete")
	}
	scanner := bufio.NewScanner(io.LimitReader(input, maxHookMessageBytes))
	scanner.Buffer(make([]byte, 4096), 8192)
	request := HookRequest{Token: token, ObjectDirectory: objectDirectory}
	for scanner.Scan() {
		fields := strings.Fields(scanner.Text())
		if len(fields) != 3 || len(request.Updates) >= 128 {
			return fmt.Errorf("invalid Git pre-receive input")
		}
		request.Updates = append(request.Updates, ProposedRefUpdate{Old: fields[0], New: fields[1], Ref: fields[2]})
	}
	if err := scanner.Err(); err != nil || len(request.Updates) == 0 {
		return fmt.Errorf("invalid Git pre-receive input")
	}
	connection, err := net.DialTimeout("unix", socketPath, 3*time.Second)
	if err != nil {
		return fmt.Errorf("sunaba Git approval broker is unavailable")
	}
	defer connection.Close()
	_ = connection.SetDeadline(time.Now().Add(30 * time.Second))
	if err := json.NewEncoder(connection).Encode(request); err != nil {
		return fmt.Errorf("send Git approval request")
	}
	var response HookResponse
	if err := json.NewDecoder(io.LimitReader(connection, maxHookMessageBytes)).Decode(&response); err != nil {
		return fmt.Errorf("read Git approval response")
	}
	message := sanitizeHookMessage(response.Message)
	if message != "" {
		_, _ = fmt.Fprintln(output, message)
	}
	if !response.Accept {
		return fmt.Errorf("Git push requires host approval")
	}
	return nil
}

func sanitizeHookMessage(message string) string {
	return terminal.ASCIIHookMessage(message, 1024)
}

func filepathIsPrivateSocketParent(socketPath string) bool {
	if !filepath.IsAbs(socketPath) || filepath.Clean(socketPath) != socketPath || !strings.HasSuffix(socketPath, ".sock") {
		return false
	}
	parent := filepath.Dir(socketPath)
	info, err := os.Lstat(parent)
	var stat unix.Stat_t
	statErr := unix.Lstat(parent, &stat)
	canonical, canonicalErr := filepath.EvalSymlinks(parent)
	return err == nil && statErr == nil && canonicalErr == nil && canonical == parent && info.IsDir() && info.Mode().Perm() == 0700 && stat.Uid == uint32(os.Geteuid())
}
