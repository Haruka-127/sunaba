package trustedui

import (
	"bytes"
	"errors"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"sunaba/internal/approval"
	"sunaba/internal/audit"
	"sunaba/internal/gitgateway"
)

func TestConfirmApplyRendersStructuredSanitizedHostUI(t *testing.T) {
	manager := approval.NewManager(nil)
	binding := approval.Binding{ProjectID: "project", BaselineDigest: strings.Repeat("a", 64), MergedDigest: strings.Repeat("b", 64), ChangeSetDigest: strings.Repeat("c", 64)}
	request, err := manager.NewRequest(binding, "evil\x1b]52;c;fake\a\n\u202e.txt", time.Minute)
	if err != nil {
		t.Fatal(err)
	}
	var output bytes.Buffer
	if err := ConfirmApply(strings.NewReader(request.Nonce+"\n"), &output, request); err != nil {
		t.Fatal(err)
	}
	text := output.String()
	for _, unsafe := range []string{"\x1b", "\a", "\u202e"} {
		if strings.Contains(text, unsafe) {
			t.Fatalf("Trusted UI retained unsafe content %q: %q", unsafe, text)
		}
	}
	for _, required := range []string{"SUNABA HOST TRUSTED APPROVAL", binding.ProjectID, binding.BaselineDigest, binding.MergedDigest, binding.ChangeSetDigest, request.Nonce, "<U+001B>", "Approved by host input"} {
		if !strings.Contains(text, required) {
			t.Fatalf("Trusted UI missing %q: %q", required, text)
		}
	}
}

func TestSanitizeTerminalPreservesLinesAndEscapesHostActions(t *testing.T) {
	input := "line one\n\x1b]52;c;clipboard\a\u202Eevil\xff\n"
	got := SanitizeTerminal(input)
	if !strings.Contains(got, "line one\n") || !strings.Contains(got, "<U+001B>]52;c;clipboard<U+0007>") || !strings.Contains(got, "<U+202E>evil<INVALID-UTF8>") {
		t.Fatalf("sanitized terminal output=%q", got)
	}
	if strings.ContainsRune(got, '\x1b') || strings.ContainsRune(got, '\a') || strings.ContainsRune(got, '\u202e') {
		t.Fatal("terminal action survived sanitization")
	}
}

func TestConfirmPushDisplaysObjectForceAndDeleteBinding(t *testing.T) {
	request := gitgateway.PushRequest{
		Nonce: strings.Repeat("n", 43), Digest: "",
		ExpiresAt: time.Now().Add(time.Minute),
		Binding: gitgateway.PushBinding{
			ProjectID: "project", Repository: "repository", RemoteName: "origin", RemoteURL: "https://example.com/repository.git",
			Updates: []gitgateway.RefUpdate{
				{Ref: "refs/heads/main", Old: strings.Repeat("a", 40), New: strings.Repeat("b", 40), Force: true},
				{Ref: "refs/heads/obsolete", Old: strings.Repeat("c", 40), New: strings.Repeat("0", 40), Delete: true},
			},
		},
	}
	request.Digest = pushRequestDigest(t, request)
	var output bytes.Buffer
	if err := ConfirmPush(strings.NewReader(request.Nonce+"\n"), &output, request); err != nil {
		t.Fatal(err)
	}
	text := output.String()
	for _, required := range []string{"Operation: Git push", request.Binding.RemoteURL, request.Digest, "refs/heads/main", "Force: true", "refs/heads/obsolete", "Delete: true", "Approved by host input"} {
		if !strings.Contains(text, required) {
			t.Fatalf("Trusted Git UI missing %q: %q", required, text)
		}
	}
	changed := request
	changed.Digest = strings.Repeat("f", 64)
	if err := ConfirmPush(strings.NewReader(changed.Nonce+"\n"), ioDiscard{}, changed); err == nil {
		t.Fatal("Trusted Git UI accepted mismatched digest")
	}
}

func pushRequestDigest(t *testing.T, request gitgateway.PushRequest) string {
	t.Helper()
	recorder, err := audit.NewRecorder(filepath.Join(t.TempDir(), "audit"))
	if err != nil {
		t.Fatal(err)
	}
	manager, err := gitgateway.NewPushApprovalManager(nil, recorder, "vm", "session")
	if err != nil {
		t.Fatal(err)
	}
	generated, err := manager.NewRequest(request.Binding, time.Minute)
	if err != nil {
		t.Fatal(err)
	}
	return generated.Digest
}

func TestConfirmApplyRejectsAnythingExceptExactBoundedNonce(t *testing.T) {
	manager := approval.NewManager(nil)
	binding := approval.Binding{ProjectID: "project", BaselineDigest: strings.Repeat("a", 64), MergedDigest: strings.Repeat("b", 64), ChangeSetDigest: strings.Repeat("c", 64)}
	request, err := manager.NewRequest(binding, "safe", time.Minute)
	if err != nil {
		t.Fatal(err)
	}
	for _, input := range []string{"yes\n", " " + request.Nonce + "\n", request.Nonce + " extra\n", request.Nonce + "\x1b\n", strings.Repeat("x", 600)} {
		if err := ConfirmApply(strings.NewReader(input), ioDiscard{}, request); !errors.Is(err, ErrRejected) {
			t.Fatalf("input %q error=%v", input, err)
		}
	}
}

type ioDiscard struct{}

func (ioDiscard) Write(p []byte) (int, error) { return len(p), nil }
