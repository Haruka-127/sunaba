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
	if err := ConfirmApply(strings.NewReader("apply all changes\n"), &output, request); err != nil {
		t.Fatal(err)
	}
	text := output.String()
	for _, unsafe := range []string{"\x1b", "\a", "\u202e"} {
		if strings.Contains(text, unsafe) {
			t.Fatalf("Trusted UI retained unsafe content %q: %q", unsafe, text)
		}
	}
	for _, required := range []string{"SUNABA HOST TRUSTED APPROVAL", binding.ProjectID, binding.BaselineDigest, binding.MergedDigest, binding.ChangeSetDigest, "<U+001B>", "Approved the entire displayed Change Set"} {
		if !strings.Contains(text, required) {
			t.Fatalf("Trusted UI missing %q: %q", required, text)
		}
	}
	if strings.Contains(text, request.Nonce) {
		t.Fatalf("Trusted UI exposed internal nonce: %q", text)
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

func TestSelectPushBindsNumberOrIDWithoutNonceInput(t *testing.T) {
	request := gitgateway.PushRequest{
		Nonce: strings.Repeat("n", 43), ExpiresAt: time.Now().Add(time.Minute),
		Binding: gitgateway.PushBinding{ProjectID: "project", Repository: "repository", RemoteName: "origin", RemoteURL: "https://example.com/repository.git", Updates: []gitgateway.RefUpdate{{Ref: "refs/heads/main", Old: strings.Repeat("a", 40), New: strings.Repeat("b", 40)}}},
	}
	request.Digest = pushRequestDigest(t, request)
	var output bytes.Buffer
	index, decision, err := SelectPush(strings.NewReader("approve 1\n"), &output, []gitgateway.PushRequest{request})
	if err != nil || index != 0 || decision != "approve" {
		t.Fatalf("selection index=%d decision=%q error=%v", index, decision, err)
	}
	if strings.Contains(output.String(), request.Nonce) || !strings.Contains(output.String(), request.Digest[:12]) {
		t.Fatalf("selection output exposed nonce or omitted ID: %s", output.String())
	}
	index, decision, err = SelectPush(strings.NewReader("reject "+request.Digest[:12]+"\n"), ioDiscard{}, []gitgateway.PushRequest{request})
	if err != nil || index != 0 || decision != "reject" {
		t.Fatalf("ID selection index=%d decision=%q error=%v", index, decision, err)
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

func TestConfirmApplyRejectsAnythingExceptExactBoundedAction(t *testing.T) {
	manager := approval.NewManager(nil)
	binding := approval.Binding{ProjectID: "project", BaselineDigest: strings.Repeat("a", 64), MergedDigest: strings.Repeat("b", 64), ChangeSetDigest: strings.Repeat("c", 64)}
	request, err := manager.NewRequest(binding, "safe", time.Minute)
	if err != nil {
		t.Fatal(err)
	}
	for _, input := range []string{"yes\n", " apply all changes\n", "apply all changes extra\n", "apply all changes\x1b\n", request.Nonce + "\n", strings.Repeat("x", 600)} {
		if err := ConfirmApply(strings.NewReader(input), ioDiscard{}, request); !errors.Is(err, ErrRejected) {
			t.Fatalf("input %q error=%v", input, err)
		}
	}
}

type ioDiscard struct{}

func (ioDiscard) Write(p []byte) (int, error) { return len(p), nil }
