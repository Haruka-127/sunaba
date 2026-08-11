package trustedui

import (
	"bytes"
	"errors"
	"strings"
	"testing"
	"time"

	"sunaba/internal/approval"
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
