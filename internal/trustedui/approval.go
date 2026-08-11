package trustedui

import (
	"bufio"
	"crypto/sha256"
	"crypto/subtle"
	"errors"
	"fmt"
	"io"
	"strings"
	"unicode/utf8"

	"sunaba/internal/approval"
	"sunaba/internal/gitgateway"
)

var ErrRejected = errors.New("host approval was rejected")

// SanitizeTerminal preserves ordinary line-oriented output while escaping
// terminal controls, invalid UTF-8, and bidirectional display controls.
func SanitizeTerminal(text string) string {
	var output strings.Builder
	for len(text) > 0 {
		r, size := utf8.DecodeRuneInString(text)
		if r == utf8.RuneError && size == 1 {
			output.WriteString("<INVALID-UTF8>")
			text = text[1:]
			continue
		}
		switch {
		case r == '\n':
			output.WriteByte('\n')
		case r == '\r':
			output.WriteString("<U+000D>")
		case r == '\t':
			output.WriteString("<U+0009>")
		case r == 0x1b || r == 0x7f || (r >= 0 && r < 0x20) || (r >= 0x80 && r <= 0x9f) || r == 0x200e || r == 0x200f || (r >= 0x202a && r <= 0x202e) || (r >= 0x2066 && r <= 0x2069):
			fmt.Fprintf(&output, "<U+%04X>", r)
		default:
			output.WriteRune(r)
		}
		text = text[size:]
	}
	return output.String()
}

func ConfirmApply(input io.Reader, output io.Writer, request approval.Request) error {
	if input == nil || output == nil || approval.ValidateBinding(request.Binding) != nil || len(request.Nonce) < 32 || request.ExpiresAt.IsZero() {
		return fmt.Errorf("invalid Trusted Approval request")
	}
	summary := approval.SanitizeText(request.Summary)
	if _, err := fmt.Fprintf(output,
		"SUNABA HOST TRUSTED APPROVAL\nOperation: apply Change Set\nProject: %s\nBaseline: %s\nMerged: %s\nChange Set: %s\nSummary: %s\nExpires: %s\nNonce: %s\nType the nonce exactly to approve: ",
		approval.SanitizeText(request.Binding.ProjectID), request.Binding.BaselineDigest, request.Binding.MergedDigest,
		request.Binding.ChangeSetDigest, summary, request.ExpiresAt.UTC().Format("2006-01-02T15:04:05Z"), request.Nonce,
	); err != nil {
		return err
	}
	return confirmNonce(input, output, request.Nonce)
}

func ConfirmPush(input io.Reader, output io.Writer, request gitgateway.PushRequest) error {
	if input == nil || output == nil || gitgateway.ValidatePushRequest(request) != nil {
		return fmt.Errorf("invalid Trusted Git push approval request")
	}
	if _, err := fmt.Fprintf(output,
		"SUNABA HOST TRUSTED APPROVAL\nOperation: Git push\nProject: %s\nRepository: %s\nRemote: %s\nDestination: %s\nPush digest: %s\nExpires: %s\n",
		approval.SanitizeText(request.Binding.ProjectID), approval.SanitizeText(request.Binding.Repository),
		approval.SanitizeText(request.Binding.RemoteName), approval.SanitizeText(request.Binding.RemoteURL),
		request.Digest, request.ExpiresAt.UTC().Format("2006-01-02T15:04:05Z"),
	); err != nil {
		return err
	}
	for _, update := range request.Binding.Updates {
		if _, err := fmt.Fprintf(output, "Ref: %s\n  Old: %s\n  New: %s\n  Force: %t\n  Delete: %t\n", approval.SanitizeText(update.Ref), update.Old, update.New, update.Force, update.Delete); err != nil {
			return err
		}
	}
	if _, err := fmt.Fprintf(output, "Nonce: %s\nType the nonce exactly to approve: ", request.Nonce); err != nil {
		return err
	}
	return confirmNonce(input, output, request.Nonce)
}

func confirmNonce(input io.Reader, output io.Writer, nonce string) error {
	reader := bufio.NewReader(io.LimitReader(input, 514))
	line, err := reader.ReadString('\n')
	if err != nil && !errors.Is(err, io.EOF) {
		return err
	}
	if len(line) > 513 || (len(line) == 513 && !strings.HasSuffix(line, "\n")) {
		return ErrRejected
	}
	line = strings.TrimSuffix(line, "\n")
	line = strings.TrimSuffix(line, "\r")
	if strings.ContainsAny(line, "\x00\n\r\t\x1b") {
		return ErrRejected
	}
	presented := sha256.Sum256([]byte(line))
	expected := sha256.Sum256([]byte(nonce))
	if subtle.ConstantTimeCompare(presented[:], expected[:]) != 1 {
		return ErrRejected
	}
	_, err = io.WriteString(output, "Approved by host input.\n")
	return err
}
