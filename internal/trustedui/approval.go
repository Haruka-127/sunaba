package trustedui

import (
	"bufio"
	"crypto/sha256"
	"crypto/subtle"
	"errors"
	"fmt"
	"io"
	"strings"

	"sunaba/internal/approval"
)

var ErrRejected = errors.New("host approval was rejected")

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
	expected := sha256.Sum256([]byte(request.Nonce))
	if subtle.ConstantTimeCompare(presented[:], expected[:]) != 1 {
		return ErrRejected
	}
	_, err = io.WriteString(output, "Approved by host input.\n")
	return err
}
