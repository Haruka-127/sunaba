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
	"sunaba/internal/gitgateway"
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
