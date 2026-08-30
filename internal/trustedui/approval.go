package trustedui

import (
	"bufio"
	"errors"
	"fmt"
	"io"
	"strconv"
	"strings"

	"sunaba/internal/approval"
	"sunaba/internal/gitgateway"
	"sunaba/internal/terminal"
)

var ErrRejected = errors.New("host approval was rejected")

// SanitizeTerminal preserves ordinary line-oriented output while escaping
// terminal controls, invalid UTF-8, and bidirectional display controls.
func SanitizeTerminal(text string) string {
	return terminal.Multiline(text)
}

// SelectPush renders every host-validated request, then binds a simple
// approve/reject choice to its internally held nonce. The nonce is never typed
// or copied by the user.
func SelectPush(input io.Reader, output io.Writer, requests []gitgateway.PushRequest) (int, string, error) {
	if input == nil || output == nil || len(requests) == 0 || len(requests) > 128 {
		return 0, "", fmt.Errorf("invalid Trusted Git push selection")
	}
	if _, err := io.WriteString(output, "SUNABA HOST TRUSTED APPROVALS\n"); err != nil {
		return 0, "", err
	}
	for index, request := range requests {
		if gitgateway.ValidatePushRequest(request) != nil {
			return 0, "", fmt.Errorf("invalid Trusted Git push approval request")
		}
		if _, err := fmt.Fprintf(output, "[%d] ID %s  %s -> %s  expires %s\n", index+1, request.Digest[:12], approval.SanitizeText(request.Binding.Repository), approval.SanitizeText(request.Binding.RemoteURL), request.ExpiresAt.UTC().Format("2006-01-02T15:04:05Z")); err != nil {
			return 0, "", err
		}
		for _, update := range request.Binding.Updates {
			if _, err := fmt.Fprintf(output, "    %s  %s -> %s  force=%t delete=%t\n", approval.SanitizeText(update.Ref), update.Old, update.New, update.Force, update.Delete); err != nil {
				return 0, "", err
			}
		}
	}
	if _, err := io.WriteString(output, "Choose 'approve <number-or-ID>', 'reject <number-or-ID>', or 'skip': "); err != nil {
		return 0, "", err
	}
	reader := bufio.NewReader(io.LimitReader(input, 514))
	line, err := reader.ReadString('\n')
	if err != nil && !errors.Is(err, io.EOF) {
		return 0, "", err
	}
	line = strings.TrimSpace(line)
	if line == "skip" || line == "" {
		fmt.Fprintln(output, "Skipped without changing pending requests.")
		return 0, "skip", nil
	}
	fields := strings.Fields(line)
	if len(fields) != 2 || (fields[0] != "approve" && fields[0] != "reject") {
		return 0, "", ErrRejected
	}
	selected := -1
	if number, parseErr := strconv.Atoi(fields[1]); parseErr == nil && number >= 1 && number <= len(requests) {
		selected = number - 1
	} else {
		for index, request := range requests {
			if fields[1] == request.Digest || (len(fields[1]) >= 12 && strings.HasPrefix(request.Digest, fields[1])) {
				if selected >= 0 {
					return 0, "", ErrRejected
				}
				selected = index
			}
		}
	}
	if selected < 0 {
		return 0, "", ErrRejected
	}
	label := "Approved"
	if fields[0] == "reject" {
		label = "Rejected"
	}
	if _, err := fmt.Fprintf(output, "%s request %s by host selection.\n", label, requests[selected].Digest[:12]); err != nil {
		return 0, "", err
	}
	return selected, fields[0], nil
}

func ConfirmApply(input io.Reader, output io.Writer, request approval.Request) error {
	if input == nil || output == nil || approval.ValidateBinding(request.Binding) != nil || len(request.Nonce) < 32 || request.ExpiresAt.IsZero() {
		return fmt.Errorf("invalid Trusted Approval request")
	}
	summary := approval.SanitizeText(request.Summary)
	if _, err := fmt.Fprintf(output,
		"SUNABA HOST TRUSTED APPROVAL\nOperation: apply all changes\nProject: %s\nBaseline: %s\nMerged: %s\nChange Set: %s\nSummary: %s\nExpires: %s\nApply the entire displayed Change Set? Type 'apply all changes' to approve: ",
		approval.SanitizeText(request.Binding.ProjectID), request.Binding.BaselineDigest, request.Binding.MergedDigest,
		request.Binding.ChangeSetDigest, summary, request.ExpiresAt.UTC().Format("2006-01-02T15:04:05Z"),
	); err != nil {
		return err
	}
	return confirmApplyAll(input, output)
}

func confirmApplyAll(input io.Reader, output io.Writer) error {
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
	if line != "apply all changes" {
		return ErrRejected
	}
	_, err = io.WriteString(output, "Approved the entire displayed Change Set by host input.\n")
	return err
}
