package trustedui

import (
	"fmt"
	"io"
	"strconv"
	"strings"

	"sunaba/internal/terminal"
	"sunaba/internal/workspace"
)

func RenderChangeReview(output io.Writer, projectID string, review workspace.Review) error {
	if output == nil || projectID == "" || len(review.ChangeSetDigest) != 64 || len(review.BaselineDigest) != 64 || len(review.MergedDigest) != 64 {
		return fmt.Errorf("invalid Change Set review")
	}
	if _, err := fmt.Fprintf(output,
		"SUNABA HOST CHANGE SET REVIEW\nProject: %s\nBaseline: %s\nMerged: %s\nChange Set: %s\nChanges: add=%d modify=%d delete=%d rename=%d\nRisk summary: executable=%d symlink=%d opaque=%d omitted=%d\n",
		quoteReviewText(projectID), review.BaselineDigest, review.MergedDigest, review.ChangeSetDigest,
		review.Counts.Add, review.Counts.Modify, review.Counts.Delete, review.Counts.Rename,
		review.Executable, review.Symlink, review.Opaque, review.Omitted,
	); err != nil {
		return err
	}
	if review.Filtered {
		if _, err := io.WriteString(output, "WARNING: this is a filtered view; changes apply still applies the entire Change Set.\n"); err != nil {
			return err
		}
	}
	if review.BaselineMissing {
		if _, err := io.WriteString(output, "WARNING: this legacy pending Change Set has no saved baseline content and the host baseline changed; only metadata can be reviewed and apply will be rejected.\n"); err != nil {
			return err
		}
	}
	if review.StatOnly {
		if _, err := io.WriteString(output, "Content diff omitted by --stat.\n"); err != nil {
			return err
		}
	}
	for _, item := range review.Items {
		if err := renderReviewItem(output, item); err != nil {
			return err
		}
	}
	if review.Opaque > 0 {
		if _, err := fmt.Fprintf(output, "WARNING: %d change(s) contain content that was not rendered; review their type, size, mode, and SHA-256 before approval.\n", review.Opaque); err != nil {
			return err
		}
	}
	if review.Omitted > 0 {
		_, err := fmt.Fprintf(output, "WARNING: %d change(s) were omitted by the bounded display limit; use --path with an exact Change Set path to review an omitted item.\n", review.Omitted)
		return err
	}
	return nil
}

func renderReviewItem(output io.Writer, item workspace.ReviewItem) error {
	change := item.Change
	if change.Kind == workspace.ChangeRename {
		if _, err := fmt.Fprintf(output, "\nChange: rename %s <- %s\n", quoteReviewText(change.Path), quoteReviewText(change.From)); err != nil {
			return err
		}
	} else if _, err := fmt.Fprintf(output, "\nChange: %s %s\n", change.Kind, quoteReviewText(change.Path)); err != nil {
		return err
	}
	if _, err := fmt.Fprintf(output, "Before: %s\nAfter:  %s\n", renderEntry(change.Before), renderEntry(change.After)); err != nil {
		return err
	}
	if item.OpaqueReason != "" {
		if _, err := fmt.Fprintf(output, "Content: NOT RENDERED (%s)\n", terminal.SingleLine(item.OpaqueReason)); err != nil {
			return err
		}
	}
	if len(item.Hunks) == 0 {
		return nil
	}
	if _, err := fmt.Fprintf(output, "--- %s\n+++ %s\n", reviewSidePath("a", change.Before), reviewSidePath("b", change.After)); err != nil {
		return err
	}
	for _, hunk := range item.Hunks {
		if _, err := fmt.Fprintf(output, "@@ -%d,%d +%d,%d @@\n", hunk.OldStart, hunk.OldLines, hunk.NewStart, hunk.NewLines); err != nil {
			return err
		}
		for _, line := range hunk.Lines {
			hasNewline := strings.HasSuffix(line.Text, "\n")
			content := strings.TrimSuffix(line.Text, "\n")
			if _, err := fmt.Fprintf(output, "%c%s\n", line.Kind, terminal.SingleLine(content)); err != nil {
				return err
			}
			if !hasNewline {
				if _, err := io.WriteString(output, "\\ No newline at end of file\n"); err != nil {
					return err
				}
			}
		}
	}
	return nil
}

func renderEntry(entry *workspace.SnapshotEntry) string {
	if entry == nil {
		return "absent"
	}
	switch entry.Type {
	case workspace.TypeFile:
		return fmt.Sprintf("file mode=%04o size=%d sha256=%s", entry.Mode, entry.Size, entry.SHA256)
	case workspace.TypeDirectory:
		return fmt.Sprintf("directory mode=%04o", entry.Mode)
	case workspace.TypeSymlink:
		return fmt.Sprintf("symlink target=%s", quoteReviewText(entry.LinkTarget))
	default:
		return "unsupported"
	}
}

func reviewSidePath(prefix string, entry *workspace.SnapshotEntry) string {
	if entry == nil {
		return "/dev/null"
	}
	return quoteReviewText(prefix + "/" + entry.Path)
}

func quoteReviewText(value string) string {
	return strconv.Quote(terminal.SingleLine(value))
}
