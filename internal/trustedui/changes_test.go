package trustedui

import (
	"bytes"
	"strings"
	"testing"

	"sunaba/internal/workspace"
)

func TestRenderChangeReviewEscapesUntrustedPathsTargetsAndDiff(t *testing.T) {
	digest := strings.Repeat("a", 64)
	review := workspace.Review{
		BaselineDigest: digest, MergedDigest: strings.Repeat("b", 64), ChangeSetDigest: strings.Repeat("c", 64),
		Counts: workspace.ReviewCounts{Modify: 1}, Symlink: 1,
		Items: []workspace.ReviewItem{{
			Change: workspace.Change{
				Kind: workspace.ChangeModify, Path: "evil\x1b]52;c;path\a\u202e.txt",
				Before: &workspace.SnapshotEntry{Path: "evil", Type: workspace.TypeFile, Mode: 0644, Size: 4, SHA256: digest},
				After:  &workspace.SnapshotEntry{Path: "evil", Type: workspace.TypeSymlink, Mode: 0777, LinkTarget: "target\n\x1b"},
			},
			Hunks: []workspace.ReviewHunk{{OldStart: 1, OldLines: 1, NewStart: 1, NewLines: 1, Lines: []workspace.ReviewLine{
				{Kind: '-', Text: "old\x1b\n"}, {Kind: '+', Text: "new\u202e"},
			}}},
		}},
	}
	var output bytes.Buffer
	if err := RenderChangeReview(&output, "project", review); err != nil {
		t.Fatal(err)
	}
	text := output.String()
	for _, unsafe := range []string{"\x1b", "\a", "\u202e"} {
		if strings.Contains(text, unsafe) {
			t.Fatalf("review retained unsafe content %q: %q", unsafe, text)
		}
	}
	for _, expected := range []string{"SUNABA HOST CHANGE SET REVIEW", "<U+001B>", "<U+0007>", "<U+202E>", "No newline at end of file", "target=\"target<U+000A><U+001B>\""} {
		if !strings.Contains(text, expected) {
			t.Fatalf("review missing %q: %q", expected, text)
		}
	}
}
