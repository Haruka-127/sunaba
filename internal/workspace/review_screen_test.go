package workspace

import (
	"strings"
	"testing"
)

func TestBuildReviewScreenUsesChangedFilesAndResponsiveLayouts(t *testing.T) {
	review := Review{ChangeSetDigest: strings.Repeat("a", 64), Items: []ReviewItem{
		{Change: Change{Kind: ChangeModify, Path: "code.go", Before: &SnapshotEntry{Path: "code.go", Mode: 0644}, After: &SnapshotEntry{Path: "code.go", Mode: 0755}}, Executable: true, Hunks: []ReviewHunk{{OldStart: 1, OldLines: 2, NewStart: 1, NewLines: 2, Lines: []ReviewLine{{Kind: ' ', Text: "same\n"}, {Kind: '-', Text: "old\n"}, {Kind: '+', Text: "new\n"}}}}},
		{Change: Change{Kind: ChangeRename, Path: "new.txt", From: "old.txt"}, Binary: true, OpaqueReason: "binary"},
	}}
	narrow, err := BuildReviewScreen(review, 80, "new.txt")
	if err != nil || narrow.Layout != ReviewLayoutUnified || narrow.Selected != 1 || narrow.Files[0].Status != "M" || narrow.Files[1].Status != "R" {
		t.Fatalf("narrow screen=%+v error=%v", narrow, err)
	}
	if strings.Join(narrow.Files[0].Risks, ",") != "executable,mode-change" || strings.Join(narrow.Files[1].Risks, ",") != "binary" {
		t.Fatalf("risk classification=%+v", narrow.Files)
	}
	wide, err := BuildReviewScreen(review, WideReviewMinimumWidth, "code.go")
	if err != nil || wide.Layout != ReviewLayoutSideBySide || len(wide.Unified) != 4 || len(wide.SideBySide) != 3 {
		t.Fatalf("wide screen=%+v error=%v", wide, err)
	}
	if wide.SideBySide[1].BeforeLine != 1 || wide.SideBySide[1].AfterLine != 1 || wide.SideBySide[2].BeforeKind != '-' || wide.SideBySide[2].BeforeLine != 2 || wide.SideBySide[2].Before != "old" || wide.SideBySide[2].AfterKind != '+' || wide.SideBySide[2].AfterLine != 2 || wide.SideBySide[2].After != "new" {
		t.Fatalf("side-by-side replacement=%+v", wide.SideBySide[2])
	}
	if wide.Unified[1].OldLine != 1 || wide.Unified[1].NewLine != 1 || wide.Unified[2].OldLine != 2 || strings.Contains(wide.Unified[2].Text, "\n") {
		t.Fatalf("unified line metadata=%+v", wide.Unified)
	}
}

func TestBuildReviewScreenRejectsUnknownSelectionAndInvalidWidth(t *testing.T) {
	review := Review{ChangeSetDigest: strings.Repeat("a", 64), Items: []ReviewItem{{Change: Change{Kind: ChangeAdd, Path: "one.txt"}}}}
	if _, err := BuildReviewScreen(review, 0, ""); err == nil {
		t.Fatal("zero width was accepted")
	}
	if _, err := BuildReviewScreen(review, 80, "missing.txt"); err == nil {
		t.Fatal("unknown selected path was accepted")
	}
}

func TestBuildReviewScreenDisclosesSymlinkTargets(t *testing.T) {
	review := Review{ChangeSetDigest: strings.Repeat("a", 64), Items: []ReviewItem{
		{Change: Change{Kind: ChangeAdd, Path: "added-link", After: &SnapshotEntry{Path: "added-link", Type: TypeSymlink, LinkTarget: "../../../.ssh/id_ed25519"}}, Symlink: true},
		{Change: Change{Kind: ChangeModify, Path: "retargeted-link", Before: &SnapshotEntry{Path: "retargeted-link", Type: TypeSymlink, LinkTarget: "docs"}, After: &SnapshotEntry{Path: "retargeted-link", Type: TypeSymlink, LinkTarget: "/etc/passwd"}}, Symlink: true},
		{Change: Change{Kind: ChangeDelete, Path: "removed-link", Before: &SnapshotEntry{Path: "removed-link", Type: TypeSymlink, LinkTarget: "old-target"}}, Symlink: true},
	}}
	screen, err := BuildReviewScreen(review, 80, "")
	if err != nil {
		t.Fatal(err)
	}
	if screen.Files[0].LinkTarget != "../../../.ssh/id_ed25519" || screen.Files[0].PreviousLinkTarget != "" {
		t.Fatalf("added symlink target=%+v", screen.Files[0])
	}
	if screen.Files[1].LinkTarget != "/etc/passwd" || screen.Files[1].PreviousLinkTarget != "docs" {
		t.Fatalf("retargeted symlink=%+v", screen.Files[1])
	}
	if !contains(screen.Files[1].Risks, "symlink-target-change") || contains(screen.Files[0].Risks, "symlink-target-change") {
		t.Fatalf("target-change classification=%+v %+v", screen.Files[0].Risks, screen.Files[1].Risks)
	}
	if screen.Files[2].LinkTarget != "" || screen.Files[2].PreviousLinkTarget != "old-target" {
		t.Fatalf("deleted symlink=%+v", screen.Files[2])
	}
}

func contains(values []string, want string) bool {
	for _, value := range values {
		if value == want {
			return true
		}
	}
	return false
}
