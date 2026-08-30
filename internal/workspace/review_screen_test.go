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
	if wide.SideBySide[2].BeforeKind != '-' || wide.SideBySide[2].Before != "old\n" || wide.SideBySide[2].AfterKind != '+' || wide.SideBySide[2].After != "new\n" {
		t.Fatalf("side-by-side replacement=%+v", wide.SideBySide[2])
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
