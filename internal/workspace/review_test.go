package workspace

import (
	"fmt"
	"os"
	"path/filepath"
	"strings"
	"testing"
)

func TestBuildReviewRendersTextAndClassifiesRisks(t *testing.T) {
	root := canonicalTestRoot(t)
	baselineRoot := filepath.Join(root, "baseline")
	mergedRoot := filepath.Join(root, "merged")
	for _, directory := range []string{baselineRoot, mergedRoot} {
		if err := os.Mkdir(directory, 0700); err != nil {
			t.Fatal(err)
		}
	}
	writeFile(t, filepath.Join(baselineRoot, "code.txt"), "one\nold\ntail\n")
	writeFile(t, filepath.Join(mergedRoot, "code.txt"), "one\nnew\ntail\n")
	writeFile(t, filepath.Join(mergedRoot, "run.sh"), "#!/bin/sh\necho safe\n")
	if err := os.Chmod(filepath.Join(mergedRoot, "run.sh"), 0755); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(filepath.Join(mergedRoot, "asset.bin"), []byte{0, 1, 2}, 0600); err != nil {
		t.Fatal(err)
	}
	if err := os.Symlink("code.txt", filepath.Join(mergedRoot, "current")); err != nil {
		t.Fatal(err)
	}
	policy := DefaultSnapshotPolicy()
	baseline, err := BuildSnapshotManifest(baselineRoot, policy)
	if err != nil {
		t.Fatal(err)
	}
	merged, err := BuildSnapshotManifest(mergedRoot, policy)
	if err != nil {
		t.Fatal(err)
	}
	changes, err := BuildChangeSet(baseline, merged, policy)
	if err != nil {
		t.Fatal(err)
	}
	review, err := BuildReview(baselineRoot, mergedRoot, baseline, merged, changes, policy, ReviewOptions{Context: 1})
	if err != nil {
		t.Fatal(err)
	}
	if review.Counts.Add != 3 || review.Counts.Modify != 1 || review.Executable != 1 || review.Symlink != 1 || review.Opaque != 1 {
		t.Fatalf("review summary=%+v", review)
	}
	var sawOld, sawNew, sawBinary bool
	for _, item := range review.Items {
		switch item.Change.Path {
		case "code.txt":
			for _, hunk := range item.Hunks {
				for _, line := range hunk.Lines {
					if line.Kind == '-' && line.Text == "old\n" {
						sawOld = true
					}
					if line.Kind == '+' && line.Text == "new\n" {
						sawNew = true
					}
				}
			}
		case "asset.bin":
			sawBinary = item.Binary && strings.Contains(item.OpaqueReason, "binary")
		}
	}
	if !sawOld || !sawNew || !sawBinary {
		t.Fatalf("old=%t new=%t binary=%t review=%+v", sawOld, sawNew, sawBinary, review)
	}
}

func TestBuildReviewFiltersExactPathAndRejectsSnapshotTampering(t *testing.T) {
	root := canonicalTestRoot(t)
	baselineRoot := filepath.Join(root, "baseline")
	mergedRoot := filepath.Join(root, "merged")
	for _, directory := range []string{baselineRoot, mergedRoot} {
		if err := os.Mkdir(directory, 0700); err != nil {
			t.Fatal(err)
		}
	}
	writeFile(t, filepath.Join(baselineRoot, "one.txt"), "before\n")
	writeFile(t, filepath.Join(mergedRoot, "one.txt"), "after\n")
	writeFile(t, filepath.Join(mergedRoot, "two.txt"), "two\n")
	policy := DefaultSnapshotPolicy()
	baseline, err := BuildSnapshotManifest(baselineRoot, policy)
	if err != nil {
		t.Fatal(err)
	}
	merged, err := BuildSnapshotManifest(mergedRoot, policy)
	if err != nil {
		t.Fatal(err)
	}
	changes, err := BuildChangeSet(baseline, merged, policy)
	if err != nil {
		t.Fatal(err)
	}
	review, err := BuildReview(baselineRoot, mergedRoot, baseline, merged, changes, policy, ReviewOptions{Context: 0, Path: "one.txt"})
	if err != nil || !review.Filtered || len(review.Items) != 1 || review.Items[0].Change.Path != "one.txt" {
		t.Fatalf("review=%+v error=%v", review, err)
	}
	if _, err := BuildReview(baselineRoot, mergedRoot, baseline, merged, changes, policy, ReviewOptions{Path: "missing.txt"}); err == nil {
		t.Fatal("missing review path was accepted")
	}
	writeFile(t, filepath.Join(mergedRoot, "one.txt"), "tampered\n")
	if _, err := BuildReview(baselineRoot, mergedRoot, baseline, merged, changes, policy, ReviewOptions{}); err == nil {
		t.Fatal("tampered Merged View was accepted")
	}
}

func canonicalTestRoot(t *testing.T) string {
	t.Helper()
	root, err := filepath.EvalSymlinks(t.TempDir())
	if err != nil {
		t.Fatal(err)
	}
	return root
}

func TestMyersLineOperationsReconstructTarget(t *testing.T) {
	tests := []struct {
		before []string
		after  []string
	}{
		{nil, []string{"added\n"}},
		{[]string{"deleted\n"}, nil},
		{[]string{"a\n", "b\n", "c\n"}, []string{"a\n", "x\n", "c\n"}},
		{[]string{"same\n", "same\n", "old\n"}, []string{"same\n", "new\n", "same\n"}},
		{[]string{"a\n", "b\n"}, []string{"x\n", "a\n", "b\n", "y\n"}},
	}
	for _, test := range tests {
		operations, ok := myersLineOperations(test.before, test.after)
		if !ok {
			t.Fatalf("bounded fixture unexpectedly exceeded edit distance: before=%v after=%v", test.before, test.after)
		}
		var reconstructed []string
		var consumed []string
		for _, operation := range operations {
			switch operation.kind {
			case ' ':
				consumed = append(consumed, operation.text)
				reconstructed = append(reconstructed, operation.text)
			case '-':
				consumed = append(consumed, operation.text)
			case '+':
				reconstructed = append(reconstructed, operation.text)
			default:
				t.Fatalf("unknown operation: %+v", operation)
			}
		}
		if strings.Join(consumed, "") != strings.Join(test.before, "") || strings.Join(reconstructed, "") != strings.Join(test.after, "") {
			t.Fatalf("operations do not reconstruct inputs: before=%v after=%v operations=%v", test.before, test.after, operations)
		}
	}
}

func TestBuildReviewMakesLargeContentAndExcessItemsExplicit(t *testing.T) {
	root := canonicalTestRoot(t)
	baselineRoot := filepath.Join(root, "baseline")
	mergedRoot := filepath.Join(root, "merged")
	for _, directory := range []string{baselineRoot, mergedRoot} {
		if err := os.Mkdir(directory, 0700); err != nil {
			t.Fatal(err)
		}
	}
	large := make([]byte, maximumReviewFileBytes+1)
	for index := range large {
		large[index] = 'x'
	}
	if err := os.WriteFile(filepath.Join(mergedRoot, "large.txt"), large, 0600); err != nil {
		t.Fatal(err)
	}
	for index := 0; index < maximumReviewItems; index++ {
		name := filepath.Join(mergedRoot, fmt.Sprintf("small-%04d.txt", index))
		if err := os.WriteFile(name, nil, 0600); err != nil {
			t.Fatal(err)
		}
	}
	policy := DefaultSnapshotPolicy()
	baseline, err := BuildSnapshotManifest(baselineRoot, policy)
	if err != nil {
		t.Fatal(err)
	}
	merged, err := BuildSnapshotManifest(mergedRoot, policy)
	if err != nil {
		t.Fatal(err)
	}
	changes, err := BuildChangeSet(baseline, merged, policy)
	if err != nil {
		t.Fatal(err)
	}
	review, err := BuildReview(baselineRoot, mergedRoot, baseline, merged, changes, policy, ReviewOptions{})
	if err != nil {
		t.Fatal(err)
	}
	if len(review.Items) != maximumReviewItems || review.Omitted != 1 || review.Opaque != 1 {
		t.Fatalf("bounded review items=%d omitted=%d opaque=%d", len(review.Items), review.Omitted, review.Opaque)
	}
	if review.Items[0].Change.Path != "large.txt" || !strings.Contains(review.Items[0].OpaqueReason, "inline review limit") {
		t.Fatalf("large review item=%+v", review.Items[0])
	}
	if _, err := BuildReview(baselineRoot, mergedRoot, baseline, merged, changes, policy, ReviewOptions{Context: MaximumReviewContext + 1}); err == nil {
		t.Fatal("out-of-range review context was accepted")
	}
}
