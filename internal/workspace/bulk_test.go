package workspace

import (
	"os"
	"path/filepath"
	"strings"
	"testing"
)

func bulkTestManifest(t *testing.T, entries []SnapshotEntry) SnapshotManifest {
	t.Helper()
	var total int64
	for _, entry := range entries {
		if entry.Type == TypeFile {
			total += entry.Size
		}
	}
	manifest, err := finalizeSnapshotManifest("/private/tmp/project", entries, total)
	if err != nil {
		t.Fatal(err)
	}
	return manifest
}

func TestPartitionedSnapshotDoesNotEnterExplicitBulkDirectory(t *testing.T) {
	root := t.TempDir()
	if err := os.Mkdir(filepath.Join(root, "node_modules"), 0755); err != nil {
		t.Fatal(err)
	}
	if err := os.Mkdir(filepath.Join(root, "node_modules", "unread"), 0000); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(filepath.Join(root, "main.js"), []byte("main"), 0644); err != nil {
		t.Fatal(err)
	}
	manifest, records, err := BuildPartitionedSnapshotManifest(root, DefaultSnapshotPolicy(), DefaultBulkPolicyV1(), strings.Repeat("d", 64))
	if err != nil {
		t.Fatal(err)
	}
	if len(records) != 1 || records[0].Root != "node_modules" || records[0].Baseline.State != "present_untracked" || len(manifest.BulkRoots) != 1 {
		t.Fatalf("manifest=%+v records=%+v", manifest, records)
	}
	if len(manifest.Core.Entries) != 1 || manifest.Core.Entries[0].Path != "main.js" {
		t.Fatalf("explicit Bulk descendants entered Core: %+v", manifest.Core.Entries)
	}
}

func TestPartitionedSnapshotMovesStructuralOverflowOutOfCore(t *testing.T) {
	root := t.TempDir()
	if err := os.Mkdir(filepath.Join(root, "fixtures"), 0755); err != nil {
		t.Fatal(err)
	}
	for _, name := range []string{"a", "b", "c"} {
		if err := os.WriteFile(filepath.Join(root, "fixtures", name), []byte(name), 0644); err != nil {
			t.Fatal(err)
		}
	}
	bulkPolicy := DefaultBulkPolicyV1()
	bulkPolicy.CoreSoftEntries = 2
	bulkPolicy.CoreHardEntries = 10
	bulkPolicy.CoreSoftBytes = 1024
	bulkPolicy.CoreHardBytes = 2048
	manifest, records, err := BuildPartitionedSnapshotManifest(root, DefaultSnapshotPolicy(), bulkPolicy, strings.Repeat("e", 64))
	if err != nil {
		t.Fatal(err)
	}
	if len(records) != 1 || records[0].Root != "fixtures" || records[0].Discovery.Reason != "structural-entry-overflow" || records[0].Baseline.State != "present_untracked" {
		t.Fatalf("records=%+v", records)
	}
	if len(manifest.Core.Entries) != 0 {
		t.Fatalf("structural Bulk descendants entered Core: %+v", manifest.Core.Entries)
	}
}

func TestCoreAdmissionOverflowUsesCostThenCanonicalPath(t *testing.T) {
	manifest := bulkTestManifest(t, []SnapshotEntry{
		{Path: "a", Type: TypeDirectory, Mode: 0755}, {Path: "a/one", Type: TypeFile, Mode: 0644, Size: 1, SHA256: strings.Repeat("1", 64)},
		{Path: "b", Type: TypeDirectory, Mode: 0755}, {Path: "b/one", Type: TypeFile, Mode: 0644, Size: 1, SHA256: strings.Repeat("2", 64)},
		{Path: "c", Type: TypeDirectory, Mode: 0755}, {Path: "c/one", Type: TypeFile, Mode: 0644, Size: 1, SHA256: strings.Repeat("3", 64)},
	})
	bulkPolicy := DefaultBulkPolicyV1()
	bulkPolicy.CoreSoftEntries, bulkPolicy.CoreHardEntries = 2, 4
	bulkPolicy.CoreSoftBytes, bulkPolicy.CoreHardBytes = 1024, 2048
	_, _, records, err := PartitionManifestPair(manifest, manifest, bulkPolicy, strings.Repeat("f", 64))
	if err != nil {
		t.Fatal(err)
	}
	if len(records) != 1 || records[0].Root != "a" || records[0].Discovery.Reason != "core-admission-overflow" {
		t.Fatalf("admission partition=%+v", records)
	}
}

func TestCoreAdmissionRejectsUnpartitionableRootFiles(t *testing.T) {
	manifest := bulkTestManifest(t, []SnapshotEntry{
		{Path: "one", Type: TypeFile, Mode: 0644, Size: 1, SHA256: strings.Repeat("1", 64)},
		{Path: "two", Type: TypeFile, Mode: 0644, Size: 1, SHA256: strings.Repeat("2", 64)},
		{Path: "three", Type: TypeFile, Mode: 0644, Size: 1, SHA256: strings.Repeat("3", 64)},
	})
	bulkPolicy := DefaultBulkPolicyV1()
	bulkPolicy.CoreSoftEntries, bulkPolicy.CoreHardEntries = 2, 2
	bulkPolicy.CoreSoftBytes, bulkPolicy.CoreHardBytes = 1024, 2048
	if _, _, _, err := PartitionManifestPair(manifest, manifest, bulkPolicy, strings.Repeat("f", 64)); err == nil {
		t.Fatal("unpartitionable root-file overflow was accepted")
	}
}

func TestBulkPolicyDefaultMatchesExactDirectoryComponent(t *testing.T) {
	policy := DefaultBulkPolicyV1()
	if err := ValidateBulkPolicy(policy); err != nil {
		t.Fatal(err)
	}
	empty := bulkTestManifest(t, nil)
	result := bulkTestManifest(t, []SnapshotEntry{
		{Path: "node_modules", Type: TypeDirectory, Mode: 0755},
		{Path: "node_modules/a.js", Type: TypeFile, Mode: 0644, Size: 1, SHA256: strings.Repeat("1", 64)},
		{Path: "packages", Type: TypeDirectory, Mode: 0755},
		{Path: "packages/app", Type: TypeDirectory, Mode: 0755},
		{Path: "packages/app/node_modules", Type: TypeDirectory, Mode: 0755},
		{Path: "packages/app/node_modules/b.js", Type: TypeFile, Mode: 0644, Size: 2, SHA256: strings.Repeat("2", 64)},
		{Path: "packages/app/Node_Modules", Type: TypeDirectory, Mode: 0755},
		{Path: "packages/app/Node_Modules/kept.js", Type: TypeFile, Mode: 0644, Size: 3, SHA256: strings.Repeat("3", 64)},
	})
	left, right, records, err := PartitionManifestPair(empty, result, policy, strings.Repeat("a", 64))
	if err != nil {
		t.Fatal(err)
	}
	if len(records) != 2 || records[0].Root != "node_modules" || records[1].Root != "packages/app/node_modules" {
		t.Fatalf("bulk records=%+v", records)
	}
	if len(left.BulkRoots) != 2 || left.BulkRoots[0].State != "absent" || right.BulkRoots[0].State != "exact" || records[0].Capture.State != "frozen_vm" || records[0].Disposition != "unresolved" {
		t.Fatalf("partition left=%+v right=%+v records=%+v", left, right, records)
	}
	for _, entry := range right.Core.Entries {
		if strings.Contains(entry.Path, "node_modules") && !strings.Contains(entry.Path, "Node_Modules") {
			t.Fatalf("bulk entry leaked into Core: %s", entry.Path)
		}
	}
}

func TestBulkPolicyNormalOverrideAndNestedDedup(t *testing.T) {
	policy := DefaultBulkPolicyV1()
	policy.NormalRoots = []string{"packages/app/node_modules"}
	manifest := bulkTestManifest(t, []SnapshotEntry{
		{Path: "node_modules", Type: TypeDirectory, Mode: 0755},
		{Path: "node_modules/nested", Type: TypeDirectory, Mode: 0755},
		{Path: "node_modules/nested/node_modules", Type: TypeDirectory, Mode: 0755},
		{Path: "packages", Type: TypeDirectory, Mode: 0755},
		{Path: "packages/app", Type: TypeDirectory, Mode: 0755},
		{Path: "packages/app/node_modules", Type: TypeDirectory, Mode: 0755},
	})
	_, _, records, err := PartitionManifestPair(manifest, manifest, policy, strings.Repeat("b", 64))
	if err != nil {
		t.Fatal(err)
	}
	if len(records) != 1 || records[0].Root != "node_modules" {
		t.Fatalf("bulk records=%+v", records)
	}
}

func TestBulkMerkleChangesForIdentityFieldsAndIgnoresInputOrder(t *testing.T) {
	entries := []SnapshotEntry{
		{Path: "node_modules", Type: TypeDirectory, Mode: 0755},
		{Path: "node_modules/a", Type: TypeFile, Mode: 0644, Size: 1, SHA256: strings.Repeat("1", 64)},
		{Path: "node_modules/link", Type: TypeSymlink, Mode: 0777, LinkTarget: "a"},
	}
	_, first, firstObject, err := bulkDigests("node_modules", entries, summarizeBulkEntries(entries))
	if err != nil {
		t.Fatal(err)
	}
	reversed := []SnapshotEntry{entries[2], entries[1], entries[0]}
	_, second, secondObject, err := bulkDigests("node_modules", reversed, summarizeBulkEntries(reversed))
	if err != nil {
		t.Fatal(err)
	}
	if first != second || firstObject != secondObject {
		t.Fatal("Bulk digest depends on archive or walk order")
	}
	changed := append([]SnapshotEntry(nil), entries...)
	changed[1].Mode = 0755
	_, third, thirdObject, err := bulkDigests("node_modules", changed, summarizeBulkEntries(changed))
	if err != nil {
		t.Fatal(err)
	}
	if first == third || firstObject == thirdObject {
		t.Fatal("Bulk digest ignored a mode identity change")
	}
}

func TestDisabledBulkPolicyPreservesLegacyManifestMeaning(t *testing.T) {
	manifest := bulkTestManifest(t, []SnapshotEntry{{Path: "node_modules", Type: TypeDirectory, Mode: 0755}})
	left, right, records, err := PartitionManifestPair(manifest, manifest, DisabledBulkPolicy(), strings.Repeat("c", 64))
	if err != nil {
		t.Fatal(err)
	}
	if len(records) != 0 || left.Core.Digest != manifest.Digest || right.Core.Digest != manifest.Digest {
		t.Fatalf("disabled partition changed legacy meaning: left=%+v right=%+v records=%+v", left, right, records)
	}
}

func TestBulkPolicyRejectsGlobAndAllowsExactNormalOverride(t *testing.T) {
	policy := DefaultBulkPolicyV1()
	policy.Rules[0].Selector.Value = "**/node_modules"
	if err := ValidateBulkPolicy(policy); err == nil {
		t.Fatal("glob bulk selector was accepted")
	}
	policy = DefaultBulkPolicyV1()
	policy.Rules = append(policy.Rules, BulkRule{ID: "user.literal", Selector: BulkSelector{Kind: "literal", Value: "vendor"}, Review: "summary", VMInput: "omit", Hint: "dependency-tree"})
	policy.NormalRoots = []string{"vendor"}
	if _, err := CanonicalBulkPolicy(policy); err != nil {
		t.Fatalf("exact Normal override did not take precedence: %v", err)
	}
}

func TestSnapshotRejectsInvalidUTF8PathBeforeJSONIdentity(t *testing.T) {
	root := t.TempDir()
	name := string([]byte{'b', 'a', 'd', 0xff})
	if err := os.WriteFile(filepath.Join(root, name), []byte("x"), 0600); err != nil {
		t.Skipf("filesystem does not accept invalid UTF-8 fixture: %v", err)
	}
	if _, err := BuildSnapshotManifest(root, DefaultSnapshotPolicy()); err == nil {
		t.Fatal("invalid UTF-8 path entered a JSON-based manifest identity")
	}
}
