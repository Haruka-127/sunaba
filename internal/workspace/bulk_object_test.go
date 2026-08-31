package workspace

import (
	"context"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"
)

func TestCaptureBulkObjectCommitsOpaquePrivateObject(t *testing.T) {
	parent := t.TempDir()
	source := filepath.Join(parent, "source")
	if err := os.Mkdir(source, 0700); err != nil {
		t.Fatal(err)
	}
	root := filepath.Join(source, "node_modules")
	if err := os.Mkdir(root, 0755); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(filepath.Join(root, "package.js"), []byte("module"), 0644); err != nil {
		t.Fatal(err)
	}
	if err := os.Link(filepath.Join(root, "package.js"), filepath.Join(root, "hardlink.js")); err != nil {
		t.Fatal(err)
	}
	if err := os.Symlink("package.js", filepath.Join(root, "current.js")); err != nil {
		t.Fatal(err)
	}
	policy := DefaultSnapshotPolicy()
	capturePolicy := BulkCaptureSnapshotPolicy(policy)
	manifest, err := BuildSnapshotManifest(source, capturePolicy)
	if err != nil {
		t.Fatal(err)
	}
	canonicalParent, err := filepath.EvalSymlinks(parent)
	if err != nil {
		t.Fatal(err)
	}
	store := filepath.Join(canonicalParent, "retained")
	ctx, cancel := context.WithTimeout(context.Background(), time.Second)
	defer cancel()
	object, err := CaptureBulkObject(ctx, store, source, manifest, "node_modules", capturePolicy)
	if err != nil {
		t.Fatal(err)
	}
	if object.Capture.State != "exact_managed" || object.Metadata.Summary.HardlinksFlattened != 1 || object.Result.ObjectDigest != object.Capture.ObjectDigest {
		t.Fatalf("object=%+v", object)
	}
	objectRoot := filepath.Join(store, "objects", object.Capture.ObjectID)
	info, err := os.Lstat(objectRoot)
	if err != nil || !info.IsDir() || info.Mode().Perm() != 0700 {
		t.Fatalf("object directory mode=%v error=%v", info, err)
	}
	for _, path := range []string{filepath.Join(objectRoot, "manifest.bin"), filepath.Join(objectRoot, "object.json")} {
		info, err := os.Lstat(path)
		if err != nil || !info.Mode().IsRegular() || info.Mode().Perm() != 0600 {
			t.Fatalf("private object file %s mode=%v error=%v", path, info, err)
		}
	}
	if _, err := ValidateBulkObject(ctx, store, object.Capture, object.Result); err != nil {
		t.Fatal(err)
	}
	stage := filepath.Join(canonicalParent, "stage")
	if err := os.Mkdir(stage, 0700); err != nil {
		t.Fatal(err)
	}
	if err := MaterializeBulkObjectAt(ctx, store, object.Capture, object.Result, stage, manifest, policy); err != nil {
		t.Fatal(err)
	}
	staged, err := os.ReadFile(filepath.Join(stage, "node_modules", "hardlink.js"))
	if err != nil || string(staged) != "module" {
		t.Fatalf("materialized Bulk content=%q error=%v", staged, err)
	}
	left, err := os.Lstat(filepath.Join(stage, "node_modules", "package.js"))
	if err != nil {
		t.Fatal(err)
	}
	right, err := os.Lstat(filepath.Join(stage, "node_modules", "hardlink.js"))
	if err != nil {
		t.Fatal(err)
	}
	if os.SameFile(left, right) {
		t.Fatal("Bulk hardlink was not flattened during materialization")
	}
	entries, err := os.ReadDir(filepath.Join(objectRoot, "blobs"))
	if err != nil || len(entries) != 1 || entries[0].Name() == "package.js" || !validSHA256(entries[0].Name()) {
		t.Fatalf("blob storage leaked Project names or missed dedup: entries=%v error=%v", entries, err)
	}
}

func TestValidateBulkObjectRejectsChangedBlob(t *testing.T) {
	parent := t.TempDir()
	source := filepath.Join(parent, "source")
	if err := os.MkdirAll(filepath.Join(source, "bulk"), 0700); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(filepath.Join(source, "bulk", "secret-name"), []byte("content"), 0600); err != nil {
		t.Fatal(err)
	}
	policy := DefaultSnapshotPolicy()
	manifest, err := BuildSnapshotManifest(source, policy)
	if err != nil {
		t.Fatal(err)
	}
	canonicalParent, err := filepath.EvalSymlinks(parent)
	if err != nil {
		t.Fatal(err)
	}
	store := filepath.Join(canonicalParent, "retained")
	ctx, cancel := context.WithTimeout(context.Background(), time.Second)
	defer cancel()
	object, err := CaptureBulkObject(ctx, store, source, manifest, "bulk", policy)
	if err != nil {
		t.Fatal(err)
	}
	var digest string
	for _, entry := range manifest.Entries {
		if entry.Type == TypeFile {
			digest = entry.SHA256
		}
	}
	blob := filepath.Join(store, "objects", object.Capture.ObjectID, "blobs", digest)
	if err := os.WriteFile(blob, []byte("changed"), 0600); err != nil {
		t.Fatal(err)
	}
	if _, err := ValidateBulkObject(ctx, store, object.Capture, object.Result); err == nil || !strings.Contains(err.Error(), "changed") {
		t.Fatalf("changed blob was accepted: %v", err)
	}
}

func TestDecodeBulkManifestRejectsTraversalAndTrailingData(t *testing.T) {
	entries := []SnapshotEntry{
		{Path: "bulk", Type: TypeDirectory, Mode: 0755},
		{Path: "bulk/file", Type: TypeFile, Mode: 0644, Size: 1, SHA256: strings.Repeat("1", 64)},
	}
	encoded, err := encodeBulkManifest(entries)
	if err != nil {
		t.Fatal(err)
	}
	if _, err := decodeBulkManifest(append(encoded, 0)); err == nil {
		t.Fatal("Bulk manifest trailing data was accepted")
	}
	bad := append([]SnapshotEntry(nil), entries...)
	bad[1].Path = "../escape"
	encoded, err = encodeBulkManifest(bad)
	if err != nil {
		t.Fatal(err)
	}
	decoded, err := decodeBulkManifest(encoded)
	if err != nil {
		t.Fatal(err)
	}
	if _, _, _, err := bulkDigests("bulk", decoded, summarizeBulkEntries(decoded)); err == nil {
		t.Fatal("Bulk Merkle accepted a path outside its root")
	}
}
