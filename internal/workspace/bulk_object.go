package workspace

import (
	"context"
	"crypto/rand"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"os"
	"path/filepath"
	"sort"
	"strings"

	"golang.org/x/sys/unix"
	"sunaba/internal/securefs"
)

const bulkObjectMetadataMaximum = 64 << 10

type BulkObjectMetadata struct {
	Version         int         `json:"version"`
	ObjectID        string      `json:"object_id"`
	Root            string      `json:"root"`
	MetadataProfile string      `json:"metadata_profile"`
	ManifestDigest  string      `json:"manifest_digest"`
	MerkleDigest    string      `json:"merkle_digest"`
	ObjectDigest    string      `json:"object_digest"`
	Summary         BulkSummary `json:"summary"`
}

type BulkObject struct {
	Metadata BulkObjectMetadata
	Capture  BulkCapture
	Result   BulkManifestRef
}

// CaptureBulkObject copies an exact Bulk root from a frozen, private source
// into a host-only content-addressed object. Project programs and archive
// extractors are never invoked. Hardlinks are deliberately materialized as
// independent regular blobs and reported in the summary.
func CaptureBulkObject(ctx context.Context, storeRoot, sourceRoot string, source SnapshotManifest, root string, policy SnapshotPolicy) (object BulkObject, err error) {
	if ctx == nil {
		return BulkObject{}, fmt.Errorf("Bulk capture requires a bounded context")
	}
	if !filepath.IsAbs(storeRoot) || filepath.Clean(storeRoot) != storeRoot || !filepath.IsAbs(sourceRoot) || filepath.Clean(sourceRoot) != sourceRoot {
		return BulkObject{}, fmt.Errorf("Bulk object roots must be absolute and clean")
	}
	if err := validateCanonicalManifest(source, policy); err != nil {
		return BulkObject{}, fmt.Errorf("invalid Bulk capture manifest: %w", err)
	}
	canonicalSource, err := filepath.EvalSymlinks(sourceRoot)
	if err != nil || canonicalSource != source.Root {
		return BulkObject{}, fmt.Errorf("Bulk capture source does not match its manifest")
	}
	sourceRoot = canonicalSource
	if err := securefs.CheckCanonicalOwnedDir(sourceRoot); err != nil {
		return BulkObject{}, fmt.Errorf("Bulk capture source must be a private current-user directory: %w", err)
	}
	if err := securefs.EnsureCanonicalOwnedDir(storeRoot); err != nil {
		return BulkObject{}, err
	}
	objectsRoot := filepath.Join(storeRoot, "objects")
	if err := securefs.EnsureCanonicalOwnedDir(objectsRoot); err != nil {
		return BulkObject{}, err
	}
	entries := entriesUnderRoot(source.Entries, root)
	if len(entries) == 0 || entries[0].Path != root || entries[0].Type != TypeDirectory {
		return BulkObject{}, fmt.Errorf("Bulk root %q is not an exact directory", root)
	}
	if len(entries) > MaximumBulkEntriesPerRoot {
		return BulkObject{}, fmt.Errorf("Bulk root %q exceeds its entry ceiling", root)
	}
	initialSummary := summarizeBulkEntries(entries)
	if initialSummary.LogicalBytes > MaximumBulkLogicalBytesPerRoot {
		return BulkObject{}, fmt.Errorf("Bulk root %q exceeds its logical byte ceiling", root)
	}
	objectID, err := newBulkObjectID()
	if err != nil {
		return BulkObject{}, err
	}
	temporary, err := os.MkdirTemp(objectsRoot, ".capture-")
	if err != nil {
		return BulkObject{}, err
	}
	if err := os.Chmod(temporary, 0700); err != nil {
		_ = os.RemoveAll(temporary)
		return BulkObject{}, err
	}
	committed := false
	defer func() {
		if !committed {
			_ = os.RemoveAll(temporary)
		}
	}()
	blobsRoot := filepath.Join(temporary, "blobs")
	if err := os.Mkdir(blobsRoot, 0700); err != nil {
		return BulkObject{}, err
	}
	sourceFD, err := unix.Open(sourceRoot, unix.O_RDONLY|unix.O_DIRECTORY|unix.O_CLOEXEC|unix.O_NOFOLLOW, 0)
	if err != nil {
		return BulkObject{}, fmt.Errorf("open Bulk capture source: %w", err)
	}
	defer unix.Close(sourceFD)
	type inodeIdentity struct{ device, inode uint64 }
	seenInodes := make(map[inodeIdentity]struct{})
	summary := summarizeBulkEntries(entries)
	for _, entry := range entries {
		if err := ctx.Err(); err != nil {
			return BulkObject{}, fmt.Errorf("Bulk capture deadline: %w", err)
		}
		if entry.Type != TypeFile {
			continue
		}
		identity, err := captureBulkBlob(ctx, sourceFD, blobsRoot, entry, policy.MaxFileSize)
		if err != nil {
			return BulkObject{}, err
		}
		if _, exists := seenInodes[identity]; exists {
			summary.HardlinksFlattened++
		} else {
			seenInodes[identity] = struct{}{}
		}
	}
	manifest, err := encodeBulkManifest(entries)
	if err != nil {
		return BulkObject{}, err
	}
	manifestPath := filepath.Join(temporary, "manifest.bin")
	if err := writeExclusiveSynced(manifestPath, manifest); err != nil {
		return BulkObject{}, err
	}
	manifestDigest, merkleDigest, objectDigest, err := bulkDigests(root, entries, summary)
	if err != nil {
		return BulkObject{}, err
	}
	metadata := BulkObjectMetadata{
		Version: BulkFormatVersion, ObjectID: objectID, Root: root, MetadataProfile: BulkMetadataProfile,
		ManifestDigest: manifestDigest, MerkleDigest: merkleDigest, ObjectDigest: objectDigest, Summary: summary,
	}
	encoded, err := json.MarshalIndent(metadata, "", "  ")
	if err != nil {
		return BulkObject{}, err
	}
	encoded = append(encoded, '\n')
	if len(encoded) > bulkObjectMetadataMaximum {
		return BulkObject{}, fmt.Errorf("Bulk object metadata exceeds its bound")
	}
	if err := writeExclusiveSynced(filepath.Join(temporary, "object.json"), encoded); err != nil {
		return BulkObject{}, err
	}
	if err := securefs.SyncDir(blobsRoot); err != nil {
		return BulkObject{}, err
	}
	if err := securefs.SyncDir(temporary); err != nil {
		return BulkObject{}, err
	}
	destination := filepath.Join(objectsRoot, objectID)
	if err := os.Rename(temporary, destination); err != nil {
		return BulkObject{}, err
	}
	committed = true
	if err := securefs.SyncDir(objectsRoot); err != nil {
		return BulkObject{}, fmt.Errorf("commit Bulk object directory: %w", err)
	}
	result := BulkManifestRef{
		Root: root, State: "exact", ManifestDigest: manifestDigest, MerkleDigest: merkleDigest,
		ObjectDigest: objectDigest, Summary: summary,
	}
	return BulkObject{Metadata: metadata, Capture: BulkCapture{State: "exact_managed", ObjectID: objectID, ObjectDigest: objectDigest}, Result: result}, nil
}

func ValidateBulkObject(ctx context.Context, storeRoot string, capture BulkCapture, expected BulkManifestRef) (BulkObjectMetadata, error) {
	if ctx == nil || capture.State != "exact_managed" || !validBulkObjectID(capture.ObjectID) || !validSHA256(capture.ObjectDigest) || expected.State != "exact" {
		return BulkObjectMetadata{}, fmt.Errorf("Bulk object identity is incomplete")
	}
	if err := securefs.CheckCanonicalOwnedDir(storeRoot); err != nil {
		return BulkObjectMetadata{}, err
	}
	objectRoot := filepath.Join(storeRoot, "objects", capture.ObjectID)
	if err := securefs.CheckCanonicalOwnedDir(filepath.Join(storeRoot, "objects")); err != nil {
		return BulkObjectMetadata{}, err
	}
	if err := securefs.CheckCanonicalOwnedDir(objectRoot); err != nil {
		return BulkObjectMetadata{}, err
	}
	if err := securefs.CheckCanonicalOwnedDir(filepath.Join(objectRoot, "blobs")); err != nil {
		return BulkObjectMetadata{}, err
	}
	data, err := securefs.ReadOwnedRegular(filepath.Join(objectRoot, "object.json"), bulkObjectMetadataMaximum)
	if err != nil {
		return BulkObjectMetadata{}, err
	}
	var metadata BulkObjectMetadata
	if err := securefs.DecodeStrictJSON(data, &metadata); err != nil {
		return BulkObjectMetadata{}, err
	}
	if metadata.Version != BulkFormatVersion || metadata.ObjectID != capture.ObjectID || metadata.Root != expected.Root || metadata.MetadataProfile != BulkMetadataProfile || metadata.ManifestDigest != expected.ManifestDigest || metadata.MerkleDigest != expected.MerkleDigest || metadata.ObjectDigest != expected.ObjectDigest || metadata.ObjectDigest != capture.ObjectDigest || metadata.Summary != expected.Summary {
		return BulkObjectMetadata{}, fmt.Errorf("Bulk object metadata does not match its Work Set identity")
	}
	manifest, err := securefs.ReadOwnedRegular(filepath.Join(objectRoot, "manifest.bin"), MaximumBulkManifestBytes)
	if err != nil {
		return BulkObjectMetadata{}, err
	}
	sum := sha256.Sum256(manifest)
	if hex.EncodeToString(sum[:]) != metadata.ManifestDigest {
		return BulkObjectMetadata{}, fmt.Errorf("Bulk object manifest digest changed")
	}
	entries, err := decodeBulkManifest(manifest)
	if err != nil {
		return BulkObjectMetadata{}, err
	}
	rebuiltManifest, rebuiltMerkle, rebuiltObject, err := bulkDigests(metadata.Root, entries, metadata.Summary)
	if err != nil || rebuiltManifest != metadata.ManifestDigest || rebuiltMerkle != metadata.MerkleDigest || rebuiltObject != metadata.ObjectDigest {
		return BulkObjectMetadata{}, fmt.Errorf("Bulk object canonical identity changed")
	}
	seenBlobs := make(map[string]struct{})
	for _, entry := range entries {
		if entry.Type != TypeFile {
			continue
		}
		if err := ctx.Err(); err != nil {
			return BulkObjectMetadata{}, fmt.Errorf("Bulk object verification deadline: %w", err)
		}
		if _, exists := seenBlobs[entry.SHA256]; exists {
			continue
		}
		seenBlobs[entry.SHA256] = struct{}{}
		if err := verifyBulkBlob(ctx, filepath.Join(objectRoot, "blobs", entry.SHA256), entry.SHA256, entry.Size); err != nil {
			return BulkObjectMetadata{}, err
		}
	}
	children, err := os.ReadDir(filepath.Join(objectRoot, "blobs"))
	if err != nil || len(children) != len(seenBlobs) {
		return BulkObjectMetadata{}, fmt.Errorf("Bulk object blob inventory is not exact")
	}
	return metadata, nil
}

// MaterializeBulkObjectAt installs one exact object under an unused private
// transaction stage. It never writes directly to the host Project.
func MaterializeBulkObjectAt(ctx context.Context, storeRoot string, capture BulkCapture, expected BulkManifestRef, destinationRoot string, core SnapshotManifest, policy SnapshotPolicy) error {
	if _, err := ValidateBulkObject(ctx, storeRoot, capture, expected); err != nil {
		return err
	}
	if err := securefs.CheckCanonicalOwnedDir(destinationRoot); err != nil {
		return fmt.Errorf("Bulk transaction stage is unsafe: %w", err)
	}
	objectRoot := filepath.Join(storeRoot, "objects", capture.ObjectID)
	manifest, err := securefs.ReadOwnedRegular(filepath.Join(objectRoot, "manifest.bin"), MaximumBulkManifestBytes)
	if err != nil {
		return err
	}
	entries, err := decodeBulkManifest(manifest)
	if err != nil {
		return err
	}
	destinationFD, err := unix.Open(destinationRoot, unix.O_RDONLY|unix.O_DIRECTORY|unix.O_CLOEXEC|unix.O_NOFOLLOW, 0)
	if err != nil {
		return err
	}
	defer unix.Close(destinationFD)
	if err := materializeBulkParents(destinationFD, expected.Root, core); err != nil {
		return err
	}
	directories := make([]SnapshotEntry, 0)
	for _, entry := range entries {
		if err := ctx.Err(); err != nil {
			return err
		}
		switch entry.Type {
		case TypeDirectory:
			if err := createDirectoryAt(destinationFD, entry.Path); err != nil {
				return err
			}
			directories = append(directories, entry)
		case TypeFile:
			if err := materializeBulkBlob(ctx, destinationFD, filepath.Join(objectRoot, "blobs", entry.SHA256), entry); err != nil {
				return err
			}
		case TypeSymlink:
			parentFD, name, err := openParentAt(destinationFD, entry.Path)
			if err != nil {
				return err
			}
			err = unix.Symlinkat(entry.LinkTarget, parentFD, name)
			_ = unix.Close(parentFD)
			if err != nil {
				return fmt.Errorf("materialize Bulk symlink %q: %w", entry.Path, err)
			}
		default:
			return fmt.Errorf("Bulk object contains unsupported type")
		}
	}
	sort.Slice(directories, func(i, j int) bool {
		return strings.Count(directories[i].Path, "/") > strings.Count(directories[j].Path, "/")
	})
	for _, directory := range directories {
		fd, err := openPathAt(destinationFD, directory.Path, unix.O_RDONLY|unix.O_DIRECTORY)
		if err != nil {
			return err
		}
		err = unix.Fchmod(fd, directory.Mode&0777)
		_ = unix.Fsync(fd)
		_ = unix.Close(fd)
		if err != nil {
			return err
		}
	}
	if err := unix.Fsync(destinationFD); err != nil {
		return err
	}
	actual, err := BuildSnapshotManifest(destinationRoot, bulkScanSnapshotPolicy(policy))
	if err != nil {
		return err
	}
	actualEntries := entriesUnderRoot(actual.Entries, expected.Root)
	manifestDigest, merkleDigest, objectDigest, err := bulkDigests(expected.Root, actualEntries, expected.Summary)
	if err != nil || manifestDigest != expected.ManifestDigest || merkleDigest != expected.MerkleDigest || objectDigest != expected.ObjectDigest {
		return fmt.Errorf("materialized Bulk directory does not match its exact identity")
	}
	return nil
}

func materializeBulkParents(rootFD int, bulkRoot string, core SnapshotManifest) error {
	byPath := make(map[string]SnapshotEntry, len(core.Entries))
	for _, entry := range core.Entries {
		byPath[entry.Path] = entry
	}
	parents := make([]string, 0)
	for parent := filepath.ToSlash(filepath.Dir(bulkRoot)); parent != "."; parent = filepath.ToSlash(filepath.Dir(parent)) {
		parents = append(parents, parent)
	}
	for left, right := 0, len(parents)-1; left < right; left, right = left+1, right-1 {
		parents[left], parents[right] = parents[right], parents[left]
	}
	for _, parent := range parents {
		entry, exists := byPath[parent]
		if !exists || entry.Type != TypeDirectory {
			return fmt.Errorf("Bulk root %q has no approved Core directory parent %q", bulkRoot, parent)
		}
		existsAtStage, err := pathExistsAt(rootFD, parent)
		if err != nil {
			return err
		}
		if existsAtStage {
			continue
		}
		if err := createDirectoryAt(rootFD, parent); err != nil {
			return err
		}
	}
	return nil
}

func pathExistsAt(rootFD int, entryPath string) (bool, error) {
	parentFD, name, err := openParentAt(rootFD, entryPath)
	if err != nil {
		if errors.Is(err, unix.ENOENT) {
			return false, nil
		}
		return false, err
	}
	defer unix.Close(parentFD)
	var stat unix.Stat_t
	err = unix.Fstatat(parentFD, name, &stat, unix.AT_SYMLINK_NOFOLLOW)
	if errors.Is(err, unix.ENOENT) {
		return false, nil
	}
	return err == nil, err
}

func materializeBulkBlob(ctx context.Context, destinationRootFD int, blobPath string, entry SnapshotEntry) error {
	if err := verifyBulkBlob(ctx, blobPath, entry.SHA256, entry.Size); err != nil {
		return err
	}
	sourceFD, err := unix.Open(blobPath, unix.O_RDONLY|unix.O_CLOEXEC|unix.O_NOFOLLOW, 0)
	if err != nil {
		return err
	}
	source := os.NewFile(uintptr(sourceFD), entry.SHA256)
	defer source.Close()
	parentFD, name, err := openParentAt(destinationRootFD, entry.Path)
	if err != nil {
		return err
	}
	defer unix.Close(parentFD)
	outputFD, err := unix.Openat(parentFD, name, unix.O_WRONLY|unix.O_CREAT|unix.O_EXCL|unix.O_CLOEXEC|unix.O_NOFOLLOW, 0600)
	if err != nil {
		return err
	}
	output := os.NewFile(uintptr(outputFD), name)
	defer output.Close()
	hash := sha256.New()
	written, err := copyBulkBytes(ctx, source, output, hash, entry.Size+1)
	if err != nil || written != entry.Size || hex.EncodeToString(hash.Sum(nil)) != entry.SHA256 {
		return fmt.Errorf("Bulk blob changed during transaction staging")
	}
	if err := unix.Fchmod(outputFD, entry.Mode&0777); err != nil {
		return err
	}
	return output.Sync()
}

func captureBulkBlob(ctx context.Context, sourceRootFD int, blobsRoot string, entry SnapshotEntry, maximum int64) (struct{ device, inode uint64 }, error) {
	empty := struct{ device, inode uint64 }{}
	sourceFD, err := openPathAt(sourceRootFD, entry.Path, unix.O_RDONLY)
	if err != nil {
		return empty, fmt.Errorf("open Bulk file %q: %w", entry.Path, err)
	}
	source := os.NewFile(uintptr(sourceFD), entry.Path)
	defer source.Close()
	var before unix.Stat_t
	if err := unix.Fstat(sourceFD, &before); err != nil || uint32(before.Mode)&uint32(unix.S_IFMT) != uint32(unix.S_IFREG) || before.Size != entry.Size || uint32(before.Mode)&0777 != entry.Mode {
		return empty, fmt.Errorf("Bulk file %q changed before capture", entry.Path)
	}
	destination := filepath.Join(blobsRoot, entry.SHA256)
	if info, err := os.Lstat(destination); err == nil {
		if !info.Mode().IsRegular() || info.Mode().Perm() != 0600 || info.Size() != entry.Size {
			return empty, fmt.Errorf("Bulk blob collision for %q", entry.Path)
		}
		return struct{ device, inode uint64 }{uint64(before.Dev), uint64(before.Ino)}, nil
	} else if !errors.Is(err, os.ErrNotExist) {
		return empty, err
	}
	outputFD, err := unix.Open(destination, unix.O_WRONLY|unix.O_CREAT|unix.O_EXCL|unix.O_CLOEXEC|unix.O_NOFOLLOW, 0600)
	if err != nil {
		return empty, err
	}
	output := os.NewFile(uintptr(outputFD), entry.SHA256)
	defer output.Close()
	hash := sha256.New()
	written, err := copyBulkBytes(ctx, source, output, hash, maximum+1)
	if err != nil || written != entry.Size || hex.EncodeToString(hash.Sum(nil)) != entry.SHA256 {
		return empty, fmt.Errorf("Bulk file %q changed during capture", entry.Path)
	}
	var after unix.Stat_t
	if err := unix.Fstat(sourceFD, &after); err != nil || before.Dev != after.Dev || before.Ino != after.Ino || before.Size != after.Size || before.Mtim != after.Mtim || before.Ctim != after.Ctim {
		return empty, fmt.Errorf("Bulk file %q changed during capture", entry.Path)
	}
	if err := output.Sync(); err != nil {
		return empty, err
	}
	return struct{ device, inode uint64 }{uint64(before.Dev), uint64(before.Ino)}, nil
}

func verifyBulkBlob(ctx context.Context, blobPath, digest string, size int64) error {
	fd, err := unix.Open(blobPath, unix.O_RDONLY|unix.O_CLOEXEC|unix.O_NOFOLLOW|unix.O_NONBLOCK, 0)
	if err != nil {
		return fmt.Errorf("Bulk object blob %s is unsafe", digest)
	}
	file := os.NewFile(uintptr(fd), digest)
	defer file.Close()
	var stat unix.Stat_t
	if err := unix.Fstat(fd, &stat); err != nil || uint32(stat.Mode)&uint32(unix.S_IFMT) != uint32(unix.S_IFREG) || stat.Uid != uint32(os.Geteuid()) || uint32(stat.Mode)&0777 != 0600 || stat.Nlink != 1 || stat.Size != size {
		return fmt.Errorf("Bulk object blob %s is unsafe or has the wrong size", digest)
	}
	hash := sha256.New()
	read, err := copyBulkBytes(ctx, file, nil, hash, size+1)
	if err != nil || read != size || hex.EncodeToString(hash.Sum(nil)) != digest {
		return fmt.Errorf("Bulk object blob %s changed", digest)
	}
	return nil
}

func copyBulkBytes(ctx context.Context, source *os.File, destination *os.File, hash interface{ Write([]byte) (int, error) }, maximum int64) (int64, error) {
	buffer := make([]byte, 64<<10)
	var total int64
	for {
		if err := ctx.Err(); err != nil {
			return total, err
		}
		remaining := maximum - total
		if remaining <= 0 {
			return total, nil
		}
		chunk := buffer
		if int64(len(chunk)) > remaining {
			chunk = chunk[:remaining]
		}
		count, readErr := source.Read(chunk)
		if count > 0 {
			if _, err := hash.Write(chunk[:count]); err != nil {
				return total, err
			}
			if destination != nil {
				written, err := destination.Write(chunk[:count])
				if err != nil {
					return total, fmt.Errorf("write Bulk blob: %w", err)
				}
				if written != count {
					return total, io.ErrShortWrite
				}
			}
			total += int64(count)
		}
		if readErr != nil {
			if errors.Is(readErr, os.ErrClosed) {
				return total, readErr
			}
			if errors.Is(readErr, io.EOF) {
				return total, nil
			}
			return total, readErr
		}
	}
}

func writeExclusiveSynced(path string, data []byte) error {
	fd, err := unix.Open(path, unix.O_WRONLY|unix.O_CREAT|unix.O_EXCL|unix.O_CLOEXEC|unix.O_NOFOLLOW, 0600)
	if err != nil {
		return err
	}
	file := os.NewFile(uintptr(fd), filepath.Base(path))
	if _, err := file.Write(data); err != nil {
		_ = file.Close()
		return err
	}
	return errors.Join(file.Sync(), file.Close())
}

func newBulkObjectID() (string, error) {
	raw := make([]byte, 32)
	if _, err := rand.Read(raw); err != nil {
		return "", err
	}
	return hex.EncodeToString(raw), nil
}

func validBulkObjectID(value string) bool {
	return len(value) == 64 && validSHA256(value)
}

func decodeBulkManifest(data []byte) ([]SnapshotEntry, error) {
	const prefix = "sunaba.bulk.manifest.v1\x00"
	if len(data) < len(prefix)+4 || string(data[:len(prefix)]) != prefix {
		return nil, fmt.Errorf("Bulk manifest header is invalid")
	}
	offset := len(prefix)
	count, ok := consumeUint32(data, &offset)
	if !ok || count > MaximumBulkEntriesPerRoot {
		return nil, fmt.Errorf("Bulk manifest entry count is invalid")
	}
	entries := make([]SnapshotEntry, 0, count)
	for i := uint32(0); i < count; i++ {
		entryPath, ok := consumeBytes(data, &offset, 4096)
		if !ok {
			return nil, fmt.Errorf("Bulk manifest path is invalid")
		}
		entryType, ok := consumeBytes(data, &offset, 16)
		if !ok {
			return nil, fmt.Errorf("Bulk manifest type is invalid")
		}
		mode, ok := consumeUint32(data, &offset)
		if !ok || mode > 0777 {
			return nil, fmt.Errorf("Bulk manifest mode is invalid")
		}
		size, ok := consumeUint64(data, &offset)
		if !ok || size > uint64(MaximumBulkLogicalBytesPerRoot) {
			return nil, fmt.Errorf("Bulk manifest size is invalid")
		}
		digest, ok := consumeBytes(data, &offset, 64)
		if !ok {
			return nil, fmt.Errorf("Bulk manifest file digest is invalid")
		}
		target, ok := consumeBytes(data, &offset, 4096)
		if !ok {
			return nil, fmt.Errorf("Bulk manifest symlink target is invalid")
		}
		entry := SnapshotEntry{Path: string(entryPath), Type: EntryType(entryType), Mode: mode, Size: int64(size), SHA256: string(digest), LinkTarget: string(target)}
		entries = append(entries, entry)
	}
	if offset != len(data) {
		return nil, fmt.Errorf("Bulk manifest has trailing data")
	}
	sort.Slice(entries, func(i, j int) bool { return entries[i].Path < entries[j].Path })
	return entries, nil
}

func consumeUint32(data []byte, offset *int) (uint32, bool) {
	if *offset > len(data)-4 {
		return 0, false
	}
	value := uint32(data[*offset])<<24 | uint32(data[*offset+1])<<16 | uint32(data[*offset+2])<<8 | uint32(data[*offset+3])
	*offset += 4
	return value, true
}

func consumeUint64(data []byte, offset *int) (uint64, bool) {
	left, ok := consumeUint32(data, offset)
	if !ok {
		return 0, false
	}
	right, ok := consumeUint32(data, offset)
	return uint64(left)<<32 | uint64(right), ok
}

func consumeBytes(data []byte, offset *int, maximum int) ([]byte, bool) {
	length, ok := consumeUint32(data, offset)
	if !ok || length > uint32(maximum) || int(length) > len(data)-*offset {
		return nil, false
	}
	value := data[*offset : *offset+int(length)]
	*offset += int(length)
	return value, true
}

// BulkObjectPaths returns only opaque host paths and is intended for tests
// and recovery code; descendant Project names never become storage names.
func BulkObjectPaths(storeRoot, objectID string) []string {
	root := filepath.Join(storeRoot, "objects", objectID)
	result := []string{filepath.Join(root, "manifest.bin"), filepath.Join(root, "object.json"), filepath.Join(root, "blobs")}
	sort.Strings(result)
	return result
}

func sanitizedBulkObjectError(value string) string {
	return strings.ReplaceAll(value, "\n", " ")
}
