package workspace

import (
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"os"
	"path"
	"path/filepath"
	"sort"
	"strings"

	"golang.org/x/sys/unix"
)

const manifestVersion = 1

type EntryType string

const (
	TypeFile      EntryType = "file"
	TypeDirectory EntryType = "directory"
	TypeSymlink   EntryType = "symlink"
)

type SnapshotPolicy struct {
	MaxDepth       int
	MaxEntries     int
	MaxFileSize    int64
	MaxTotalSize   int64
	MaxSymlinkSize int
	ProtectedPaths []string
}

func DefaultSnapshotPolicy() SnapshotPolicy {
	return SnapshotPolicy{
		MaxDepth:       64,
		MaxEntries:     100_000,
		MaxFileSize:    64 << 20,
		MaxTotalSize:   1 << 30,
		MaxSymlinkSize: 4096,
		ProtectedPaths: []string{".git", ".sunaba"},
	}
}

type SnapshotEntry struct {
	Path       string    `json:"path"`
	Type       EntryType `json:"type"`
	Mode       uint32    `json:"mode"`
	Size       int64     `json:"size,omitempty"`
	SHA256     string    `json:"sha256,omitempty"`
	LinkTarget string    `json:"link_target,omitempty"`
}

type SnapshotManifest struct {
	Version   int             `json:"version"`
	Root      string          `json:"root"`
	Entries   []SnapshotEntry `json:"entries"`
	TotalSize int64           `json:"total_size"`
	Digest    string          `json:"digest"`
}

type manifestDigestInput struct {
	Version   int             `json:"version"`
	Entries   []SnapshotEntry `json:"entries"`
	TotalSize int64           `json:"total_size"`
}

type snapshotWalker struct {
	policy SnapshotPolicy
	result SnapshotManifest
}

func BuildSnapshotManifest(root string, policy SnapshotPolicy) (SnapshotManifest, error) {
	if err := policy.validate(); err != nil {
		return SnapshotManifest{}, err
	}
	canonical, err := filepath.EvalSymlinks(root)
	if err != nil {
		return SnapshotManifest{}, fmt.Errorf("resolve snapshot root: %w", err)
	}
	canonical, err = filepath.Abs(canonical)
	if err != nil {
		return SnapshotManifest{}, err
	}
	rootFD, err := unix.Open(canonical, unix.O_RDONLY|unix.O_DIRECTORY|unix.O_CLOEXEC|unix.O_NOFOLLOW, 0)
	if err != nil {
		return SnapshotManifest{}, fmt.Errorf("open snapshot root: %w", err)
	}
	defer unix.Close(rootFD)
	var rootStat unix.Stat_t
	if err := unix.Fstat(rootFD, &rootStat); err != nil {
		return SnapshotManifest{}, fmt.Errorf("stat snapshot root: %w", err)
	}
	if uint32(rootStat.Mode)&uint32(unix.S_IFMT) != uint32(unix.S_IFDIR) {
		return SnapshotManifest{}, fmt.Errorf("snapshot root is not a directory")
	}

	walker := snapshotWalker{
		policy: policy,
		result: SnapshotManifest{Version: manifestVersion, Root: canonical},
	}
	if err := walker.walkDirectory(rootFD, "", 0); err != nil {
		return SnapshotManifest{}, err
	}
	return finalizeSnapshotManifest(walker.result.Root, walker.result.Entries, walker.result.TotalSize)
}

func finalizeSnapshotManifest(root string, entries []SnapshotEntry, totalSize int64) (SnapshotManifest, error) {
	canonicalEntries := append([]SnapshotEntry(nil), entries...)
	sort.Slice(canonicalEntries, func(i, j int) bool { return canonicalEntries[i].Path < canonicalEntries[j].Path })
	digestInput, err := json.Marshal(manifestDigestInput{
		Version: manifestVersion, Entries: canonicalEntries, TotalSize: totalSize,
	})
	if err != nil {
		return SnapshotManifest{}, err
	}
	digest := sha256.Sum256(digestInput)
	return SnapshotManifest{
		Version: manifestVersion, Root: root, Entries: canonicalEntries, TotalSize: totalSize,
		Digest: hex.EncodeToString(digest[:]),
	}, nil
}

func (p SnapshotPolicy) validate() error {
	if p.MaxDepth <= 0 || p.MaxEntries <= 0 || p.MaxFileSize < 0 || p.MaxTotalSize < 0 || p.MaxSymlinkSize <= 0 {
		return fmt.Errorf("snapshot limits must be positive")
	}
	for _, protected := range p.ProtectedPaths {
		if protected == "" || protected == "." || protected == ".." || strings.ContainsAny(protected, "/\\\x00") {
			return fmt.Errorf("invalid protected path %q", protected)
		}
	}
	return nil
}

func (w *snapshotWalker) walkDirectory(parentFD int, relative string, depth int) error {
	if depth > w.policy.MaxDepth {
		return fmt.Errorf("snapshot path depth exceeds %d at %q", w.policy.MaxDepth, relative)
	}
	entries, err := readDirectoryEntries(parentFD)
	if err != nil {
		return fmt.Errorf("read directory %q: %w", relative, err)
	}
	sort.Slice(entries, func(i, j int) bool { return entries[i].Name() < entries[j].Name() })
	for _, directoryEntry := range entries {
		name := directoryEntry.Name()
		if err := validateEntryName(name); err != nil {
			return err
		}
		entryPath := name
		if relative != "" {
			entryPath = path.Join(relative, name)
		}
		if w.isProtected(entryPath) {
			continue
		}
		if len(w.result.Entries) >= w.policy.MaxEntries {
			return fmt.Errorf("snapshot entry count exceeds %d", w.policy.MaxEntries)
		}
		var before unix.Stat_t
		if err := unix.Fstatat(parentFD, name, &before, unix.AT_SYMLINK_NOFOLLOW); err != nil {
			return fmt.Errorf("lstat %q: %w", entryPath, err)
		}
		modeType := uint32(before.Mode) & uint32(unix.S_IFMT)
		switch modeType {
		case uint32(unix.S_IFDIR):
			w.result.Entries = append(w.result.Entries, SnapshotEntry{
				Path: entryPath, Type: TypeDirectory, Mode: uint32(before.Mode) & 0777,
			})
			childFD, err := unix.Openat(parentFD, name, unix.O_RDONLY|unix.O_DIRECTORY|unix.O_CLOEXEC|unix.O_NOFOLLOW, 0)
			if err != nil {
				return fmt.Errorf("open directory %q: %w", entryPath, err)
			}
			err = verifyIdentity(childFD, before, entryPath)
			if err == nil {
				err = w.walkDirectory(childFD, entryPath, depth+1)
			}
			_ = unix.Close(childFD)
			if err != nil {
				return err
			}
		case uint32(unix.S_IFREG):
			entry, err := w.readRegularFile(parentFD, name, entryPath, before)
			if err != nil {
				return err
			}
			w.result.Entries = append(w.result.Entries, entry)
		case uint32(unix.S_IFLNK):
			target, err := readLinkAt(parentFD, name, w.policy.MaxSymlinkSize)
			if err != nil {
				return fmt.Errorf("read symlink %q: %w", entryPath, err)
			}
			w.result.Entries = append(w.result.Entries, SnapshotEntry{
				Path: entryPath, Type: TypeSymlink, Mode: 0777, LinkTarget: target,
			})
		default:
			return fmt.Errorf("snapshot rejects special file %q (mode %#o)", entryPath, before.Mode)
		}
	}
	return nil
}

func (w *snapshotWalker) readRegularFile(parentFD int, name, entryPath string, before unix.Stat_t) (SnapshotEntry, error) {
	if before.Size < 0 || before.Size > w.policy.MaxFileSize {
		return SnapshotEntry{}, fmt.Errorf("file %q exceeds maximum size %d", entryPath, w.policy.MaxFileSize)
	}
	if w.result.TotalSize+before.Size > w.policy.MaxTotalSize {
		return SnapshotEntry{}, fmt.Errorf("snapshot total size exceeds %d", w.policy.MaxTotalSize)
	}
	fd, err := unix.Openat(parentFD, name, unix.O_RDONLY|unix.O_CLOEXEC|unix.O_NOFOLLOW, 0)
	if err != nil {
		return SnapshotEntry{}, fmt.Errorf("open file %q: %w", entryPath, err)
	}
	file := os.NewFile(uintptr(fd), entryPath)
	defer file.Close()
	if err := verifyIdentity(fd, before, entryPath); err != nil {
		return SnapshotEntry{}, err
	}
	hash := sha256.New()
	written, err := io.Copy(hash, io.LimitReader(file, w.policy.MaxFileSize+1))
	if err != nil {
		return SnapshotEntry{}, fmt.Errorf("hash file %q: %w", entryPath, err)
	}
	if written != before.Size {
		return SnapshotEntry{}, fmt.Errorf("file %q changed while snapshotting", entryPath)
	}
	var after unix.Stat_t
	if err := unix.Fstat(fd, &after); err != nil {
		return SnapshotEntry{}, err
	}
	if !sameIdentity(before, after) || after.Size != before.Size {
		return SnapshotEntry{}, fmt.Errorf("file %q changed while snapshotting", entryPath)
	}
	w.result.TotalSize += written
	return SnapshotEntry{
		Path: entryPath, Type: TypeFile, Mode: uint32(after.Mode) & 0777,
		Size: written, SHA256: hex.EncodeToString(hash.Sum(nil)),
	}, nil
}

func readDirectoryEntries(fd int) ([]os.DirEntry, error) {
	duplicate, err := unix.Dup(fd)
	if err != nil {
		return nil, err
	}
	file := os.NewFile(uintptr(duplicate), "snapshot-directory")
	if file == nil {
		_ = unix.Close(duplicate)
		return nil, errors.New("create directory file handle")
	}
	defer file.Close()
	return file.ReadDir(-1)
}

func verifyIdentity(fd int, before unix.Stat_t, entryPath string) error {
	var after unix.Stat_t
	if err := unix.Fstat(fd, &after); err != nil {
		return err
	}
	if !sameIdentity(before, after) {
		return fmt.Errorf("entry %q changed while snapshotting", entryPath)
	}
	return nil
}

func sameIdentity(a, b unix.Stat_t) bool {
	return uint64(a.Dev) == uint64(b.Dev) && a.Ino == b.Ino && (uint32(a.Mode)&uint32(unix.S_IFMT)) == (uint32(b.Mode)&uint32(unix.S_IFMT))
}

func readLinkAt(parentFD int, name string, maximum int) (string, error) {
	buffer := make([]byte, maximum+1)
	length, err := unix.Readlinkat(parentFD, name, buffer)
	if err != nil {
		return "", err
	}
	if length > maximum {
		return "", fmt.Errorf("symlink target exceeds %d bytes", maximum)
	}
	return string(buffer[:length]), nil
}

func validateEntryName(name string) error {
	if name == "" || name == "." || name == ".." || strings.ContainsAny(name, "/\\\x00") {
		return fmt.Errorf("invalid snapshot entry name %q", name)
	}
	return nil
}

func (w *snapshotWalker) isProtected(entryPath string) bool {
	first := strings.Split(entryPath, "/")[0]
	for _, protected := range w.policy.ProtectedPaths {
		if strings.EqualFold(first, protected) {
			return true
		}
	}
	return false
}
