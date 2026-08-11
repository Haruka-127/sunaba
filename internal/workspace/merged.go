package workspace

import (
	"crypto/sha256"
	"encoding/hex"
	"fmt"
	"io"
	"os"
	"path"
	"path/filepath"
	"sort"
	"strings"

	"golang.org/x/sys/unix"
)

type MergedView struct {
	Manifest SnapshotManifest
	Root     string
}

type mergedEntry struct {
	manifest  SnapshotEntry
	lowerPath string
	dataPath  string
}

func MaterializeMergedView(snapshotRoot, destination string, baseline SnapshotManifest, frozen FrozenExport, policy SnapshotPolicy) (view MergedView, err error) {
	if err := policy.validate(); err != nil {
		return MergedView{}, err
	}
	if err := validateCanonicalManifest(baseline, policy); err != nil {
		return MergedView{}, fmt.Errorf("invalid trusted baseline: %w", err)
	}
	if frozen.Lower.Digest != baseline.Digest {
		return MergedView{}, fmt.Errorf("frozen lower does not match trusted baseline")
	}
	destination, err = filepath.Abs(destination)
	if err != nil {
		return MergedView{}, err
	}
	if !strings.HasPrefix(filepath.Base(destination), "sunaba-merged-") {
		return MergedView{}, fmt.Errorf("merged destination must have sunaba-merged- prefix")
	}
	if err := validateQuarantine(filepath.Dir(destination)); err != nil {
		return MergedView{}, err
	}
	verifyPolicy := policy
	verifyPolicy.ProtectedPaths = nil
	trusted, err := BuildSnapshotManifest(snapshotRoot, verifyPolicy)
	if err != nil {
		return MergedView{}, fmt.Errorf("verify trusted snapshot: %w", err)
	}
	if trusted.Digest != baseline.Digest {
		return MergedView{}, fmt.Errorf("trusted snapshot digest changed")
	}
	if err := validateFrozenUpper(frozen.Upper, policy); err != nil {
		return MergedView{}, err
	}

	state := make(map[string]mergedEntry, len(baseline.Entries)+len(frozen.Upper))
	baselineByPath := make(map[string]SnapshotEntry, len(baseline.Entries))
	for _, entry := range baseline.Entries {
		if err := validateWorkspacePath(entry.Path, policy); err != nil {
			return MergedView{}, err
		}
		if _, exists := state[entry.Path]; exists {
			return MergedView{}, fmt.Errorf("duplicate baseline path %q", entry.Path)
		}
		state[entry.Path] = mergedEntry{manifest: entry, lowerPath: entry.Path}
		baselineByPath[entry.Path] = entry
	}
	if err := applyRedirects(state, baselineByPath, frozen.Upper); err != nil {
		return MergedView{}, err
	}
	for _, entry := range frozen.Upper {
		if entry.Whiteout {
			removeMergedSubtree(state, entry.Path, true)
		}
	}
	for _, entry := range frozen.Upper {
		if entry.Opaque {
			removeMergedSubtree(state, entry.Path, false)
		}
	}
	upper := append([]OverlayEntry(nil), frozen.Upper...)
	sort.Slice(upper, func(i, j int) bool {
		leftDepth, rightDepth := strings.Count(upper[i].Path, "/"), strings.Count(upper[j].Path, "/")
		if leftDepth != rightDepth {
			return leftDepth < rightDepth
		}
		return upper[i].Path < upper[j].Path
	})
	for _, entry := range upper {
		if entry.Whiteout {
			continue
		}
		item, err := mergedEntryFromUpper(entry, baselineByPath, frozen.StagingDir)
		if err != nil {
			return MergedView{}, err
		}
		if item.manifest.Type != TypeDirectory {
			removeMergedSubtree(state, entry.Path, true)
		} else if existing, exists := state[entry.Path]; exists && existing.manifest.Type != TypeDirectory {
			delete(state, entry.Path)
		}
		state[entry.Path] = item
	}
	if len(state) > policy.MaxEntries {
		return MergedView{}, fmt.Errorf("merged workspace exceeds entry limit")
	}
	if err := validateMergedParents(state); err != nil {
		return MergedView{}, err
	}

	entries := make([]SnapshotEntry, 0, len(state))
	var total int64
	for _, item := range state {
		entries = append(entries, item.manifest)
		if item.manifest.Type == TypeFile {
			total += item.manifest.Size
			if total > policy.MaxTotalSize {
				return MergedView{}, fmt.Errorf("merged workspace exceeds total size")
			}
		}
	}
	manifest, err := finalizeSnapshotManifest(destination, entries, total)
	if err != nil {
		return MergedView{}, err
	}
	if err := materializeMergedState(snapshotRoot, destination, state, manifest, policy); err != nil {
		return MergedView{}, err
	}
	return MergedView{Manifest: manifest, Root: destination}, nil
}

func validateFrozenUpper(upper []OverlayEntry, policy SnapshotPolicy) error {
	if len(upper) > policy.MaxEntries {
		return fmt.Errorf("frozen upper exceeds entry limit")
	}
	seen := make(map[string]struct{}, len(upper))
	for _, entry := range upper {
		if err := validateWorkspacePath(entry.Path, policy); err != nil {
			return err
		}
		if _, exists := seen[entry.Path]; exists {
			return fmt.Errorf("duplicate frozen upper path %q", entry.Path)
		}
		seen[entry.Path] = struct{}{}
		if entry.Redirect != "" {
			if err := validateWorkspacePath(entry.Redirect, policy); err != nil {
				return err
			}
		}
		if entry.Mode > 0777 {
			return fmt.Errorf("frozen upper path %q has unsafe mode", entry.Path)
		}
		if entry.Whiteout {
			if entry.Type != "" || entry.Size != 0 || entry.SHA256 != "" || entry.LinkTarget != "" || entry.DataPath != "" || entry.Opaque || entry.Metacopy || entry.Redirect != "" {
				return fmt.Errorf("whiteout %q has incompatible metadata", entry.Path)
			}
			continue
		}
		switch entry.Type {
		case TypeDirectory:
			if entry.Size != 0 || entry.SHA256 != "" || entry.LinkTarget != "" || entry.DataPath != "" || entry.Metacopy {
				return fmt.Errorf("frozen upper directory %q has invalid metadata", entry.Path)
			}
		case TypeFile:
			if entry.Size < 0 || entry.Size > policy.MaxFileSize || entry.LinkTarget != "" || entry.Opaque {
				return fmt.Errorf("frozen upper file %q has invalid metadata", entry.Path)
			}
			hash, err := hex.DecodeString(entry.SHA256)
			if err != nil || len(hash) != sha256.Size {
				return fmt.Errorf("frozen upper file %q has invalid digest", entry.Path)
			}
			if (entry.Metacopy && entry.DataPath != "") || (!entry.Metacopy && entry.DataPath == "") {
				return fmt.Errorf("frozen upper file %q has invalid data source", entry.Path)
			}
		case TypeSymlink:
			if entry.Mode != 0777 || entry.Size != 0 || entry.SHA256 != "" || entry.LinkTarget == "" || strings.ContainsRune(entry.LinkTarget, '\x00') || len(entry.LinkTarget) > policy.MaxSymlinkSize || entry.DataPath != "" || entry.Opaque || entry.Metacopy || entry.Redirect != "" {
				return fmt.Errorf("frozen upper symlink %q has invalid metadata", entry.Path)
			}
		default:
			return fmt.Errorf("frozen upper path %q has unsupported type %q", entry.Path, entry.Type)
		}
	}
	return nil
}

func applyRedirects(state map[string]mergedEntry, baseline map[string]SnapshotEntry, upper []OverlayEntry) error {
	redirects := make([]OverlayEntry, 0)
	for _, entry := range upper {
		if entry.Redirect != "" {
			redirects = append(redirects, entry)
		}
	}
	sort.Slice(redirects, func(i, j int) bool { return redirects[i].Path < redirects[j].Path })
	for i, entry := range redirects {
		if entry.Path == entry.Redirect || pathsOverlap(entry.Path, entry.Redirect) {
			return fmt.Errorf("overlapping redirect %q <- %q", entry.Path, entry.Redirect)
		}
		for j := 0; j < i; j++ {
			other := redirects[j]
			if pathsOverlap(entry.Path, other.Path) || pathsOverlap(entry.Path, other.Redirect) || pathsOverlap(entry.Redirect, other.Path) || pathsOverlap(entry.Redirect, other.Redirect) {
				return fmt.Errorf("overlapping redirects are not supported")
			}
		}
		source, exists := baseline[entry.Redirect]
		if !exists || source.Type != entry.Type {
			return fmt.Errorf("redirect %q has missing or incompatible baseline source", entry.Path)
		}
		removeMergedSubtree(state, entry.Redirect, true)
		removeMergedSubtree(state, entry.Path, true)
		for sourcePath, sourceEntry := range baseline {
			if sourcePath != entry.Redirect && !strings.HasPrefix(sourcePath, entry.Redirect+"/") {
				continue
			}
			suffix := strings.TrimPrefix(sourcePath, entry.Redirect)
			destinationPath := entry.Path + suffix
			cloned := sourceEntry
			cloned.Path = destinationPath
			state[destinationPath] = mergedEntry{manifest: cloned, lowerPath: sourcePath}
		}
	}
	return nil
}

func mergedEntryFromUpper(entry OverlayEntry, baseline map[string]SnapshotEntry, staging string) (mergedEntry, error) {
	manifest := SnapshotEntry{
		Path: entry.Path, Type: entry.Type, Mode: entry.Mode & 0777, Size: entry.Size,
		SHA256: entry.SHA256, LinkTarget: entry.LinkTarget,
	}
	item := mergedEntry{manifest: manifest}
	switch entry.Type {
	case TypeDirectory:
		manifest.Size, manifest.SHA256, manifest.LinkTarget = 0, "", ""
		item.manifest = manifest
	case TypeFile:
		if entry.Metacopy {
			sourcePath := entry.Path
			if entry.Redirect != "" {
				sourcePath = entry.Redirect
			}
			source, exists := baseline[sourcePath]
			if !exists || source.Type != TypeFile || source.Size != entry.Size || source.SHA256 != entry.SHA256 {
				return mergedEntry{}, fmt.Errorf("metacopy %q does not match trusted lower", entry.Path)
			}
			item.lowerPath = sourcePath
		} else {
			if err := validateStagedDataPath(staging, entry.DataPath); err != nil {
				return mergedEntry{}, fmt.Errorf("upper file %q: %w", entry.Path, err)
			}
			item.dataPath = entry.DataPath
		}
	case TypeSymlink:
		manifest.Mode, manifest.Size, manifest.SHA256 = 0777, 0, ""
		item.manifest = manifest
	default:
		return mergedEntry{}, fmt.Errorf("upper entry %q has unsupported type %q", entry.Path, entry.Type)
	}
	return item, nil
}

func validateStagedDataPath(staging, dataPath string) error {
	if staging == "" || dataPath == "" || filepath.Dir(dataPath) != staging || !strings.HasPrefix(filepath.Base(dataPath), "entry-") {
		return fmt.Errorf("invalid staged data path")
	}
	info, err := os.Lstat(staging)
	if err != nil || !info.IsDir() || info.Mode().Perm() != 0700 || !strings.HasPrefix(filepath.Base(staging), "sunaba-export-") {
		return fmt.Errorf("invalid staging directory")
	}
	info, err = os.Lstat(dataPath)
	if err != nil || !info.Mode().IsRegular() || info.Mode().Perm() != 0600 {
		return fmt.Errorf("staged data is not a mode 0600 regular file")
	}
	return nil
}

func validateMergedParents(state map[string]mergedEntry) error {
	for entryPath := range state {
		parent := path.Dir(entryPath)
		for parent != "." {
			entry, exists := state[parent]
			if !exists || entry.manifest.Type != TypeDirectory {
				return fmt.Errorf("merged path %q has missing or non-directory parent %q", entryPath, parent)
			}
			parent = path.Dir(parent)
		}
	}
	return nil
}

func removeMergedSubtree(state map[string]mergedEntry, root string, includeRoot bool) {
	for entryPath := range state {
		if (includeRoot && entryPath == root) || strings.HasPrefix(entryPath, root+"/") {
			delete(state, entryPath)
		}
	}
}

func pathsOverlap(left, right string) bool {
	return left == right || strings.HasPrefix(left, right+"/") || strings.HasPrefix(right, left+"/")
}

func materializeMergedState(snapshotRoot, destination string, state map[string]mergedEntry, manifest SnapshotManifest, policy SnapshotPolicy) (err error) {
	if err := os.Mkdir(destination, 0700); err != nil {
		return fmt.Errorf("create merged destination: %w", err)
	}
	defer func() {
		if err != nil {
			_ = os.RemoveAll(destination)
		}
	}()
	lowerFD, err := unix.Open(snapshotRoot, unix.O_RDONLY|unix.O_DIRECTORY|unix.O_CLOEXEC|unix.O_NOFOLLOW, 0)
	if err != nil {
		return err
	}
	defer unix.Close(lowerFD)
	destinationFD, err := unix.Open(destination, unix.O_RDONLY|unix.O_DIRECTORY|unix.O_CLOEXEC|unix.O_NOFOLLOW, 0)
	if err != nil {
		return err
	}
	defer unix.Close(destinationFD)

	ordered := append([]SnapshotEntry(nil), manifest.Entries...)
	sort.Slice(ordered, func(i, j int) bool {
		leftDepth, rightDepth := strings.Count(ordered[i].Path, "/"), strings.Count(ordered[j].Path, "/")
		if leftDepth != rightDepth {
			return leftDepth < rightDepth
		}
		return ordered[i].Path < ordered[j].Path
	})
	directories := make([]SnapshotEntry, 0)
	for _, entry := range ordered {
		item := state[entry.Path]
		switch entry.Type {
		case TypeDirectory:
			if err := createDirectoryAt(destinationFD, entry.Path); err != nil {
				return err
			}
			directories = append(directories, entry)
		case TypeFile:
			if err := copyMergedFile(lowerFD, destinationFD, item, policy.MaxFileSize); err != nil {
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
				return fmt.Errorf("create merged symlink %q: %w", entry.Path, err)
			}
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
		_ = unix.Close(fd)
		if err != nil {
			return err
		}
	}
	if err := unix.Fsync(destinationFD); err != nil {
		return err
	}
	verifyPolicy := policy
	verifyPolicy.ProtectedPaths = nil
	verified, err := BuildSnapshotManifest(destination, verifyPolicy)
	if err != nil {
		return err
	}
	if verified.Digest != manifest.Digest {
		return fmt.Errorf("materialized merged digest does not match computed manifest")
	}
	return nil
}

func copyMergedFile(lowerRootFD, destinationRootFD int, item mergedEntry, maximum int64) error {
	var sourceFD int
	var err error
	if item.lowerPath != "" {
		sourceFD, err = openPathAt(lowerRootFD, item.lowerPath, unix.O_RDONLY)
	} else {
		sourceFD, err = unix.Open(item.dataPath, unix.O_RDONLY|unix.O_CLOEXEC|unix.O_NOFOLLOW, 0)
	}
	if err != nil {
		return fmt.Errorf("open merged source for %q: %w", item.manifest.Path, err)
	}
	source := os.NewFile(uintptr(sourceFD), item.manifest.Path)
	defer source.Close()
	var stat unix.Stat_t
	if err := unix.Fstat(sourceFD, &stat); err != nil {
		return err
	}
	if uint32(stat.Mode)&uint32(unix.S_IFMT) != uint32(unix.S_IFREG) || stat.Size != item.manifest.Size {
		return fmt.Errorf("merged source for %q changed", item.manifest.Path)
	}
	parentFD, name, err := openParentAt(destinationRootFD, item.manifest.Path)
	if err != nil {
		return err
	}
	defer unix.Close(parentFD)
	outputFD, err := unix.Openat(parentFD, name, unix.O_WRONLY|unix.O_CREAT|unix.O_EXCL|unix.O_CLOEXEC|unix.O_NOFOLLOW, 0600)
	if err != nil {
		return err
	}
	output := os.NewFile(uintptr(outputFD), item.manifest.Path)
	defer output.Close()
	hash := sha256.New()
	written, err := io.Copy(io.MultiWriter(output, hash), io.LimitReader(source, maximum+1))
	if err != nil {
		return err
	}
	if written != item.manifest.Size || hex.EncodeToString(hash.Sum(nil)) != item.manifest.SHA256 {
		return fmt.Errorf("merged source content for %q changed", item.manifest.Path)
	}
	if err := unix.Fchmod(outputFD, item.manifest.Mode&0777); err != nil {
		return err
	}
	return unix.Fsync(outputFD)
}
