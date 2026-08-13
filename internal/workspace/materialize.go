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

func CreateProjectSnapshot(root, destination string, policy SnapshotPolicy) (manifest SnapshotManifest, err error) {
	manifest, err = BuildSnapshotManifest(root, policy)
	if err != nil {
		return SnapshotManifest{}, err
	}
	verified, err := materializeSnapshot(manifest.Root, destination, manifest.Entries, policy)
	if err != nil {
		return SnapshotManifest{}, err
	}
	if verified.Digest != manifest.Digest {
		return SnapshotManifest{}, fmt.Errorf("materialized snapshot digest %s does not match source %s", verified.Digest, manifest.Digest)
	}
	return manifest, nil
}

func CreateApprovedSnapshotSubset(root, destination string, approved SnapshotManifest, roots []string, policy SnapshotPolicy) (SnapshotManifest, error) {
	if err := validateCanonicalManifest(approved, policy); err != nil {
		return SnapshotManifest{}, fmt.Errorf("invalid approved manifest: %w", err)
	}
	canonicalRoot, err := filepath.EvalSymlinks(root)
	if err != nil {
		return SnapshotManifest{}, fmt.Errorf("resolve approved snapshot root: %w", err)
	}
	canonicalRoot, err = filepath.Abs(canonicalRoot)
	if err != nil {
		return SnapshotManifest{}, err
	}
	if canonicalRoot != approved.Root {
		return SnapshotManifest{}, fmt.Errorf("approved manifest root does not match snapshot source")
	}
	entries, err := approvedSnapshotSubset(approved, roots, policy)
	if err != nil {
		return SnapshotManifest{}, err
	}
	return materializeSnapshot(canonicalRoot, destination, entries, policy)
}

func approvedSnapshotSubset(approved SnapshotManifest, roots []string, policy SnapshotPolicy) ([]SnapshotEntry, error) {
	byPath := make(map[string]SnapshotEntry, len(approved.Entries))
	for _, entry := range approved.Entries {
		byPath[entry.Path] = entry
	}
	selected := make(map[string]struct{})
	selectedRoots := make(map[string]struct{}, len(roots))
	for _, root := range roots {
		if err := validateWorkspacePath(root, policy); err != nil {
			return nil, err
		}
		_, exists := byPath[root]
		if !exists {
			continue
		}
		selectedRoots[root] = struct{}{}
		for parent := path.Dir(root); parent != "."; parent = path.Dir(parent) {
			ancestor, exists := byPath[parent]
			if !exists || ancestor.Type != TypeDirectory {
				return nil, fmt.Errorf("approved snapshot is missing directory ancestor %q", parent)
			}
			selected[parent] = struct{}{}
		}
	}
	entries := make([]SnapshotEntry, 0, len(selected))
	for _, entry := range approved.Entries {
		for candidate := entry.Path; candidate != "."; candidate = path.Dir(candidate) {
			if _, exists := selectedRoots[candidate]; exists {
				selected[entry.Path] = struct{}{}
				break
			}
		}
		if _, exists := selected[entry.Path]; exists {
			entries = append(entries, entry)
		}
	}
	return entries, nil
}

func materializeSnapshot(sourceRoot, destination string, entries []SnapshotEntry, policy SnapshotPolicy) (verified SnapshotManifest, err error) {
	destination, err = filepath.Abs(destination)
	if err != nil {
		return SnapshotManifest{}, err
	}
	parent, err := filepath.EvalSymlinks(filepath.Dir(destination))
	if err != nil {
		return SnapshotManifest{}, fmt.Errorf("resolve snapshot destination parent: %w", err)
	}
	destination = filepath.Join(parent, filepath.Base(destination))
	if err := validateEntryName(filepath.Base(destination)); err != nil {
		return SnapshotManifest{}, fmt.Errorf("invalid snapshot destination: %w", err)
	}
	if pathWithin(sourceRoot, destination) {
		return SnapshotManifest{}, fmt.Errorf("snapshot destination must not be inside Project root")
	}
	if err := os.Mkdir(destination, 0700); err != nil {
		return SnapshotManifest{}, fmt.Errorf("create snapshot destination: %w", err)
	}
	created := true
	defer func() {
		if err != nil && created {
			_ = os.RemoveAll(destination)
		}
	}()

	sourceFD, err := unix.Open(sourceRoot, unix.O_RDONLY|unix.O_DIRECTORY|unix.O_CLOEXEC|unix.O_NOFOLLOW, 0)
	if err != nil {
		return SnapshotManifest{}, fmt.Errorf("open Project root for materialization: %w", err)
	}
	defer unix.Close(sourceFD)
	destinationFD, err := unix.Open(destination, unix.O_RDONLY|unix.O_DIRECTORY|unix.O_CLOEXEC|unix.O_NOFOLLOW, 0)
	if err != nil {
		return SnapshotManifest{}, fmt.Errorf("open snapshot destination: %w", err)
	}
	defer unix.Close(destinationFD)

	directories := make([]SnapshotEntry, 0)
	for _, entry := range entries {
		switch entry.Type {
		case TypeDirectory:
			if err := createDirectoryAt(destinationFD, entry.Path); err != nil {
				return SnapshotManifest{}, err
			}
			directories = append(directories, entry)
		case TypeFile:
			if err := copyFileAt(sourceFD, destinationFD, entry, policy.MaxFileSize); err != nil {
				return SnapshotManifest{}, err
			}
		case TypeSymlink:
			if err := copySymlinkAt(sourceFD, destinationFD, entry, policy.MaxSymlinkSize); err != nil {
				return SnapshotManifest{}, err
			}
		default:
			return SnapshotManifest{}, fmt.Errorf("unknown snapshot entry type %q", entry.Type)
		}
	}
	sort.Slice(directories, func(i, j int) bool {
		return strings.Count(directories[i].Path, "/") > strings.Count(directories[j].Path, "/")
	})
	for _, directory := range directories {
		fd, err := openPathAt(destinationFD, directory.Path, unix.O_RDONLY|unix.O_DIRECTORY)
		if err != nil {
			return SnapshotManifest{}, err
		}
		err = unix.Fchmod(fd, directory.Mode&0777)
		_ = unix.Close(fd)
		if err != nil {
			return SnapshotManifest{}, fmt.Errorf("set snapshot directory mode %q: %w", directory.Path, err)
		}
	}
	if err := unix.Fsync(destinationFD); err != nil {
		return SnapshotManifest{}, fmt.Errorf("sync snapshot root: %w", err)
	}
	verifyPolicy := policy
	verifyPolicy.ProtectedPaths = nil
	verified, err = BuildSnapshotManifest(destination, verifyPolicy)
	if err != nil {
		return SnapshotManifest{}, fmt.Errorf("verify materialized snapshot: %w", err)
	}
	var totalSize int64
	for _, entry := range entries {
		if entry.Type == TypeFile {
			totalSize += entry.Size
		}
	}
	expected, err := finalizeSnapshotManifest(destination, entries, totalSize)
	if err != nil {
		return SnapshotManifest{}, err
	}
	if verified.Digest != expected.Digest {
		return SnapshotManifest{}, fmt.Errorf("materialized snapshot digest %s does not match approved subset %s", verified.Digest, expected.Digest)
	}
	created = false
	return verified, nil
}

func createDirectoryAt(rootFD int, entryPath string) error {
	parentFD, name, err := openParentAt(rootFD, entryPath)
	if err != nil {
		return err
	}
	defer unix.Close(parentFD)
	if err := unix.Mkdirat(parentFD, name, 0700); err != nil {
		return fmt.Errorf("create snapshot directory %q: %w", entryPath, err)
	}
	return nil
}

func copyFileAt(sourceRootFD, destinationRootFD int, entry SnapshotEntry, maximum int64) error {
	sourceFD, err := openPathAt(sourceRootFD, entry.Path, unix.O_RDONLY)
	if err != nil {
		return fmt.Errorf("open snapshot source %q: %w", entry.Path, err)
	}
	source := os.NewFile(uintptr(sourceFD), entry.Path)
	defer source.Close()
	var sourceStat unix.Stat_t
	if err := unix.Fstat(sourceFD, &sourceStat); err != nil {
		return err
	}
	if uint32(sourceStat.Mode)&uint32(unix.S_IFMT) != uint32(unix.S_IFREG) || sourceStat.Size != entry.Size || uint32(sourceStat.Mode)&0777 != entry.Mode {
		return fmt.Errorf("snapshot source %q changed before materialization", entry.Path)
	}
	parentFD, name, err := openParentAt(destinationRootFD, entry.Path)
	if err != nil {
		return err
	}
	defer unix.Close(parentFD)
	destinationFD, err := unix.Openat(parentFD, name, unix.O_WRONLY|unix.O_CREAT|unix.O_EXCL|unix.O_CLOEXEC|unix.O_NOFOLLOW, entry.Mode&0777)
	if err != nil {
		return fmt.Errorf("create snapshot file %q: %w", entry.Path, err)
	}
	destination := os.NewFile(uintptr(destinationFD), entry.Path)
	defer destination.Close()
	hash := sha256.New()
	written, err := io.Copy(io.MultiWriter(destination, hash), io.LimitReader(source, maximum+1))
	if err != nil {
		return fmt.Errorf("copy snapshot file %q: %w", entry.Path, err)
	}
	if written != entry.Size || hex.EncodeToString(hash.Sum(nil)) != entry.SHA256 {
		return fmt.Errorf("snapshot source %q changed during materialization", entry.Path)
	}
	if err := unix.Fchmod(destinationFD, entry.Mode&0777); err != nil {
		return err
	}
	if err := unix.Fsync(destinationFD); err != nil {
		return fmt.Errorf("sync snapshot file %q: %w", entry.Path, err)
	}
	return nil
}

func copySymlinkAt(sourceRootFD, destinationRootFD int, entry SnapshotEntry, maximum int) error {
	sourceParentFD, sourceName, err := openParentAt(sourceRootFD, entry.Path)
	if err != nil {
		return err
	}
	defer unix.Close(sourceParentFD)
	target, err := readLinkAt(sourceParentFD, sourceName, maximum)
	if err != nil {
		return fmt.Errorf("read snapshot symlink %q: %w", entry.Path, err)
	}
	if target != entry.LinkTarget {
		return fmt.Errorf("snapshot symlink %q changed during materialization", entry.Path)
	}
	destinationParentFD, destinationName, err := openParentAt(destinationRootFD, entry.Path)
	if err != nil {
		return err
	}
	defer unix.Close(destinationParentFD)
	if err := unix.Symlinkat(target, destinationParentFD, destinationName); err != nil {
		return fmt.Errorf("create snapshot symlink %q: %w", entry.Path, err)
	}
	return nil
}

func openPathAt(rootFD int, entryPath string, flags int) (int, error) {
	components := strings.Split(entryPath, "/")
	current, err := unix.Dup(rootFD)
	if err != nil {
		return -1, err
	}
	for index, component := range components {
		if err := validateEntryName(component); err != nil {
			_ = unix.Close(current)
			return -1, err
		}
		openFlags := unix.O_RDONLY | unix.O_DIRECTORY | unix.O_CLOEXEC | unix.O_NOFOLLOW
		if index == len(components)-1 {
			openFlags = flags | unix.O_CLOEXEC | unix.O_NOFOLLOW
		}
		next, err := unix.Openat(current, component, openFlags, 0)
		_ = unix.Close(current)
		if err != nil {
			return -1, fmt.Errorf("open path %q: %w", entryPath, err)
		}
		current = next
	}
	return current, nil
}

func openParentAt(rootFD int, entryPath string) (int, string, error) {
	components := strings.Split(entryPath, "/")
	if len(components) == 0 {
		return -1, "", fmt.Errorf("empty entry path")
	}
	name := components[len(components)-1]
	if err := validateEntryName(name); err != nil {
		return -1, "", err
	}
	if len(components) == 1 {
		fd, err := unix.Dup(rootFD)
		return fd, name, err
	}
	fd, err := openPathAt(rootFD, strings.Join(components[:len(components)-1], "/"), unix.O_RDONLY|unix.O_DIRECTORY)
	return fd, name, err
}

func pathWithin(root, candidate string) bool {
	relative, err := filepath.Rel(root, candidate)
	if err != nil {
		return true
	}
	return relative == "." || (relative != ".." && !strings.HasPrefix(relative, ".."+string(filepath.Separator)))
}
