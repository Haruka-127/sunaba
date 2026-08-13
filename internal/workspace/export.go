package workspace

import (
	"archive/tar"
	"crypto/sha256"
	"encoding/hex"
	"fmt"
	"io"
	"os"
	"path"
	"path/filepath"
	"regexp"
	"strings"
)

const (
	lowerPrefix                 = "var/lib/sunaba/lower"
	upperPrefix                 = "var/lib/sunaba/upper"
	mergedPrefix                = "var/lib/sunaba/merged-export"
	MaximumArchiveEntries       = 500_000
	MaximumArchiveSize    int64 = 8 << 30
)

var whiteoutLinkPattern = regexp.MustCompile(`^var/lib/sunaba/work/(?:index|work)/#[0-9]+$`)

type ExportPolicy struct {
	Workspace         SnapshotPolicy
	MaxArchiveEntries int
	MaxArchiveSize    int64
}

func DefaultExportPolicy() ExportPolicy {
	return ExportPolicy{
		Workspace:         DefaultSnapshotPolicy(),
		MaxArchiveEntries: MaximumArchiveEntries,
		MaxArchiveSize:    MaximumArchiveSize,
	}
}

type OverlayEntry struct {
	Path       string
	Type       EntryType
	Mode       uint32
	Size       int64
	SHA256     string
	LinkTarget string
	DataPath   string
	Whiteout   bool
	Opaque     bool
	Metacopy   bool
	Redirect   string
}

type FrozenExport struct {
	Lower      SnapshotManifest
	Upper      []OverlayEntry
	StagingDir string
}

func (e *FrozenExport) Close() error {
	if e.StagingDir == "" {
		return nil
	}
	staging := e.StagingDir
	if !filepath.IsAbs(staging) || !strings.HasPrefix(filepath.Base(staging), "sunaba-export-") {
		return fmt.Errorf("refusing to remove invalid export staging path")
	}
	if err := validateQuarantine(filepath.Dir(staging)); err != nil {
		return fmt.Errorf("refusing to remove export staging: %w", err)
	}
	info, err := os.Lstat(staging)
	if err != nil {
		return err
	}
	if !info.IsDir() || info.Mode().Perm() != 0700 {
		return fmt.Errorf("refusing to remove invalid export staging directory")
	}
	err = os.RemoveAll(staging)
	if err == nil {
		e.StagingDir = ""
	}
	return err
}

func ParseFrozenRootFS(archivePath, quarantine string, baseline SnapshotManifest, policy ExportPolicy) (result FrozenExport, err error) {
	if err := policy.validate(); err != nil {
		return FrozenExport{}, err
	}
	if err := validateCanonicalManifest(baseline, policy.Workspace); err != nil {
		return FrozenExport{}, fmt.Errorf("invalid trusted baseline: %w", err)
	}
	if err := validateQuarantine(quarantine); err != nil {
		return FrozenExport{}, err
	}
	archiveInfo, err := os.Lstat(archivePath)
	if err != nil {
		return FrozenExport{}, err
	}
	if !archiveInfo.Mode().IsRegular() || archiveInfo.Size() > policy.MaxArchiveSize {
		return FrozenExport{}, fmt.Errorf("rootfs export must be a regular file no larger than %d", policy.MaxArchiveSize)
	}
	staging, err := os.MkdirTemp(quarantine, "sunaba-export-")
	if err != nil {
		return FrozenExport{}, err
	}
	if err := os.Chmod(staging, 0700); err != nil {
		_ = os.RemoveAll(staging)
		return FrozenExport{}, err
	}
	canonicalStaging, err := filepath.EvalSymlinks(staging)
	if err != nil {
		_ = os.RemoveAll(staging)
		return FrozenExport{}, err
	}
	staging = canonicalStaging
	result.StagingDir = staging
	defer func() {
		if err != nil {
			_ = os.RemoveAll(staging)
		}
	}()

	archive, err := os.Open(archivePath)
	if err != nil {
		return FrozenExport{}, err
	}
	defer archive.Close()
	reader := tar.NewReader(archive)
	lowerEntries := make([]SnapshotEntry, 0, len(baseline.Entries))
	lowerSeen := make(map[string]struct{}, len(baseline.Entries))
	upperSeen := make(map[string]struct{})
	mergedSeen := make(map[string]struct{})
	var parsedUpper, parsedMerged []OverlayEntry
	baselineByPath := make(map[string]SnapshotEntry, len(baseline.Entries))
	for _, entry := range baseline.Entries {
		baselineByPath[entry.Path] = entry
	}
	var lowerTotal, upperTotal int64
	var lowerRootSeen, upperRootSeen, mergedRootSeen bool
	archiveEntries := 0
	for {
		header, nextErr := reader.Next()
		if nextErr == io.EOF {
			break
		}
		if nextErr != nil {
			return FrozenExport{}, fmt.Errorf("read rootfs tar: %w", nextErr)
		}
		archiveEntries++
		if archiveEntries > policy.MaxArchiveEntries {
			return FrozenExport{}, fmt.Errorf("rootfs archive exceeds %d entries", policy.MaxArchiveEntries)
		}
		name, err := validateArchivePath(header.Name, header.Typeflag)
		if err != nil {
			return FrozenExport{}, err
		}
		switch {
		case name == lowerPrefix:
			if lowerRootSeen {
				return FrozenExport{}, fmt.Errorf("duplicate lower root")
			}
			lowerRootSeen = true
			if header.Typeflag != tar.TypeDir {
				return FrozenExport{}, fmt.Errorf("lower root must be a directory")
			}
		case strings.HasPrefix(name, lowerPrefix+"/"):
			relative := strings.TrimPrefix(name, lowerPrefix+"/")
			if _, exists := lowerSeen[relative]; exists {
				return FrozenExport{}, fmt.Errorf("duplicate lower path %q", relative)
			}
			lowerSeen[relative] = struct{}{}
			entry, size, err := parseLowerEntry(reader, header, relative, policy.Workspace)
			if err != nil {
				return FrozenExport{}, err
			}
			lowerTotal += size
			if lowerTotal > policy.Workspace.MaxTotalSize {
				return FrozenExport{}, fmt.Errorf("exported lower exceeds workspace total size")
			}
			lowerEntries = append(lowerEntries, entry)
		case name == upperPrefix:
			if upperRootSeen {
				return FrozenExport{}, fmt.Errorf("duplicate upper root")
			}
			upperRootSeen = true
			if header.Typeflag != tar.TypeDir {
				return FrozenExport{}, fmt.Errorf("upper root must be a directory")
			}
			if err := validateOverlayPAX(header.PAXRecords, true); err != nil {
				return FrozenExport{}, err
			}
		case strings.HasPrefix(name, upperPrefix+"/"):
			relative := strings.TrimPrefix(name, upperPrefix+"/")
			if _, exists := upperSeen[relative]; exists {
				return FrozenExport{}, fmt.Errorf("duplicate upper path %q", relative)
			}
			upperSeen[relative] = struct{}{}
			entry, size, err := parseUpperEntry(reader, header, relative, staging, baselineByPath, policy.Workspace)
			if err != nil {
				return FrozenExport{}, err
			}
			upperTotal += size
			if upperTotal > policy.Workspace.MaxTotalSize {
				return FrozenExport{}, fmt.Errorf("exported upper exceeds workspace total size")
			}
			parsedUpper = append(parsedUpper, entry)
		case name == mergedPrefix:
			if mergedRootSeen || header.Typeflag != tar.TypeDir {
				return FrozenExport{}, fmt.Errorf("duplicate or invalid merged export root")
			}
			mergedRootSeen = true
		case strings.HasPrefix(name, mergedPrefix+"/"):
			relative := strings.TrimPrefix(name, mergedPrefix+"/")
			if _, exists := mergedSeen[relative]; exists {
				return FrozenExport{}, fmt.Errorf("duplicate merged export path %q", relative)
			}
			mergedSeen[relative] = struct{}{}
			entry, size, err := parseMergedEntry(reader, header, relative, staging, policy.Workspace)
			if err != nil {
				return FrozenExport{}, err
			}
			upperTotal += size
			if upperTotal > policy.Workspace.MaxTotalSize {
				return FrozenExport{}, fmt.Errorf("exported merged workspace exceeds total size")
			}
			parsedMerged = append(parsedMerged, entry)
		}
	}
	if !lowerRootSeen || (!upperRootSeen && !mergedRootSeen) {
		return FrozenExport{}, fmt.Errorf("rootfs export is missing lower and a workspace result root")
	}
	if mergedRootSeen {
		result.Upper = parsedMerged
		for _, entry := range baseline.Entries {
			if _, exists := mergedSeen[entry.Path]; !exists {
				result.Upper = append(result.Upper, OverlayEntry{Path: entry.Path, Whiteout: true})
			}
		}
	} else {
		result.Upper = parsedUpper
	}
	if len(lowerEntries) > policy.Workspace.MaxEntries || len(result.Upper) > policy.Workspace.MaxEntries {
		return FrozenExport{}, fmt.Errorf("exported workspace exceeds entry limit")
	}
	result.Lower, err = finalizeSnapshotManifest(baseline.Root, lowerEntries, lowerTotal)
	if err != nil {
		return FrozenExport{}, err
	}
	if result.Lower.Digest != baseline.Digest {
		return FrozenExport{}, fmt.Errorf("exported lower digest %s does not match trusted baseline %s", result.Lower.Digest, baseline.Digest)
	}
	return result, nil
}

func parseMergedEntry(reader io.Reader, header *tar.Header, relative, staging string, policy SnapshotPolicy) (OverlayEntry, int64, error) {
	if err := validateWorkspacePath(relative, policy); err != nil {
		return OverlayEntry{}, 0, err
	}
	for key := range header.PAXRecords {
		if strings.Contains(strings.ToLower(key), "xattr") {
			return OverlayEntry{}, 0, fmt.Errorf("merged export entry %q has forbidden metadata %q", relative, key)
		}
	}
	entry := OverlayEntry{Path: relative, Mode: uint32(header.Mode) & 0777}
	switch header.Typeflag {
	case tar.TypeDir:
		entry.Type = TypeDirectory
		return entry, 0, nil
	case tar.TypeReg, tar.TypeRegA:
		dataPath, hash, size, err := stageTarContent(reader, staging, header.Size, policy.MaxFileSize)
		if err != nil {
			return OverlayEntry{}, 0, err
		}
		entry.Type, entry.DataPath, entry.SHA256, entry.Size = TypeFile, dataPath, hash, size
		return entry, size, nil
	case tar.TypeSymlink:
		if header.Linkname == "" || strings.ContainsRune(header.Linkname, '\x00') || len(header.Linkname) > policy.MaxSymlinkSize {
			return OverlayEntry{}, 0, fmt.Errorf("merged symlink %q target exceeds limit", relative)
		}
		entry.Type, entry.Mode, entry.LinkTarget = TypeSymlink, 0777, header.Linkname
		return entry, 0, nil
	default:
		return OverlayEntry{}, 0, fmt.Errorf("merged export entry %q has forbidden type %d", relative, header.Typeflag)
	}
}

func (p ExportPolicy) validate() error {
	if err := p.Workspace.validate(); err != nil {
		return err
	}
	if p.MaxArchiveEntries <= 0 || p.MaxArchiveSize <= 0 {
		return fmt.Errorf("archive limits must be positive")
	}
	return nil
}

func validateQuarantine(quarantine string) error {
	if !filepath.IsAbs(quarantine) || !strings.HasPrefix(filepath.Base(quarantine), "sunaba-") {
		return fmt.Errorf("quarantine must be an absolute sunaba-* directory")
	}
	info, err := os.Lstat(quarantine)
	if err != nil {
		return err
	}
	if !info.IsDir() || info.Mode().Perm() != 0700 {
		return fmt.Errorf("quarantine must be a mode 0700 directory")
	}
	if _, err := filepath.EvalSymlinks(quarantine); err != nil {
		return err
	}
	return nil
}

func validateArchivePath(name string, typeflag byte) (string, error) {
	if name == "" || strings.ContainsRune(name, '\x00') || strings.HasPrefix(name, "/") {
		return "", fmt.Errorf("unsafe archive path %q", name)
	}
	if strings.HasSuffix(name, "/") && typeflag == tar.TypeDir {
		trimmed := strings.TrimSuffix(name, "/")
		if trimmed != "" && trimmed != ".." && !strings.HasPrefix(trimmed, "../") && path.Clean(trimmed) == trimmed {
			return trimmed, nil
		}
	}
	clean := path.Clean(name)
	if clean != name || clean == "." || clean == ".." || strings.HasPrefix(clean, "../") {
		return "", fmt.Errorf("non-canonical archive path %q", name)
	}
	return clean, nil
}

func parseLowerEntry(reader io.Reader, header *tar.Header, relative string, policy SnapshotPolicy) (SnapshotEntry, int64, error) {
	if err := validateWorkspacePath(relative, policy); err != nil {
		return SnapshotEntry{}, 0, err
	}
	if len(header.PAXRecords) != 0 {
		return SnapshotEntry{}, 0, fmt.Errorf("lower entry %q contains xattrs or PAX metadata", relative)
	}
	switch header.Typeflag {
	case tar.TypeDir:
		return SnapshotEntry{Path: relative, Type: TypeDirectory, Mode: uint32(header.Mode) & 0777}, 0, nil
	case tar.TypeReg, tar.TypeRegA:
		hash, size, err := hashTarContent(reader, header.Size, policy.MaxFileSize)
		return SnapshotEntry{Path: relative, Type: TypeFile, Mode: uint32(header.Mode) & 0777, Size: size, SHA256: hash}, size, err
	case tar.TypeSymlink:
		if header.Linkname == "" || strings.ContainsRune(header.Linkname, '\x00') || len(header.Linkname) > policy.MaxSymlinkSize {
			return SnapshotEntry{}, 0, fmt.Errorf("lower symlink %q target exceeds limit", relative)
		}
		return SnapshotEntry{Path: relative, Type: TypeSymlink, Mode: 0777, LinkTarget: header.Linkname}, 0, nil
	default:
		return SnapshotEntry{}, 0, fmt.Errorf("lower entry %q has forbidden type %d", relative, header.Typeflag)
	}
}

func parseUpperEntry(reader io.Reader, header *tar.Header, relative, staging string, baseline map[string]SnapshotEntry, policy SnapshotPolicy) (OverlayEntry, int64, error) {
	if err := validateWorkspacePath(relative, policy); err != nil {
		return OverlayEntry{}, 0, err
	}
	metadata, err := overlayMetadata(header.PAXRecords)
	if err != nil {
		return OverlayEntry{}, 0, fmt.Errorf("upper entry %q: %w", relative, err)
	}
	if metadata.redirect != "" {
		if err := validateWorkspacePath(metadata.redirect, policy); err != nil {
			return OverlayEntry{}, 0, fmt.Errorf("upper entry %q has unsafe redirect: %w", relative, err)
		}
	}
	entry := OverlayEntry{
		Path: relative, Mode: uint32(header.Mode) & 0777, Opaque: metadata.opaque,
		Metacopy: metadata.metacopy, Redirect: metadata.redirect,
	}
	switch header.Typeflag {
	case tar.TypeDir:
		if metadata.metacopy {
			return OverlayEntry{}, 0, fmt.Errorf("upper directory %q cannot be metacopy", relative)
		}
		if metadata.redirect != "" {
			source, exists := baseline[metadata.redirect]
			if !exists || source.Type != TypeDirectory {
				return OverlayEntry{}, 0, fmt.Errorf("upper directory %q has missing or incompatible redirect source", relative)
			}
		}
		entry.Type = TypeDirectory
		return entry, 0, nil
	case tar.TypeReg, tar.TypeRegA:
		if metadata.opaque {
			return OverlayEntry{}, 0, fmt.Errorf("upper file %q cannot be opaque", relative)
		}
		entry.Type = TypeFile
		if metadata.metacopy {
			sourcePath := relative
			if metadata.redirect != "" {
				sourcePath = metadata.redirect
			}
			source, exists := baseline[sourcePath]
			if !exists || source.Type != TypeFile || source.Size != header.Size {
				return OverlayEntry{}, 0, fmt.Errorf("upper metacopy %q has missing or incompatible lower source", relative)
			}
			if _, _, err := hashTarContent(reader, header.Size, policy.MaxFileSize); err != nil {
				return OverlayEntry{}, 0, err
			}
			entry.Size, entry.SHA256 = source.Size, source.SHA256
			return entry, source.Size, nil
		}
		if metadata.redirect != "" {
			source, exists := baseline[metadata.redirect]
			if !exists || source.Type != TypeFile {
				return OverlayEntry{}, 0, fmt.Errorf("upper file %q has missing or incompatible redirect source", relative)
			}
		}
		dataPath, hash, size, err := stageTarContent(reader, staging, header.Size, policy.MaxFileSize)
		if err != nil {
			return OverlayEntry{}, 0, err
		}
		entry.DataPath, entry.SHA256, entry.Size = dataPath, hash, size
		return entry, size, nil
	case tar.TypeSymlink:
		if metadata.opaque || metadata.metacopy || metadata.redirect != "" {
			return OverlayEntry{}, 0, fmt.Errorf("upper symlink %q has incompatible OverlayFS metadata", relative)
		}
		if header.Linkname == "" || strings.ContainsRune(header.Linkname, '\x00') || len(header.Linkname) > policy.MaxSymlinkSize {
			return OverlayEntry{}, 0, fmt.Errorf("upper symlink %q target exceeds limit", relative)
		}
		entry.Type, entry.Mode, entry.LinkTarget = TypeSymlink, 0777, header.Linkname
		return entry, 0, nil
	case tar.TypeLink:
		if !whiteoutLinkPattern.MatchString(header.Linkname) || len(header.PAXRecords) != 0 {
			return OverlayEntry{}, 0, fmt.Errorf("upper hardlink %q -> %q is not a recognized OverlayFS whiteout", relative, header.Linkname)
		}
		entry.Whiteout = true
		return entry, 0, nil
	default:
		return OverlayEntry{}, 0, fmt.Errorf("upper entry %q has forbidden type %d", relative, header.Typeflag)
	}
}

func validateWorkspacePath(relative string, policy SnapshotPolicy) error {
	if relative == "" || path.Clean(relative) != relative || strings.HasPrefix(relative, "../") || strings.HasPrefix(relative, "/") {
		return fmt.Errorf("unsafe workspace path %q", relative)
	}
	components := strings.Split(relative, "/")
	if len(components) > policy.MaxDepth {
		return fmt.Errorf("workspace path %q exceeds depth limit", relative)
	}
	for _, component := range components {
		if err := validateEntryName(component); err != nil {
			return err
		}
	}
	for _, protected := range policy.ProtectedPaths {
		if strings.EqualFold(components[0], protected) {
			return fmt.Errorf("workspace path %q targets Protected Path", relative)
		}
	}
	return nil
}

type parsedOverlayMetadata struct {
	opaque   bool
	metacopy bool
	redirect string
}

func overlayMetadata(records map[string]string) (parsedOverlayMetadata, error) {
	if err := validateOverlayPAX(records, false); err != nil {
		return parsedOverlayMetadata{}, err
	}
	metadata := parsedOverlayMetadata{}
	for key, value := range records {
		switch key {
		case "SCHILY.xattr.trusted.overlay.opaque":
			if value != "y" {
				return parsedOverlayMetadata{}, fmt.Errorf("invalid opaque value")
			}
			metadata.opaque = true
		case "SCHILY.xattr.trusted.overlay.metacopy":
			if value != "" && value != "y" {
				return parsedOverlayMetadata{}, fmt.Errorf("invalid metacopy value")
			}
			metadata.metacopy = true
		case "SCHILY.xattr.trusted.overlay.redirect":
			redirect := value
			if redirect == "" || strings.HasPrefix(redirect, "/") || path.Clean(redirect) != redirect || strings.ContainsRune(redirect, '\x00') {
				return parsedOverlayMetadata{}, fmt.Errorf("invalid redirect path")
			}
			metadata.redirect = redirect
		}
	}
	return metadata, nil
}

func validateOverlayPAX(records map[string]string, root bool) error {
	for key := range records {
		if !strings.HasPrefix(key, "SCHILY.xattr.") {
			continue
		}
		switch key {
		case "SCHILY.xattr.trusted.overlay.opaque",
			"SCHILY.xattr.trusted.overlay.metacopy",
			"SCHILY.xattr.trusted.overlay.redirect",
			"SCHILY.xattr.trusted.overlay.origin",
			"SCHILY.xattr.trusted.overlay.impure",
			"SCHILY.xattr.trusted.overlay.uuid",
			"SCHILY.xattr.trusted.overlay.upper":
		default:
			return fmt.Errorf("unapproved xattr %q", key)
		}
		if root && key != "SCHILY.xattr.trusted.overlay.origin" && key != "SCHILY.xattr.trusted.overlay.impure" && key != "SCHILY.xattr.trusted.overlay.uuid" {
			return fmt.Errorf("unapproved upper root xattr %q", key)
		}
	}
	return nil
}

func hashTarContent(reader io.Reader, size, maximum int64) (string, int64, error) {
	if size < 0 || size > maximum {
		return "", 0, fmt.Errorf("tar content size %d exceeds limit %d", size, maximum)
	}
	hash := sha256.New()
	written, err := io.Copy(hash, io.LimitReader(reader, maximum+1))
	if err != nil {
		return "", 0, err
	}
	if written != size {
		return "", 0, fmt.Errorf("tar content size changed: read %d, expected %d", written, size)
	}
	return hex.EncodeToString(hash.Sum(nil)), written, nil
}

func stageTarContent(reader io.Reader, staging string, size, maximum int64) (dataPath, digest string, written int64, err error) {
	if size < 0 || size > maximum {
		return "", "", 0, fmt.Errorf("tar content size %d exceeds limit %d", size, maximum)
	}
	file, err := os.CreateTemp(staging, "entry-")
	if err != nil {
		return "", "", 0, err
	}
	dataPath = file.Name()
	defer func() {
		closeErr := file.Close()
		if err == nil {
			err = closeErr
		}
		if err != nil {
			_ = os.Remove(dataPath)
		}
	}()
	if err := file.Chmod(0600); err != nil {
		return "", "", 0, err
	}
	hash := sha256.New()
	written, err = io.Copy(io.MultiWriter(file, hash), io.LimitReader(reader, maximum+1))
	if err != nil {
		return "", "", 0, err
	}
	if written != size {
		return "", "", 0, fmt.Errorf("tar content size changed: read %d, expected %d", written, size)
	}
	if err := file.Sync(); err != nil {
		return "", "", 0, err
	}
	return dataPath, hex.EncodeToString(hash.Sum(nil)), written, nil
}
