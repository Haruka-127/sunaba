package workspace

import (
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"fmt"
	"path"
	"sort"
	"strings"
)

type ChangeKind string

const (
	ChangeAdd    ChangeKind = "add"
	ChangeModify ChangeKind = "modify"
	ChangeDelete ChangeKind = "delete"
	ChangeRename ChangeKind = "rename"
)

type Change struct {
	Kind   ChangeKind     `json:"kind"`
	Path   string         `json:"path"`
	From   string         `json:"from,omitempty"`
	Before *SnapshotEntry `json:"before,omitempty"`
	After  *SnapshotEntry `json:"after,omitempty"`
}

type ChangeSet struct {
	Version        int      `json:"version"`
	BaselineDigest string   `json:"baseline_digest"`
	MergedDigest   string   `json:"merged_digest"`
	Changes        []Change `json:"changes"`
	Digest         string   `json:"digest"`
}

type changeSetDigestInput struct {
	Version        int      `json:"version"`
	BaselineDigest string   `json:"baseline_digest"`
	MergedDigest   string   `json:"merged_digest"`
	Changes        []Change `json:"changes"`
}

func BuildChangeSet(baseline, merged SnapshotManifest, policy SnapshotPolicy) (ChangeSet, error) {
	if err := validateCanonicalManifest(baseline, policy); err != nil {
		return ChangeSet{}, fmt.Errorf("invalid baseline manifest: %w", err)
	}
	if err := validateCanonicalManifest(merged, policy); err != nil {
		return ChangeSet{}, fmt.Errorf("invalid merged manifest: %w", err)
	}
	before := make(map[string]SnapshotEntry, len(baseline.Entries))
	after := make(map[string]SnapshotEntry, len(merged.Entries))
	for _, entry := range baseline.Entries {
		before[entry.Path] = entry
	}
	for _, entry := range merged.Entries {
		after[entry.Path] = entry
	}
	changes := make([]Change, 0)
	deleted := make([]SnapshotEntry, 0)
	added := make([]SnapshotEntry, 0)
	for entryPath, oldEntry := range before {
		newEntry, exists := after[entryPath]
		if !exists {
			deleted = append(deleted, oldEntry)
			continue
		}
		if !sameSnapshotEntry(oldEntry, newEntry) {
			oldCopy, newCopy := oldEntry, newEntry
			changes = append(changes, Change{Kind: ChangeModify, Path: entryPath, Before: &oldCopy, After: &newCopy})
		}
	}
	for entryPath, newEntry := range after {
		if _, exists := before[entryPath]; !exists {
			added = append(added, newEntry)
		}
	}

	deleteGroups := groupRenameCandidates(deleted)
	addGroups := groupRenameCandidates(added)
	renamedDelete := make(map[string]struct{})
	renamedAdd := make(map[string]struct{})
	for fingerprint, oldEntries := range deleteGroups {
		newEntries := addGroups[fingerprint]
		if len(oldEntries) != 1 || len(newEntries) != 1 {
			continue
		}
		oldEntry, newEntry := oldEntries[0], newEntries[0]
		oldCopy, newCopy := oldEntry, newEntry
		changes = append(changes, Change{
			Kind: ChangeRename, Path: newEntry.Path, From: oldEntry.Path,
			Before: &oldCopy, After: &newCopy,
		})
		renamedDelete[oldEntry.Path] = struct{}{}
		renamedAdd[newEntry.Path] = struct{}{}
	}
	for _, entry := range deleted {
		if _, renamed := renamedDelete[entry.Path]; renamed {
			continue
		}
		entryCopy := entry
		changes = append(changes, Change{Kind: ChangeDelete, Path: entry.Path, Before: &entryCopy})
	}
	for _, entry := range added {
		if _, renamed := renamedAdd[entry.Path]; renamed {
			continue
		}
		entryCopy := entry
		changes = append(changes, Change{Kind: ChangeAdd, Path: entry.Path, After: &entryCopy})
	}
	sort.Slice(changes, func(i, j int) bool {
		if changes[i].Path != changes[j].Path {
			return changes[i].Path < changes[j].Path
		}
		if changes[i].Kind != changes[j].Kind {
			return changes[i].Kind < changes[j].Kind
		}
		return changes[i].From < changes[j].From
	})
	input := changeSetDigestInput{
		Version: manifestVersion, BaselineDigest: baseline.Digest,
		MergedDigest: merged.Digest, Changes: changes,
	}
	encoded, err := json.Marshal(input)
	if err != nil {
		return ChangeSet{}, err
	}
	digest := sha256.Sum256(encoded)
	return ChangeSet{
		Version: input.Version, BaselineDigest: input.BaselineDigest, MergedDigest: input.MergedDigest,
		Changes: changes, Digest: hex.EncodeToString(digest[:]),
	}, nil
}

func validateCanonicalManifest(manifest SnapshotManifest, policy SnapshotPolicy) error {
	if err := policy.validate(); err != nil {
		return err
	}
	if manifest.Version != manifestVersion {
		return fmt.Errorf("unsupported manifest version %d", manifest.Version)
	}
	entries := append([]SnapshotEntry(nil), manifest.Entries...)
	seen := make(map[string]struct{}, len(entries))
	byPath := make(map[string]SnapshotEntry, len(entries))
	var total int64
	for index, entry := range entries {
		if index > 0 && entries[index-1].Path >= entry.Path {
			return fmt.Errorf("manifest entries are not in canonical path order")
		}
		if err := validateWorkspacePath(entry.Path, policy); err != nil {
			return err
		}
		if _, exists := seen[entry.Path]; exists {
			return fmt.Errorf("duplicate manifest path %q", entry.Path)
		}
		seen[entry.Path] = struct{}{}
		byPath[entry.Path] = entry
		if entry.Mode > 0777 {
			return fmt.Errorf("manifest path %q has unsafe mode", entry.Path)
		}
		switch entry.Type {
		case TypeFile:
			if entry.Size < 0 || entry.Size > policy.MaxFileSize || entry.LinkTarget != "" {
				return fmt.Errorf("manifest file %q has invalid metadata", entry.Path)
			}
			hash, err := hex.DecodeString(entry.SHA256)
			if err != nil || len(hash) != sha256.Size {
				return fmt.Errorf("manifest file %q has invalid digest", entry.Path)
			}
			total += entry.Size
		case TypeDirectory:
			if entry.Size != 0 || entry.SHA256 != "" || entry.LinkTarget != "" {
				return fmt.Errorf("manifest directory %q has invalid metadata", entry.Path)
			}
		case TypeSymlink:
			if entry.Mode != 0777 || entry.Size != 0 || entry.SHA256 != "" || entry.LinkTarget == "" || strings.ContainsRune(entry.LinkTarget, '\x00') || len(entry.LinkTarget) > policy.MaxSymlinkSize {
				return fmt.Errorf("manifest symlink %q has invalid metadata", entry.Path)
			}
		default:
			return fmt.Errorf("manifest path %q has unsupported type %q", entry.Path, entry.Type)
		}
	}
	if len(entries) > policy.MaxEntries || total > policy.MaxTotalSize {
		return fmt.Errorf("manifest exceeds workspace limits")
	}
	for entryPath := range byPath {
		parent := path.Dir(entryPath)
		for parent != "." {
			entry, exists := byPath[parent]
			if !exists || entry.Type != TypeDirectory {
				return fmt.Errorf("manifest path %q has missing or non-directory parent", entryPath)
			}
			parent = path.Dir(parent)
		}
	}
	if total != manifest.TotalSize {
		return fmt.Errorf("manifest total size is not canonical")
	}
	canonical, err := finalizeSnapshotManifest(manifest.Root, entries, total)
	if err != nil {
		return err
	}
	if canonical.Digest != manifest.Digest {
		return fmt.Errorf("manifest digest is not canonical")
	}
	return nil
}

func sameSnapshotEntry(left, right SnapshotEntry) bool {
	return left.Path == right.Path && left.Type == right.Type && left.Mode == right.Mode && left.Size == right.Size && left.SHA256 == right.SHA256 && left.LinkTarget == right.LinkTarget
}

func groupRenameCandidates(entries []SnapshotEntry) map[string][]SnapshotEntry {
	groups := make(map[string][]SnapshotEntry)
	for _, entry := range entries {
		if entry.Type == TypeDirectory {
			continue
		}
		fingerprint := fmt.Sprintf("%s\x00%d\x00%d\x00%s\x00%s", entry.Type, entry.Mode, entry.Size, entry.SHA256, entry.LinkTarget)
		groups[fingerprint] = append(groups[fingerprint], entry)
	}
	return groups
}
