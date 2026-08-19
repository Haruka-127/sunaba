package workspace

import (
	"path"
	"sort"
	"strings"
)

const LargeSnapshotFileBytes int64 = 10 << 20

type PreviewFile struct {
	Path string `json:"path"`
	Size int64  `json:"size"`
}

type SnapshotPreview struct {
	Digest         string        `json:"digest"`
	EntryCount     int           `json:"entry_count"`
	FileCount      int           `json:"file_count"`
	TotalSize      int64         `json:"total_size"`
	LargeFiles     []PreviewFile `json:"large_files"`
	SensitivePaths []string      `json:"sensitive_paths"`
}

// BuildSnapshotPreview reports metadata only. It never reads or returns file
// contents; hashes are deliberately omitted from the human-facing result.
func BuildSnapshotPreview(manifest SnapshotManifest) SnapshotPreview {
	preview := SnapshotPreview{Digest: manifest.Digest, EntryCount: len(manifest.Entries), TotalSize: manifest.TotalSize}
	for _, entry := range manifest.Entries {
		if entry.Type != TypeFile {
			continue
		}
		preview.FileCount++
		if entry.Size >= LargeSnapshotFileBytes {
			preview.LargeFiles = append(preview.LargeFiles, PreviewFile{Path: entry.Path, Size: entry.Size})
		}
		if sensitiveSnapshotName(entry.Path) {
			preview.SensitivePaths = append(preview.SensitivePaths, entry.Path)
		}
	}
	sort.Slice(preview.LargeFiles, func(i, j int) bool {
		if preview.LargeFiles[i].Size != preview.LargeFiles[j].Size {
			return preview.LargeFiles[i].Size > preview.LargeFiles[j].Size
		}
		return preview.LargeFiles[i].Path < preview.LargeFiles[j].Path
	})
	if len(preview.LargeFiles) > 20 {
		preview.LargeFiles = preview.LargeFiles[:20]
	}
	sort.Strings(preview.SensitivePaths)
	if len(preview.SensitivePaths) > 100 {
		preview.SensitivePaths = preview.SensitivePaths[:100]
	}
	return preview
}

func sensitiveSnapshotName(entryPath string) bool {
	name := strings.ToLower(path.Base(entryPath))
	if name == ".env" || strings.HasPrefix(name, ".env.") || name == "id_rsa" || name == "id_ed25519" || name == "credentials" || name == "credentials.json" {
		return true
	}
	for _, suffix := range []string{".pem", ".key", ".p12", ".pfx"} {
		if strings.HasSuffix(name, suffix) {
			return true
		}
	}
	return false
}
