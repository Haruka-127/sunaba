package workspace

import (
	"crypto/sha256"
	"encoding/hex"
	"fmt"
	"io"
	"os"
	"path/filepath"
	"strings"
	"unicode/utf8"

	"golang.org/x/sys/unix"
)

const (
	DefaultReviewContext      = 3
	MaximumReviewContext      = 20
	maximumReviewFileBytes    = int64(512 << 10)
	maximumReviewTotalBytes   = int64(1 << 20)
	maximumReviewLines        = 2_000
	maximumReviewLineBytes    = 64 << 10
	maximumReviewEditDistance = 512
	maximumReviewItems        = 2_000
)

type ReviewOptions struct {
	Context  int
	StatOnly bool
	Path     string
}

type ReviewCounts struct {
	Add    int
	Modify int
	Delete int
	Rename int
}

type Review struct {
	BaselineDigest  string
	MergedDigest    string
	ChangeSetDigest string
	Counts          ReviewCounts
	Items           []ReviewItem
	Filtered        bool
	StatOnly        bool
	Opaque          int
	Executable      int
	Symlink         int
	Omitted         int
	BaselineMissing bool
}

type ReviewItem struct {
	Change       Change
	Hunks        []ReviewHunk
	OpaqueReason string
	Binary       bool
	Executable   bool
	Symlink      bool
}

type ReviewHunk struct {
	OldStart int
	OldLines int
	NewStart int
	NewLines int
	Lines    []ReviewLine
}

type ReviewLine struct {
	Kind byte
	Text string
}

func BuildReview(baselineRoot, mergedRoot string, baseline, merged SnapshotManifest, changeSet ChangeSet, policy SnapshotPolicy, options ReviewOptions) (Review, error) {
	if options.Context < 0 || options.Context > MaximumReviewContext {
		return Review{}, fmt.Errorf("review context must be between 0 and %d", MaximumReviewContext)
	}
	if err := validateReviewRoot(baselineRoot, baseline.Root); err != nil {
		return Review{}, fmt.Errorf("invalid review baseline: %w", err)
	}
	if err := validateReviewRoot(mergedRoot, merged.Root); err != nil {
		return Review{}, fmt.Errorf("invalid review Merged View: %w", err)
	}
	actualBaseline, err := BuildSnapshotManifest(baselineRoot, policy)
	if err != nil || actualBaseline.Root != baselineRoot || actualBaseline.Digest != baseline.Digest {
		return Review{}, fmt.Errorf("review baseline no longer matches its manifest")
	}
	actualMerged, err := BuildSnapshotManifest(mergedRoot, policy)
	if err != nil || actualMerged.Root != mergedRoot || actualMerged.Digest != merged.Digest {
		return Review{}, fmt.Errorf("review Merged View no longer matches its manifest")
	}
	rebuilt, err := BuildChangeSet(baseline, merged, policy)
	if err != nil || rebuilt.Digest != changeSet.Digest {
		return Review{}, fmt.Errorf("review Change Set does not match its manifests")
	}
	if options.Path != "" {
		if err := validateWorkspacePath(options.Path, policy); err != nil {
			return Review{}, fmt.Errorf("invalid review path: %w", err)
		}
	}
	review := Review{
		BaselineDigest: baseline.Digest, MergedDigest: merged.Digest, ChangeSetDigest: changeSet.Digest,
		Filtered: options.Path != "", StatOnly: options.StatOnly,
	}
	for _, change := range changeSet.Changes {
		switch change.Kind {
		case ChangeAdd:
			review.Counts.Add++
		case ChangeModify:
			review.Counts.Modify++
		case ChangeDelete:
			review.Counts.Delete++
		case ChangeRename:
			review.Counts.Rename++
		}
	}
	remaining := maximumReviewTotalBytes
	matched := options.Path == ""
	for _, change := range changeSet.Changes {
		if options.Path != "" && change.Path != options.Path && change.From != options.Path {
			continue
		}
		matched = true
		item := ReviewItem{Change: change}
		item.Executable = entryExecutable(change.Before) || entryExecutable(change.After)
		item.Symlink = entryType(change.Before, TypeSymlink) || entryType(change.After, TypeSymlink)
		if item.Executable {
			review.Executable++
		}
		if item.Symlink {
			review.Symlink++
		}
		if len(review.Items) >= maximumReviewItems {
			review.Omitted++
			continue
		}
		if !options.StatOnly {
			beforeSize := regularFileSize(change.Before)
			afterSize := regularFileSize(change.After)
			if beforeSize > maximumReviewFileBytes || afterSize > maximumReviewFileBytes {
				item.OpaqueReason = fmt.Sprintf("file content exceeds the %d-byte inline review limit", maximumReviewFileBytes)
			} else if beforeSize+afterSize > remaining {
				item.OpaqueReason = fmt.Sprintf("total inline review content exceeds the %d-byte limit", maximumReviewTotalBytes)
			} else {
				before, after, contentErr := reviewFileContents(baselineRoot, mergedRoot, change)
				if contentErr != nil {
					return Review{}, contentErr
				}
				remaining -= int64(len(before) + len(after))
				if !reviewText(before) || !reviewText(after) {
					item.Binary = true
					item.OpaqueReason = "file content is binary or is not valid UTF-8"
				} else if before != nil || after != nil {
					beforeLines, splitErr := splitReviewLines(string(before))
					if splitErr != nil {
						item.OpaqueReason = splitErr.Error()
					} else {
						afterLines, splitErr := splitReviewLines(string(after))
						if splitErr != nil {
							item.OpaqueReason = splitErr.Error()
						} else {
							item.Hunks = buildReviewHunks(beforeLines, afterLines, options.Context)
						}
					}
				}
			}
		}
		if item.OpaqueReason != "" {
			review.Opaque++
		}
		review.Items = append(review.Items, item)
	}
	if !matched {
		return Review{}, fmt.Errorf("review path is not part of the pending Change Set")
	}
	return review, nil
}

func BuildMetadataOnlyReview(baseline, merged SnapshotManifest, changeSet ChangeSet, policy SnapshotPolicy, options ReviewOptions) (Review, error) {
	if options.Context < 0 || options.Context > MaximumReviewContext {
		return Review{}, fmt.Errorf("review context must be between 0 and %d", MaximumReviewContext)
	}
	rebuilt, err := BuildChangeSet(baseline, merged, policy)
	if err != nil || rebuilt.Digest != changeSet.Digest {
		return Review{}, fmt.Errorf("review Change Set does not match its manifests")
	}
	if options.Path != "" {
		if err := validateWorkspacePath(options.Path, policy); err != nil {
			return Review{}, fmt.Errorf("invalid review path: %w", err)
		}
	}
	review := Review{
		BaselineDigest: baseline.Digest, MergedDigest: merged.Digest, ChangeSetDigest: changeSet.Digest,
		Filtered: options.Path != "", StatOnly: options.StatOnly, BaselineMissing: true,
	}
	for _, change := range changeSet.Changes {
		switch change.Kind {
		case ChangeAdd:
			review.Counts.Add++
		case ChangeModify:
			review.Counts.Modify++
		case ChangeDelete:
			review.Counts.Delete++
		case ChangeRename:
			review.Counts.Rename++
		}
	}
	matched := options.Path == ""
	for _, change := range changeSet.Changes {
		if options.Path != "" && change.Path != options.Path && change.From != options.Path {
			continue
		}
		matched = true
		item := ReviewItem{Change: change}
		item.Executable = entryExecutable(change.Before) || entryExecutable(change.After)
		item.Symlink = entryType(change.Before, TypeSymlink) || entryType(change.After, TypeSymlink)
		if item.Executable {
			review.Executable++
		}
		if item.Symlink {
			review.Symlink++
		}
		if len(review.Items) >= maximumReviewItems {
			review.Omitted++
			continue
		}
		if !options.StatOnly && (entryType(change.Before, TypeFile) || entryType(change.After, TypeFile)) {
			item.OpaqueReason = "legacy pending baseline content is unavailable because the host baseline changed"
			review.Opaque++
		}
		review.Items = append(review.Items, item)
	}
	if !matched {
		return Review{}, fmt.Errorf("review path is not part of the pending Change Set")
	}
	return review, nil
}

func validateReviewRoot(root, manifestRoot string) error {
	if !filepath.IsAbs(root) || filepath.Clean(root) != root || manifestRoot != root {
		return fmt.Errorf("snapshot root identity does not match")
	}
	resolved, err := filepath.EvalSymlinks(root)
	if err != nil || resolved != root {
		return fmt.Errorf("snapshot root is missing or contains a symlink")
	}
	info, err := os.Lstat(root)
	if err != nil || !info.IsDir() || info.Mode()&os.ModeSymlink != 0 {
		return fmt.Errorf("snapshot root is not a directory")
	}
	return nil
}

func entryExecutable(entry *SnapshotEntry) bool {
	return entry != nil && entry.Type == TypeFile && entry.Mode&0111 != 0
}

func entryType(entry *SnapshotEntry, wanted EntryType) bool {
	return entry != nil && entry.Type == wanted
}

func regularFileSize(entry *SnapshotEntry) int64 {
	if entry == nil || entry.Type != TypeFile {
		return 0
	}
	return entry.Size
}

func reviewFileContents(baselineRoot, mergedRoot string, change Change) ([]byte, []byte, error) {
	var before, after []byte
	var err error
	if change.Before != nil && change.Before.Type == TypeFile && change.Kind != ChangeRename {
		before, err = readApprovedReviewFile(baselineRoot, *change.Before)
		if err != nil {
			return nil, nil, fmt.Errorf("read review baseline path %q: %w", change.Before.Path, err)
		}
	}
	if change.After != nil && change.After.Type == TypeFile && change.Kind != ChangeRename {
		after, err = readApprovedReviewFile(mergedRoot, *change.After)
		if err != nil {
			return nil, nil, fmt.Errorf("read review Merged View path %q: %w", change.After.Path, err)
		}
	}
	return before, after, nil
}

func readApprovedReviewFile(root string, expected SnapshotEntry) ([]byte, error) {
	rootFD, err := unix.Open(root, unix.O_RDONLY|unix.O_DIRECTORY|unix.O_CLOEXEC|unix.O_NOFOLLOW, 0)
	if err != nil {
		return nil, err
	}
	defer unix.Close(rootFD)
	fd, err := openPathAt(rootFD, expected.Path, unix.O_RDONLY)
	if err != nil {
		return nil, err
	}
	file := os.NewFile(uintptr(fd), expected.Path)
	if file == nil {
		unix.Close(fd)
		return nil, fmt.Errorf("create review file handle")
	}
	defer file.Close()
	var before unix.Stat_t
	if err := unix.Fstat(fd, &before); err != nil {
		return nil, err
	}
	if uint32(before.Mode)&uint32(unix.S_IFMT) != uint32(unix.S_IFREG) || before.Size != expected.Size || uint32(before.Mode)&0777 != expected.Mode {
		return nil, fmt.Errorf("approved file metadata changed")
	}
	data, err := io.ReadAll(io.LimitReader(file, expected.Size+1))
	if err != nil || int64(len(data)) != expected.Size {
		return nil, fmt.Errorf("approved file size changed during review")
	}
	var after unix.Stat_t
	if err := unix.Fstat(fd, &after); err != nil || !sameIdentity(before, after) || after.Size != before.Size {
		return nil, fmt.Errorf("approved file identity changed during review")
	}
	digest := sha256.Sum256(data)
	if hex.EncodeToString(digest[:]) != expected.SHA256 {
		return nil, fmt.Errorf("approved file content changed during review")
	}
	return data, nil
}

func reviewText(data []byte) bool {
	return utf8.Valid(data) && !strings.ContainsRune(string(data), '\x00')
}

func splitReviewLines(text string) ([]string, error) {
	if text == "" {
		return nil, nil
	}
	lines := strings.SplitAfter(text, "\n")
	if len(lines) > 0 && lines[len(lines)-1] == "" {
		lines = lines[:len(lines)-1]
	}
	if len(lines) > maximumReviewLines {
		return nil, fmt.Errorf("text file exceeds the %d-line inline review limit", maximumReviewLines)
	}
	for _, line := range lines {
		if len(line) > maximumReviewLineBytes {
			return nil, fmt.Errorf("text file contains a line exceeding the %d-byte inline review limit", maximumReviewLineBytes)
		}
	}
	return lines, nil
}

type lineOperation struct {
	kind byte
	text string
}

func buildReviewHunks(before, after []string, contextLines int) []ReviewHunk {
	operations, ok := myersLineOperations(before, after)
	if !ok {
		operations = replacementLineOperations(before, after)
	}
	if len(operations) == 0 {
		return nil
	}
	oldLine, newLine := 1, 1
	type numberedOperation struct {
		lineOperation
		oldLine int
		newLine int
	}
	numbered := make([]numberedOperation, 0, len(operations))
	changed := make([]int, 0)
	for _, operation := range operations {
		numbered = append(numbered, numberedOperation{lineOperation: operation, oldLine: oldLine, newLine: newLine})
		if operation.kind != ' ' {
			changed = append(changed, len(numbered)-1)
		}
		if operation.kind != '+' {
			oldLine++
		}
		if operation.kind != '-' {
			newLine++
		}
	}
	if len(changed) == 0 {
		return nil
	}
	type window struct{ start, end int }
	windows := make([]window, 0)
	for _, index := range changed {
		start, end := index-contextLines, index+contextLines+1
		if start < 0 {
			start = 0
		}
		if end > len(numbered) {
			end = len(numbered)
		}
		if len(windows) > 0 && start <= windows[len(windows)-1].end {
			if end > windows[len(windows)-1].end {
				windows[len(windows)-1].end = end
			}
		} else {
			windows = append(windows, window{start: start, end: end})
		}
	}
	hunks := make([]ReviewHunk, 0, len(windows))
	for _, current := range windows {
		hunk := ReviewHunk{OldStart: numbered[current.start].oldLine, NewStart: numbered[current.start].newLine}
		for _, operation := range numbered[current.start:current.end] {
			hunk.Lines = append(hunk.Lines, ReviewLine{Kind: operation.kind, Text: operation.text})
			if operation.kind != '+' {
				hunk.OldLines++
			}
			if operation.kind != '-' {
				hunk.NewLines++
			}
		}
		if hunk.OldLines == 0 && hunk.OldStart > 0 {
			hunk.OldStart--
		}
		if hunk.NewLines == 0 && hunk.NewStart > 0 {
			hunk.NewStart--
		}
		hunks = append(hunks, hunk)
	}
	return hunks
}

func myersLineOperations(before, after []string) ([]lineOperation, bool) {
	n, m := len(before), len(after)
	maximum := n + m
	if maximum == 0 {
		return nil, true
	}
	offset := maximum + 1
	v := make([]int, 2*maximum+3)
	v[offset+1] = 0
	trace := make([][]int, 0, minInt(maximum, maximumReviewEditDistance)+1)
	for distance := 0; distance <= maximum && distance <= maximumReviewEditDistance; distance++ {
		for diagonal := -distance; diagonal <= distance; diagonal += 2 {
			index := offset + diagonal
			var x int
			if diagonal == -distance || (diagonal != distance && v[index-1] < v[index+1]) {
				x = v[index+1]
			} else {
				x = v[index-1] + 1
			}
			y := x - diagonal
			for x < n && y < m && before[x] == after[y] {
				x++
				y++
			}
			v[index] = x
			if x >= n && y >= m {
				trace = append(trace, append([]int(nil), v...))
				return backtrackLineOperations(before, after, trace, offset), true
			}
		}
		trace = append(trace, append([]int(nil), v...))
	}
	return nil, false
}

func backtrackLineOperations(before, after []string, trace [][]int, offset int) []lineOperation {
	x, y := len(before), len(after)
	reversed := make([]lineOperation, 0, x+y)
	for distance := len(trace) - 1; distance > 0; distance-- {
		previous := trace[distance-1]
		diagonal := x - y
		var previousDiagonal int
		if diagonal == -distance || (diagonal != distance && previous[offset+diagonal-1] < previous[offset+diagonal+1]) {
			previousDiagonal = diagonal + 1
		} else {
			previousDiagonal = diagonal - 1
		}
		previousX := previous[offset+previousDiagonal]
		previousY := previousX - previousDiagonal
		for x > previousX && y > previousY {
			reversed = append(reversed, lineOperation{kind: ' ', text: before[x-1]})
			x--
			y--
		}
		if x == previousX {
			y--
			reversed = append(reversed, lineOperation{kind: '+', text: after[y]})
		} else {
			x--
			reversed = append(reversed, lineOperation{kind: '-', text: before[x]})
		}
	}
	for x > 0 && y > 0 {
		reversed = append(reversed, lineOperation{kind: ' ', text: before[x-1]})
		x--
		y--
	}
	for x > 0 {
		x--
		reversed = append(reversed, lineOperation{kind: '-', text: before[x]})
	}
	for y > 0 {
		y--
		reversed = append(reversed, lineOperation{kind: '+', text: after[y]})
	}
	for left, right := 0, len(reversed)-1; left < right; left, right = left+1, right-1 {
		reversed[left], reversed[right] = reversed[right], reversed[left]
	}
	return reversed
}

func replacementLineOperations(before, after []string) []lineOperation {
	prefix := 0
	for prefix < len(before) && prefix < len(after) && before[prefix] == after[prefix] {
		prefix++
	}
	suffix := 0
	for suffix < len(before)-prefix && suffix < len(after)-prefix && before[len(before)-1-suffix] == after[len(after)-1-suffix] {
		suffix++
	}
	operations := make([]lineOperation, 0, len(before)+len(after))
	for _, line := range before[:prefix] {
		operations = append(operations, lineOperation{kind: ' ', text: line})
	}
	for _, line := range before[prefix : len(before)-suffix] {
		operations = append(operations, lineOperation{kind: '-', text: line})
	}
	for _, line := range after[prefix : len(after)-suffix] {
		operations = append(operations, lineOperation{kind: '+', text: line})
	}
	for _, line := range before[len(before)-suffix:] {
		operations = append(operations, lineOperation{kind: ' ', text: line})
	}
	return operations
}

func minInt(left, right int) int {
	if left < right {
		return left
	}
	return right
}
