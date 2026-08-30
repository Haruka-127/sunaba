package workspace

import "fmt"

const WideReviewMinimumWidth = 120

type ReviewLayout string

const (
	ReviewLayoutUnified    ReviewLayout = "unified"
	ReviewLayoutSideBySide ReviewLayout = "side-by-side"
)

type ReviewFile struct {
	Status       string
	Path         string
	From         string
	Risks        []string
	Type         EntryType
	Size         int64
	SHA256       string
	OpaqueReason string
}

type UnifiedReviewRow struct {
	Kind byte
	Text string
}

type SideBySideReviewRow struct {
	BeforeKind byte
	Before     string
	AfterKind  byte
	After      string
}

// ReviewScreen is a bounded, read-only presentation of one selected item from
// a host-generated Change Set. It contains no path that the UI helper can open.
type ReviewScreen struct {
	ChangeSetDigest string
	Layout          ReviewLayout
	Files           []ReviewFile
	Selected        int
	Item            ReviewItem
	Unified         []UnifiedReviewRow
	SideBySide      []SideBySideReviewRow
}

func BuildReviewScreen(review Review, terminalWidth int, selectedPath string) (ReviewScreen, error) {
	if len(review.Items) == 0 || terminalWidth <= 0 || terminalWidth > 1000 {
		return ReviewScreen{}, fmt.Errorf("review screen requires changed files and a bounded terminal width")
	}
	selected := 0
	if selectedPath != "" {
		selected = -1
		for index, item := range review.Items {
			if item.Change.Path == selectedPath {
				selected = index
				break
			}
		}
		if selected < 0 {
			return ReviewScreen{}, fmt.Errorf("selected review path is not part of the Change Set")
		}
	}
	screen := ReviewScreen{ChangeSetDigest: review.ChangeSetDigest, Layout: ReviewLayoutUnified, Selected: selected, Item: review.Items[selected]}
	if terminalWidth >= WideReviewMinimumWidth {
		screen.Layout = ReviewLayoutSideBySide
	}
	screen.Files = make([]ReviewFile, len(review.Items))
	for index, item := range review.Items {
		screen.Files[index] = reviewFile(item)
	}
	screen.Unified, screen.SideBySide = reviewRows(screen.Item)
	return screen, nil
}

func reviewFile(item ReviewItem) ReviewFile {
	file := ReviewFile{Status: reviewStatus(item.Change.Kind), Path: item.Change.Path, From: item.Change.From, OpaqueReason: item.OpaqueReason}
	entry := item.Change.After
	if entry == nil {
		entry = item.Change.Before
	}
	if entry != nil {
		file.Type, file.Size, file.SHA256 = entry.Type, entry.Size, entry.SHA256
	}
	if item.Executable {
		file.Risks = append(file.Risks, "executable")
	}
	if item.Symlink {
		file.Risks = append(file.Risks, "symlink")
	}
	if item.Binary {
		file.Risks = append(file.Risks, "binary")
	}
	if item.OpaqueReason != "" && !item.Binary {
		file.Risks = append(file.Risks, "content-not-rendered")
	}
	if item.Change.Before != nil && item.Change.After != nil && item.Change.Before.Mode != item.Change.After.Mode {
		file.Risks = append(file.Risks, "mode-change")
	}
	return file
}

func reviewStatus(kind ChangeKind) string {
	switch kind {
	case ChangeAdd:
		return "A"
	case ChangeModify:
		return "M"
	case ChangeDelete:
		return "D"
	case ChangeRename:
		return "R"
	default:
		return "?"
	}
}

func reviewRows(item ReviewItem) ([]UnifiedReviewRow, []SideBySideReviewRow) {
	var unified []UnifiedReviewRow
	var side []SideBySideReviewRow
	for _, hunk := range item.Hunks {
		beforeHeader := fmt.Sprintf("@@ -%d,%d", hunk.OldStart, hunk.OldLines)
		afterHeader := fmt.Sprintf("+%d,%d @@", hunk.NewStart, hunk.NewLines)
		unified = append(unified, UnifiedReviewRow{Kind: '@', Text: beforeHeader + " " + afterHeader})
		side = append(side, SideBySideReviewRow{BeforeKind: '@', Before: beforeHeader, AfterKind: '@', After: afterHeader})
		var removed, added []string
		flushEdits := func() {
			count := max(len(removed), len(added))
			for index := 0; index < count; index++ {
				row := SideBySideReviewRow{}
				if index < len(removed) {
					row.BeforeKind, row.Before = '-', removed[index]
				}
				if index < len(added) {
					row.AfterKind, row.After = '+', added[index]
				}
				side = append(side, row)
			}
			removed, added = nil, nil
		}
		for _, line := range hunk.Lines {
			unified = append(unified, UnifiedReviewRow{Kind: line.Kind, Text: line.Text})
			switch line.Kind {
			case '-':
				removed = append(removed, line.Text)
			case '+':
				added = append(added, line.Text)
			default:
				flushEdits()
				side = append(side, SideBySideReviewRow{BeforeKind: ' ', Before: line.Text, AfterKind: ' ', After: line.Text})
			}
		}
		flushEdits()
	}
	return unified, side
}
