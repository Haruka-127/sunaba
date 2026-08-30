// Package tui defines the host-authoritative protocol used by the bundled
// sunaba-ui process. The helper can render a view and return one bounded event;
// it cannot name commands, paths, or mutations.
package tui

import (
	"bufio"
	"bytes"
	"encoding/binary"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"net"
	"regexp"
	"time"
	"unicode/utf8"
)

const (
	ProtocolVersion  = 4
	MaxFrameBytes    = 256 << 10
	MaxTextBytes     = 64 << 10
	MaxInputBytes    = 4 << 10
	MaxActions       = 32
	MaxFields        = 256
	MaxChangeFiles   = MaxActions - 6
	MaxDiffRows      = 256
	MaxDiffTotalRows = 8192
	MaxBulkItems     = 20
)

var (
	idPattern    = regexp.MustCompile(`^[a-z][a-z0-9._-]{0,63}$`)
	noncePattern = regexp.MustCompile(`^[0-9a-f]{64}$`)
	screenIDs    = map[string]struct{}{"home": {}, "project-selector": {}, "setup": {}, "settings": {}, "changes": {}, "recovery": {}}
)

type Binding struct {
	ProcessID int    `json:"process_id"`
	ProjectID string `json:"project_id"`
	Nonce     string `json:"nonce"`
}

type TextField struct {
	ID    string `json:"id"`
	Label string `json:"label"`
	Text  string `json:"text"`
}

type InputSpec struct {
	Allowed  bool `json:"allowed"`
	Masked   bool `json:"masked"`
	MaxBytes int  `json:"max_bytes"`
}

type Action struct {
	ID    string    `json:"id"`
	Label string    `json:"label"`
	Input InputSpec `json:"input"`
}

// ChangeFile is a bounded, already sanitized file-list entry. ActionID names
// the exact authority action to return when this entry is opened.
type ChangeFile struct {
	ActionID string `json:"action_id"`
	Status   string `json:"status"`
	Path     string `json:"path"`
	Detail   string `json:"detail"`
}

// DiffRow keeps repository-controlled text in individual cells. Newlines and
// column separators remain UI-owned structure; the helper derives responsive
// unified and side-by-side layouts from this single canonical representation.
type DiffCell struct {
	Kind string `json:"kind"`
	Line int    `json:"line"`
	Text string `json:"text"`
}

type DiffRow struct {
	Kind   string   `json:"kind"`
	Header string   `json:"header"`
	Before DiffCell `json:"before"`
	After  DiffCell `json:"after"`
}

type ChangesView struct {
	Summary             string       `json:"summary"`
	Layout              string       `json:"layout"`
	Page                int          `json:"page"`
	Pages               int          `json:"pages"`
	SelectedActionID    string       `json:"selected_action_id"`
	InitialFocus        string       `json:"initial_focus"`
	InitialDiffPosition string       `json:"initial_diff_position"`
	DiffStart           int          `json:"diff_start"`
	DiffTotal           int          `json:"diff_total"`
	DiffPage            int          `json:"diff_page"`
	DiffPages           int          `json:"diff_pages"`
	Files               []ChangeFile `json:"files"`
	Rows                []DiffRow    `json:"rows"`
}

type BulkItem struct {
	ActionID     string `json:"action_id"`
	BulkID       string `json:"bulk_id"`
	Root         string `json:"root"`
	Reason       string `json:"reason"`
	CaptureState string `json:"capture_state"`
	Disposition  string `json:"disposition"`
	Retention    string `json:"retention"`
	Summary      string `json:"summary"`
	DigestPrefix string `json:"digest_prefix"`
}

type BulkView struct {
	Page             int        `json:"page"`
	Pages            int        `json:"pages"`
	SelectedActionID string     `json:"selected_action_id"`
	Items            []BulkItem `json:"items"`
}

// View is immutable for a given ScreenID and Revision. All text must pass the
// host sanitizer before it crosses the process boundary.
type View struct {
	Version  int          `json:"version"`
	Type     string       `json:"type"`
	ScreenID string       `json:"screen_id"`
	Revision uint64       `json:"revision"`
	Binding  Binding      `json:"binding"`
	Title    string       `json:"title"`
	Fields   []TextField  `json:"fields"`
	Actions  []Action     `json:"actions"`
	Changes  *ChangesView `json:"changes"`
	Bulk     *BulkView    `json:"bulk"`
}

type TerminalCapability struct {
	Color   bool `json:"color"`
	Unicode bool `json:"unicode"`
}

type TerminalSize struct {
	Width  int `json:"width"`
	Height int `json:"height"`
}

// EventKind is intentionally closed. Only action events can request a state
// transition; every mutation is still revalidated and executed by Go.
type EventKind string

const (
	EventAction        EventKind = "action"
	EventCancel        EventKind = "cancel"
	EventExit          EventKind = "exit"
	EventTerminalError EventKind = "terminal_error"
)

type Event struct {
	Version    int                `json:"version"`
	Type       string             `json:"type"`
	ScreenID   string             `json:"screen_id"`
	Revision   uint64             `json:"revision"`
	Binding    Binding            `json:"binding"`
	Kind       EventKind          `json:"kind"`
	ActionID   string             `json:"action_id"`
	Input      string             `json:"input"`
	Capability TerminalCapability `json:"capability"`
	Size       TerminalSize       `json:"size"`
	Error      string             `json:"error"`
}

func (b Binding) validate() error {
	if b.ProcessID <= 0 || len(b.ProjectID) == 0 || len(b.ProjectID) > 128 || hasUnsafeInput(b.ProjectID) || !noncePattern.MatchString(b.Nonce) {
		return errors.New("invalid UI process binding")
	}
	return nil
}

func (v View) Validate() error {
	if _, known := screenIDs[v.ScreenID]; v.Version != ProtocolVersion || v.Type != "view" || !known || v.Revision == 0 {
		return errors.New("invalid UI view envelope")
	}
	if err := v.Binding.validate(); err != nil {
		return err
	}
	if v.Fields == nil || v.Actions == nil || len(v.Fields) > MaxFields || len(v.Actions) > MaxActions || len(v.Title) > MaxTextBytes || SanitizeDisplayText(v.Title) != v.Title {
		return errors.New("invalid or unsanitized UI view content")
	}
	totalBytes := len(v.Title)
	seenFields := make(map[string]struct{}, len(v.Fields))
	for _, field := range v.Fields {
		totalBytes += len(field.ID) + len(field.Label) + len(field.Text)
		if !idPattern.MatchString(field.ID) || len(field.Label)+len(field.Text) > MaxTextBytes || SanitizeDisplayText(field.Label) != field.Label || SanitizeDisplayText(field.Text) != field.Text {
			return fmt.Errorf("invalid or unsanitized UI field %q", field.ID)
		}
		if _, exists := seenFields[field.ID]; exists {
			return fmt.Errorf("duplicate UI field %q", field.ID)
		}
		seenFields[field.ID] = struct{}{}
	}
	seenActions := make(map[string]struct{}, len(v.Actions))
	for _, action := range v.Actions {
		totalBytes += len(action.ID) + len(action.Label)
		if !idPattern.MatchString(action.ID) || len(action.Label) == 0 || len(action.Label) > 256 || SanitizeDisplayText(action.Label) != action.Label {
			return fmt.Errorf("invalid UI action %q", action.ID)
		}
		if !action.Input.Allowed && (action.Input.Masked || action.Input.MaxBytes != 0) || action.Input.Allowed && (action.Input.MaxBytes <= 0 || action.Input.MaxBytes > MaxInputBytes) {
			return fmt.Errorf("invalid UI input contract for %q", action.ID)
		}
		if _, exists := seenActions[action.ID]; exists {
			return fmt.Errorf("duplicate UI action %q", action.ID)
		}
		seenActions[action.ID] = struct{}{}
	}
	if v.Changes != nil {
		if v.ScreenID != "changes" {
			return errors.New("structured Changes data is only valid on the Changes screen")
		}
		changesBytes, err := v.Changes.validate(seenActions)
		if err != nil {
			return err
		}
		totalBytes += changesBytes
	}
	if v.Bulk != nil {
		if v.ScreenID != "changes" || v.Changes != nil {
			return errors.New("structured Bulk data is only valid as a Changes section")
		}
		bulkBytes, err := v.Bulk.validate(seenActions)
		if err != nil {
			return err
		}
		totalBytes += bulkBytes
	}
	if totalBytes > MaxFrameBytes/2 {
		return errors.New("UI view content exceeds its aggregate size bound")
	}
	return nil
}

func (b BulkView) validate(actions map[string]struct{}) (int, error) {
	if b.Page <= 0 || b.Pages < b.Page || len(b.Items) == 0 || len(b.Items) > MaxBulkItems || !idPattern.MatchString(b.SelectedActionID) {
		return 0, errors.New("structured Bulk bounds are invalid")
	}
	total := len(b.SelectedActionID)
	selected := false
	seen := make(map[string]struct{}, len(b.Items))
	for _, item := range b.Items {
		total += len(item.ActionID) + len(item.BulkID) + len(item.Root) + len(item.Reason) + len(item.CaptureState) + len(item.Disposition) + len(item.Retention) + len(item.Summary) + len(item.DigestPrefix)
		if !idPattern.MatchString(item.ActionID) || item.BulkID == "" || item.Root == "" || item.Reason == "" || item.CaptureState == "" || item.Disposition == "" || item.Summary == "" || len(item.DigestPrefix) > 64 || SanitizeDisplayText(item.BulkID) != item.BulkID || SanitizeDisplayText(item.Root) != item.Root || SanitizeDisplayText(item.Reason) != item.Reason || SanitizeDisplayText(item.CaptureState) != item.CaptureState || SanitizeDisplayText(item.Disposition) != item.Disposition || SanitizeDisplayText(item.Retention) != item.Retention || SanitizeDisplayText(item.Summary) != item.Summary || SanitizeDisplayText(item.DigestPrefix) != item.DigestPrefix {
			return 0, errors.New("structured Bulk item is invalid")
		}
		if _, exists := actions[item.ActionID]; !exists {
			return 0, errors.New("structured Bulk item is not bound to an authority action")
		}
		if _, duplicate := seen[item.ActionID]; duplicate {
			return 0, errors.New("structured Bulk action is duplicated")
		}
		seen[item.ActionID] = struct{}{}
		selected = selected || item.ActionID == b.SelectedActionID
	}
	if !selected {
		return 0, errors.New("structured Bulk selection is not visible")
	}
	return total, nil
}

func (c ChangesView) validate(actions map[string]struct{}) (int, error) {
	if c.Files == nil || c.Rows == nil || c.Summary == "" || len(c.Summary) > MaxTextBytes || SanitizeDisplayText(c.Summary) != c.Summary || c.Layout != "side-by-side" || (c.InitialFocus != "files" && c.InitialFocus != "diff") || (c.InitialDiffPosition != "start" && c.InitialDiffPosition != "end") || c.Page <= 0 || c.Pages < c.Page || c.DiffPage <= 0 || c.DiffPages < c.DiffPage || c.DiffStart < 0 || c.DiffTotal < 0 || c.DiffTotal > MaxDiffTotalRows || len(c.Files) == 0 || len(c.Files) > MaxChangeFiles || len(c.Rows) > MaxDiffRows {
		return 0, errors.New("structured Changes summary or bounds are invalid")
	}
	if c.DiffTotal == 0 && (c.DiffStart != 0 || len(c.Rows) != 0 || c.DiffPage != 1 || c.DiffPages != 1) || c.DiffTotal > 0 && (len(c.Rows) == 0 || c.DiffStart >= c.DiffTotal || c.DiffStart+len(c.Rows) > c.DiffTotal) {
		return 0, errors.New("structured Changes diff window is invalid")
	}
	total := len(c.Summary) + len(c.Layout) + len(c.SelectedActionID)
	selected := false
	seen := make(map[string]struct{}, len(c.Files))
	for _, file := range c.Files {
		total += len(file.ActionID) + len(file.Status) + len(file.Path) + len(file.Detail)
		if !idPattern.MatchString(file.ActionID) || (file.Status != "A" && file.Status != "M" && file.Status != "D" && file.Status != "R") || file.Path == "" || len(file.Path)+len(file.Detail) > MaxTextBytes || SanitizeDisplayText(file.Path) != file.Path || SanitizeDisplayText(file.Detail) != file.Detail {
			return 0, errors.New("structured Changes file entry is invalid")
		}
		if _, exists := actions[file.ActionID]; !exists {
			return 0, errors.New("structured Changes file is not bound to an authority action")
		}
		if _, duplicate := seen[file.ActionID]; duplicate {
			return 0, errors.New("structured Changes file action is duplicated")
		}
		seen[file.ActionID] = struct{}{}
		selected = selected || file.ActionID == c.SelectedActionID
	}
	if !selected {
		return 0, errors.New("structured Changes selection is not visible")
	}
	for _, row := range c.Rows {
		total += len(row.Kind) + len(row.Header) + len(row.Before.Kind) + len(row.Before.Text) + len(row.After.Kind) + len(row.After.Text)
		if !validDiffRow(row) {
			return 0, errors.New("structured diff row is invalid")
		}
	}
	return total, nil
}

func validDiffRow(row DiffRow) bool {
	if len(row.Header)+len(row.Before.Text)+len(row.After.Text) > MaxTextBytes || SanitizeDisplayText(row.Header) != row.Header || SanitizeDisplayText(row.Before.Text) != row.Before.Text || SanitizeDisplayText(row.After.Text) != row.After.Text {
		return false
	}
	if row.Kind == "hunk" {
		empty := DiffCell{Kind: "empty"}
		return row.Header != "" && row.Before == empty && row.After == empty
	}
	if row.Kind != "content" || row.Header != "" {
		return false
	}
	validCell := func(cell DiffCell, allowed ...string) bool {
		if cell.Kind == "empty" {
			return cell.Line == 0 && cell.Text == ""
		}
		if cell.Line <= 0 {
			return false
		}
		for _, kind := range allowed {
			if cell.Kind == kind {
				return true
			}
		}
		return false
	}
	if !validCell(row.Before, "context", "delete") || !validCell(row.After, "context", "add") {
		return false
	}
	return row.Before.Kind != "empty" || row.After.Kind != "empty"
}

// PrepareView is the mandatory sanitization seam for data that may originate
// from a guest, repository, diff, or external error.
func PrepareView(view View) (View, error) {
	if view.Fields == nil {
		view.Fields = []TextField{}
	}
	if view.Actions == nil {
		view.Actions = []Action{}
	}
	view.Title = SanitizeDisplayText(view.Title)
	for index := range view.Fields {
		view.Fields[index].Label = SanitizeDisplayText(view.Fields[index].Label)
		view.Fields[index].Text = SanitizeDisplayText(view.Fields[index].Text)
	}
	for index := range view.Actions {
		view.Actions[index].Label = SanitizeDisplayText(view.Actions[index].Label)
	}
	if view.Changes != nil {
		if view.Changes.Files == nil {
			view.Changes.Files = []ChangeFile{}
		}
		if view.Changes.Rows == nil {
			view.Changes.Rows = []DiffRow{}
		}
		view.Changes.Summary = SanitizeDisplayText(view.Changes.Summary)
		for index := range view.Changes.Files {
			view.Changes.Files[index].Path = SanitizeDisplayText(view.Changes.Files[index].Path)
			view.Changes.Files[index].Detail = SanitizeDisplayText(view.Changes.Files[index].Detail)
		}
		for index := range view.Changes.Rows {
			row := &view.Changes.Rows[index]
			row.Header = SanitizeDisplayText(row.Header)
			row.Before.Text = SanitizeDisplayText(row.Before.Text)
			row.After.Text = SanitizeDisplayText(row.After.Text)
		}
	}
	if view.Bulk != nil {
		if view.Bulk.Items == nil {
			view.Bulk.Items = []BulkItem{}
		}
		for index := range view.Bulk.Items {
			item := &view.Bulk.Items[index]
			item.BulkID = SanitizeDisplayText(item.BulkID)
			item.Root = SanitizeDisplayText(item.Root)
			item.Reason = SanitizeDisplayText(item.Reason)
			item.CaptureState = SanitizeDisplayText(item.CaptureState)
			item.Disposition = SanitizeDisplayText(item.Disposition)
			item.Retention = SanitizeDisplayText(item.Retention)
			item.Summary = SanitizeDisplayText(item.Summary)
			item.DigestPrefix = SanitizeDisplayText(item.DigestPrefix)
		}
	}
	return view, view.Validate()
}

func (e Event) ValidateFor(view View) error {
	if err := view.Validate(); err != nil {
		return fmt.Errorf("authority view: %w", err)
	}
	if e.Version != ProtocolVersion || e.Type != "event" || e.ScreenID != view.ScreenID || e.Revision != view.Revision || e.Binding != view.Binding {
		return errors.New("stale or unbound UI event")
	}
	if e.Size.Width <= 0 || e.Size.Width > 1000 || e.Size.Height <= 0 || e.Size.Height > 1000 {
		return errors.New("invalid terminal size")
	}
	if len(e.Input) > MaxInputBytes || len(e.Error) > MaxInputBytes || hasUnsafeInput(e.Input) || hasUnsafeInput(e.Error) {
		return errors.New("invalid UI input")
	}
	switch e.Kind {
	case EventAction:
		if !idPattern.MatchString(e.ActionID) || e.Error != "" {
			return errors.New("invalid UI action event")
		}
		for _, action := range view.Actions {
			if action.ID != e.ActionID {
				continue
			}
			if !action.Input.Allowed && e.Input != "" || action.Input.Allowed && len(e.Input) > action.Input.MaxBytes {
				return errors.New("UI action input violates its bound")
			}
			return nil
		}
		return errors.New("unknown UI action")
	case EventCancel, EventExit:
		if e.ActionID != "" || e.Input != "" || e.Error != "" {
			return errors.New("unexpected data on UI exit event")
		}
		return nil
	case EventTerminalError:
		if e.ActionID != "" || e.Input != "" || e.Error == "" {
			return errors.New("invalid terminal error event")
		}
		return nil
	default:
		return errors.New("unknown UI event kind")
	}
}

func WriteFrame(writer io.Writer, value any) error {
	payload, err := json.Marshal(value)
	if err != nil {
		return err
	}
	if len(payload) == 0 || len(payload) > MaxFrameBytes {
		return errors.New("UI frame exceeds its size bound")
	}
	var header [4]byte
	binary.BigEndian.PutUint32(header[:], uint32(len(payload)))
	if err := writeAll(writer, header[:]); err != nil {
		return err
	}
	return writeAll(writer, payload)
}

func writeAll(writer io.Writer, payload []byte) error {
	for len(payload) > 0 {
		written, err := writer.Write(payload)
		if err != nil {
			return err
		}
		if written <= 0 {
			return io.ErrShortWrite
		}
		payload = payload[written:]
	}
	return nil
}

func ReadFrame(reader io.Reader, target any) error {
	var header [4]byte
	if _, err := io.ReadFull(reader, header[:]); err != nil {
		return fmt.Errorf("read UI frame header: %w", err)
	}
	size := binary.BigEndian.Uint32(header[:])
	if size == 0 || size > MaxFrameBytes {
		return errors.New("UI frame exceeds its size bound")
	}
	return readFrameBody(reader, size, target)
}

func readFrameBody(reader io.Reader, size uint32, target any) error {
	if size == 0 || size > MaxFrameBytes {
		return errors.New("UI frame exceeds its size bound")
	}
	payload := make([]byte, int(size))
	if _, err := io.ReadFull(reader, payload); err != nil {
		return fmt.Errorf("read UI frame body: %w", err)
	}
	decoder := json.NewDecoder(bytes.NewReader(payload))
	decoder.DisallowUnknownFields()
	if err := decoder.Decode(target); err != nil {
		return fmt.Errorf("decode UI frame: %w", err)
	}
	if err := requireJSONEOF(decoder); err != nil {
		return err
	}
	return nil
}

func requireJSONEOF(decoder *json.Decoder) error {
	var trailing any
	if err := decoder.Decode(&trailing); !errors.Is(err, io.EOF) {
		if err == nil {
			return errors.New("UI frame contains trailing JSON data")
		}
		return fmt.Errorf("decode trailing UI data: %w", err)
	}
	return nil
}

// ReadSingleEvent requires the helper to half-close after its only response.
// This makes a second frame or arbitrary trailing bytes a protocol violation.
func ReadSingleEvent(reader io.Reader) (Event, error) {
	buffered := bufio.NewReader(reader)
	var event Event
	if err := ReadFrame(buffered, &event); err != nil {
		return Event{}, err
	}
	if _, err := buffered.ReadByte(); !errors.Is(err, io.EOF) {
		if err == nil {
			return Event{}, errors.New("UI response contains trailing data")
		}
		return Event{}, fmt.Errorf("read trailing UI response: %w", err)
	}
	return event, nil
}

func readSingleEventFromConn(connection net.Conn, waitDeadline time.Time, frameTimeout time.Duration) (Event, error) {
	if err := connection.SetReadDeadline(waitDeadline); err != nil {
		return Event{}, err
	}
	var header [4]byte
	if _, err := io.ReadFull(connection, header[:]); err != nil {
		return Event{}, fmt.Errorf("read UI frame header: %w", err)
	}
	if err := connection.SetReadDeadline(time.Now().Add(frameTimeout)); err != nil {
		return Event{}, err
	}
	var event Event
	if err := readFrameBody(connection, binary.BigEndian.Uint32(header[:]), &event); err != nil {
		return Event{}, err
	}
	var trailing [1]byte
	if _, err := connection.Read(trailing[:]); !errors.Is(err, io.EOF) {
		if err == nil {
			return Event{}, errors.New("UI response contains trailing data")
		}
		return Event{}, fmt.Errorf("read trailing UI response: %w", err)
	}
	return event, nil
}

func hasUnsafeInput(value string) bool {
	if !utf8.ValidString(value) {
		return true
	}
	for _, r := range value {
		if r < 0x20 || r >= 0x7f && r <= 0x9f || isBidiControl(r) {
			return true
		}
	}
	return false
}
