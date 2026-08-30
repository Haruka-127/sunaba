package tui

import (
	"bytes"
	"encoding/binary"
	"encoding/json"
	"strings"
	"testing"
)

func TestPrepareViewNormalizesRequiredArrayFields(t *testing.T) {
	view := View{
		Version: ProtocolVersion, Type: "view", ScreenID: "home", Revision: 1,
		Binding: Binding{ProcessID: 123, ProjectID: "project-1", Nonce: strings.Repeat("a", 64)}, Title: "Home",
	}
	if err := view.Validate(); err == nil {
		t.Fatal("nil fields and actions passed the protocol contract")
	}
	prepared, err := PrepareView(view)
	if err != nil || prepared.Fields == nil || prepared.Actions == nil {
		t.Fatalf("prepared=%+v error=%v", prepared, err)
	}
	encoded, err := json.Marshal(prepared)
	if err != nil {
		t.Fatal(err)
	}
	if !bytes.Contains(encoded, []byte(`"fields":[]`)) || !bytes.Contains(encoded, []byte(`"actions":[]`)) {
		t.Fatalf("required arrays were not encoded as arrays: %s", encoded)
	}
}

func TestPrepareViewNormalizesStructuredChangesArrays(t *testing.T) {
	view := View{
		Version: ProtocolVersion, Type: "view", ScreenID: "changes", Revision: 1,
		Binding: Binding{ProcessID: 123, ProjectID: "project-1", Nonce: strings.Repeat("a", 64)}, Title: "Changes",
		Fields:  []TextField{},
		Actions: []Action{{ID: "file.0", Label: "A test.txt"}},
		Changes: &ChangesView{
			Summary: "1 file", Layout: "side-by-side", Page: 1, Pages: 1, SelectedActionID: "file.0", InitialFocus: "files", InitialDiffPosition: "start", DiffPage: 1, DiffPages: 1,
			Files: []ChangeFile{{ActionID: "file.0", Status: "A", Path: "test.txt"}},
		},
	}
	if err := view.Validate(); err == nil {
		t.Fatal("nil structured Changes arrays passed the protocol contract")
	}
	prepared, err := PrepareView(view)
	if err != nil || prepared.Changes.Rows == nil {
		t.Fatalf("prepared=%+v error=%v", prepared, err)
	}
	encoded, err := json.Marshal(prepared)
	if err != nil {
		t.Fatal(err)
	}
	if !bytes.Contains(encoded, []byte(`"rows":[]`)) {
		t.Fatalf("structured Changes arrays were not encoded as arrays: %s", encoded)
	}
}

func testView(t *testing.T) View {
	t.Helper()
	binding := Binding{ProcessID: 123, ProjectID: "project-1", Nonce: strings.Repeat("a", 64)}
	view, err := PrepareView(View{
		Version: ProtocolVersion, Type: "view", ScreenID: "home", Revision: 7, Binding: binding,
		Title: "Home", Fields: []TextField{{ID: "status", Label: "Status", Text: "Ready"}},
		Actions: []Action{
			{ID: "start", Label: "Start"},
			{ID: "api-key", Label: "Set API key", Input: InputSpec{Allowed: true, Masked: true, MaxBytes: 128}},
		},
	})
	if err != nil {
		t.Fatal(err)
	}
	return view
}

func testEvent(view View) Event {
	return Event{Version: ProtocolVersion, Type: "event", ScreenID: view.ScreenID, Revision: view.Revision, Binding: view.Binding, Kind: EventAction, ActionID: "start", Capability: TerminalCapability{Color: true, Unicode: true}, Size: TerminalSize{Width: 120, Height: 40}}
}

func testChangesView(t *testing.T) View {
	t.Helper()
	binding := Binding{ProcessID: 123, ProjectID: "project-1", Nonce: strings.Repeat("a", 64)}
	view, err := PrepareView(View{
		Version: ProtocolVersion, Type: "view", ScreenID: "changes", Revision: 8, Binding: binding,
		Title:   "Review changes",
		Actions: []Action{{ID: "file.0", Label: "A test.txt"}, {ID: "apply-all", Label: "Apply all 1 file"}, {ID: "back", Label: "Back"}},
		Changes: &ChangesView{
			Summary: "1 file · 1 added", Layout: "side-by-side", Page: 1, Pages: 1, SelectedActionID: "file.0", InitialFocus: "files", InitialDiffPosition: "start",
			DiffTotal: 2, DiffPage: 1, DiffPages: 1,
			Files: []ChangeFile{{ActionID: "file.0", Status: "A", Path: "test.txt"}},
			Rows: []DiffRow{
				{Kind: "hunk", Header: "@@ -0,0 +1,1 @@", Before: DiffCell{Kind: "empty"}, After: DiffCell{Kind: "empty"}},
				{Kind: "content", Before: DiffCell{Kind: "empty"}, After: DiffCell{Kind: "add", Line: 1, Text: "test"}},
			},
		},
	})
	if err != nil {
		t.Fatal(err)
	}
	return view
}

func TestFrameRoundTripAndStrictJSON(t *testing.T) {
	view := testView(t)
	var encoded bytes.Buffer
	if err := WriteFrame(&encoded, view); err != nil {
		t.Fatal(err)
	}
	var decoded View
	if err := ReadFrame(&encoded, &decoded); err != nil || decoded.Revision != view.Revision {
		t.Fatalf("decoded=%+v error=%v", decoded, err)
	}
	for _, payload := range []string{
		`{"version":3,"type":"event","screen_id":"home","revision":7,"binding":{"process_id":123,"project_id":"project-1","nonce":"` + strings.Repeat("a", 64) + `"},"kind":"exit","action_id":"","input":"","capability":{"color":false,"unicode":false},"size":{"width":80,"height":24},"error":"","unknown":true}`,
		`{} {}`,
	} {
		var frame bytes.Buffer
		_ = binary.Write(&frame, binary.BigEndian, uint32(len(payload)))
		frame.WriteString(payload)
		var event Event
		if err := ReadFrame(&frame, &event); err == nil {
			t.Fatalf("strict decoder accepted %q", payload)
		}
	}
}

func TestFrameRejectsOversizeAndTrailingResponse(t *testing.T) {
	var oversize bytes.Buffer
	_ = binary.Write(&oversize, binary.BigEndian, uint32(MaxFrameBytes+1))
	var event Event
	if err := ReadFrame(&oversize, &event); err == nil {
		t.Fatal("oversize frame accepted")
	}
	view := testView(t)
	var response bytes.Buffer
	if err := WriteFrame(&response, testEvent(view)); err != nil {
		t.Fatal(err)
	}
	response.WriteByte(0)
	if _, err := ReadSingleEvent(&response); err == nil {
		t.Fatal("trailing response byte accepted")
	}
}

func TestEventRejectsStaleUnknownAndInvalidInput(t *testing.T) {
	view := testView(t)
	cases := []Event{
		func() Event { event := testEvent(view); event.Revision--; return event }(),
		func() Event { event := testEvent(view); event.ActionID = "destroy"; return event }(),
		func() Event { event := testEvent(view); event.Input = "not-allowed"; return event }(),
		func() Event {
			event := testEvent(view)
			event.ActionID = "api-key"
			event.Input = strings.Repeat("x", 129)
			return event
		}(),
		func() Event {
			event := testEvent(view)
			event.ActionID = "api-key"
			event.Input = "line\nbreak"
			return event
		}(),
		func() Event { event := testEvent(view); event.Size.Width = 0; return event }(),
	}
	for index, event := range cases {
		if err := event.ValidateFor(view); err == nil {
			t.Fatalf("invalid event %d accepted", index)
		}
	}
}

func TestSanitizeDisplayTextEscapesTerminalAndLayoutControls(t *testing.T) {
	input := "file\x1b]52;c;secret\a\nnext\u009b31m\u202eexe"
	output := SanitizeDisplayText(input)
	for _, unsafe := range []string{"\x1b", "\a", "\n", "\u009b", "\u202e"} {
		if strings.Contains(output, unsafe) {
			t.Fatalf("sanitized output retained %q: %q", unsafe, output)
		}
	}
	for _, marker := range []string{"<U+001B>", "<U+0007>", "<U+000A>", "<U+009B>", "<U+202E>"} {
		if !strings.Contains(output, marker) {
			t.Fatalf("sanitized output missing %q: %q", marker, output)
		}
	}
	view := testView(t)
	view.Fields[0].Text = input
	if err := view.Validate(); err == nil {
		t.Fatal("unsanitized view accepted")
	}
	if prepared, err := PrepareView(view); err != nil || strings.Contains(prepared.Fields[0].Text, "\x1b") {
		t.Fatalf("prepared=%+v error=%v", prepared, err)
	}
}

func TestViewRejectsAggregateTextOversize(t *testing.T) {
	view := testView(t)
	view.Fields = []TextField{
		{ID: "one", Label: "One", Text: strings.Repeat("x", 60<<10)},
		{ID: "two", Label: "Two", Text: strings.Repeat("x", 60<<10)},
		{ID: "three", Label: "Three", Text: strings.Repeat("x", 60<<10)},
	}
	if err := view.Validate(); err == nil {
		t.Fatal("aggregate oversize view accepted")
	}
}

func TestStructuredChangesRowsOwnLayoutAndBindVisibleFileActions(t *testing.T) {
	view := testChangesView(t)
	if err := view.Validate(); err != nil || view.Changes == nil || view.Changes.Rows[1].After.Text != "test" {
		t.Fatalf("structured view=%+v error=%v", view.Changes, err)
	}
	for name, mutate := range map[string]func(*View){
		"unbound selection": func(candidate *View) { candidate.Changes.SelectedActionID = "file.1" },
		"unsafe diff row":   func(candidate *View) { candidate.Changes.Rows[1].After.Text = "test\nfake action" },
		"invalid line":      func(candidate *View) { candidate.Changes.Rows[1].After.Line = 0 },
		"unknown cell kind": func(candidate *View) { candidate.Changes.Rows[1].After.Kind = "execute" },
		"invalid window":    func(candidate *View) { candidate.Changes.DiffStart = 2 },
	} {
		t.Run(name, func(t *testing.T) {
			candidate := testChangesView(t)
			mutate(&candidate)
			if err := candidate.Validate(); err == nil {
				t.Fatal("unsafe structured Changes view was accepted")
			}
		})
	}
	unsafe := testChangesView(t)
	unsafe.Changes.Files[0].Path = "fake\nApply all"
	prepared, err := PrepareView(unsafe)
	if err != nil || strings.Contains(prepared.Changes.Files[0].Path, "\n") || !strings.Contains(prepared.Changes.Files[0].Path, "<U+000A>") {
		t.Fatalf("prepared path=%q error=%v", prepared.Changes.Files[0].Path, err)
	}
}
