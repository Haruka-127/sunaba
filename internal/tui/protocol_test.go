package tui

import (
	"bytes"
	"encoding/binary"
	"strings"
	"testing"
)

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
		`{"version":1,"type":"event","screen_id":"home","revision":7,"binding":{"process_id":123,"project_id":"project-1","nonce":"` + strings.Repeat("a", 64) + `"},"kind":"exit","action_id":"","input":"","capability":{"color":false,"unicode":false},"size":{"width":80,"height":24},"error":"","unknown":true}`,
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
