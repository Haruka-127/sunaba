package terminal

import "testing"

func TestSanitizationProfiles(t *testing.T) {
	input := "line\n\t\x1b\x7f\u202e" + string([]byte{0xff})
	if got, want := SingleLine(input), "line<U+000A><U+0009><U+001B><U+007F><U+202E><INVALID-UTF8>"; got != want {
		t.Fatalf("single line=%q want=%q", got, want)
	}
	if got, want := Multiline(input), "line\n<U+0009><U+001B><U+007F><U+202E><INVALID-UTF8>"; got != want {
		t.Fatalf("multiline=%q want=%q", got, want)
	}
	if got, want := MultilineWithTabs(input), "line\n\t<U+001B><U+007F><U+202E><INVALID-UTF8>"; got != want {
		t.Fatalf("multiline with tabs=%q want=%q", got, want)
	}
}

func TestASCIIHookMessageBoundsAndFilters(t *testing.T) {
	if got, want := ASCIIHookMessage("ok\n日本語-safe", 10), "ok"; got != want {
		t.Fatalf("hook message=%q want=%q", got, want)
	}
}
