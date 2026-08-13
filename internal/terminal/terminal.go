package terminal

import (
	"fmt"
	"strings"
	"unicode/utf8"
)

// IsUnsafeRune reports whether a valid rune can alter terminal state or the
// visual ordering of adjacent text. Newline and tab are unsafe by default;
// profiles that intentionally retain them handle those runes before calling it.
func IsUnsafeRune(r rune) bool {
	return (r >= 0 && r < 0x20) || (r >= 0x7f && r <= 0x9f) ||
		r == 0x200e || r == 0x200f || (r >= 0x202a && r <= 0x202e) || (r >= 0x2066 && r <= 0x2069)
}

// SingleLine escapes every terminal control, including newline and tab.
func SingleLine(text string) string {
	return encode(text, false, false)
}

// Multiline retains line feeds but escapes tabs and all other terminal controls.
func Multiline(text string) string {
	return encode(text, true, false)
}

// MultilineWithTabs retains line feeds and tabs for structured text whose
// layout is part of the payload, while still escaping terminal actions.
func MultilineWithTabs(text string) string {
	return encode(text, true, true)
}

// ASCIIHookMessage returns at most maximum input bytes of printable ASCII.
func ASCIIHookMessage(text string, maximum int) string {
	if maximum <= 0 {
		return ""
	}
	if len(text) > maximum {
		text = text[:maximum]
	}
	var output strings.Builder
	output.Grow(len(text))
	for _, r := range text {
		if r >= 0x20 && r < 0x7f {
			output.WriteRune(r)
		}
	}
	return output.String()
}

func encode(text string, preserveNewline, preserveTab bool) string {
	var output strings.Builder
	output.Grow(len(text))
	for len(text) > 0 {
		r, size := utf8.DecodeRuneInString(text)
		if r == utf8.RuneError && size == 1 {
			output.WriteString("<INVALID-UTF8>")
			text = text[1:]
			continue
		}
		switch {
		case r == '\n' && preserveNewline:
			output.WriteByte('\n')
		case r == '\t' && preserveTab:
			output.WriteByte('\t')
		case IsUnsafeRune(r):
			fmt.Fprintf(&output, "<U+%04X>", r)
		default:
			output.WriteRune(r)
		}
		text = text[size:]
	}
	return output.String()
}
