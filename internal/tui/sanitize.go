package tui

import (
	"fmt"
	"strings"
	"unicode/utf8"
)

// SanitizeDisplayText renders terminal controls, line separators, invalid
// UTF-8, and bidi controls as visible tokens. Newlines are escaped as well so a
// guest-controlled field cannot create a fake action or status row.
func SanitizeDisplayText(value string) string {
	var output strings.Builder
	for len(value) > 0 {
		r, size := utf8.DecodeRuneInString(value)
		if r == utf8.RuneError && size == 1 {
			output.WriteString("<INVALID-UTF8>")
			value = value[1:]
			continue
		}
		value = value[size:]
		if r < 0x20 || r >= 0x7f && r <= 0x9f || r == 0x2028 || r == 0x2029 || isBidiControl(r) {
			fmt.Fprintf(&output, "<U+%04X>", r)
			continue
		}
		output.WriteRune(r)
	}
	return output.String()
}

func isBidiControl(r rune) bool {
	return r == 0x061c || r == 0x200e || r == 0x200f || r >= 0x202a && r <= 0x202e || r >= 0x2066 && r <= 0x2069
}
