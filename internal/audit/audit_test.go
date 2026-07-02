package audit

import (
	"bufio"
	"strings"
	"testing"
)

func TestParseSSE(t *testing.T) {
	input := "event: x\ndata: {\"a\":1}\n\n:data ignored\ndata: hello\ndata: world\n\n"
	var got []string
	err := ParseSSE(bufio.NewScanner(strings.NewReader(input)), func(b []byte) error {
		got = append(got, string(b))
		return nil
	})
	if err != nil {
		t.Fatal(err)
	}
	if len(got) != 2 || got[0] != "{\"a\":1}" || got[1] != "hello\nworld" {
		t.Fatalf("got %#v", got)
	}
}
