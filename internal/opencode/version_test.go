package opencode

import "testing"

func TestCompareVersion(t *testing.T) {
	cases := []struct {
		a, b string
		want int
	}{
		{"1.17.13", "1.17.13", 0},
		{"v1.17.14", "1.17.13", 1},
		{"1.18.0", "1.17.99", 1},
		{"1.17.12", "1.17.13", -1},
	}
	for _, tc := range cases {
		if got := CompareVersion(tc.a, tc.b); got != tc.want {
			t.Fatalf("CompareVersion(%q,%q)=%d", tc.a, tc.b, got)
		}
	}
}
