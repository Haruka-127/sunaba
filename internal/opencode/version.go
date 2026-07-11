package opencode

import (
	"regexp"
	"strconv"
	"strings"
)

var semanticVersionPattern = regexp.MustCompile(`(?:^|[^0-9])v?([0-9]+\.[0-9]+(?:\.[0-9]+)?)(?:[^0-9]|$)`)

func CompareVersion(a, b string) int {
	ap := splitVersion(a)
	bp := splitVersion(b)
	n := len(ap)
	if len(bp) > n {
		n = len(bp)
	}
	for i := 0; i < n; i++ {
		var av, bv int
		if i < len(ap) {
			av = ap[i]
		}
		if i < len(bp) {
			bv = bp[i]
		}
		if av < bv {
			return -1
		}
		if av > bv {
			return 1
		}
	}
	return 0
}

func splitVersion(v string) []int {
	v = strings.TrimPrefix(strings.TrimSpace(v), "v")
	v = strings.Split(v, "-")[0]
	parts := strings.Split(v, ".")
	out := make([]int, 0, len(parts))
	for _, p := range parts {
		n, _ := strconv.Atoi(p)
		out = append(out, n)
	}
	return out
}

func firstSemanticVersion(s string) string {
	m := semanticVersionPattern.FindStringSubmatch(s)
	if len(m) < 2 {
		return ""
	}
	return m[1]
}
