package webgateway

import (
	"net/netip"
	"strings"
	"testing"
)

func FuzzNormalizeHostname(f *testing.F) {
	for _, seed := range []string{"example.com", "EXAMPLE.COM.", "sub.example.com", "127.0.0.1", "[::1]", "éxample.com", "a..b", strings.Repeat("a", 64) + ".com"} {
		f.Add(seed)
	}
	f.Fuzz(func(t *testing.T, input string) {
		normalized, err := normalizeHostname(input)
		if err != nil {
			return
		}
		if normalized != strings.ToLower(strings.TrimSuffix(input, ".")) {
			t.Fatalf("non-canonical hostname accepted: input=%q normalized=%q", input, normalized)
		}
		if _, err := netip.ParseAddr(normalized); err == nil {
			t.Fatalf("IP literal accepted as hostname: %q", normalized)
		}
		if repeated, err := normalizeHostname(normalized); err != nil || repeated != normalized {
			t.Fatalf("hostname normalization is not idempotent: %q %q %v", normalized, repeated, err)
		}
	})
}

func FuzzHostsBlocklistParser(f *testing.F) {
	for _, seed := range [][]byte{
		[]byte("0.0.0.0 malware.example\n"),
		[]byte("127.0.0.1 a.example b.example # comment\n"),
		[]byte("1.2.3.4 unsafe.example\n"),
		[]byte{0xff, 0xfe, 0xfd},
	} {
		f.Add(seed)
	}
	f.Fuzz(func(t *testing.T, input []byte) {
		if len(input) > 128<<10 {
			t.Skip()
		}
		domains, err := parseHostsBlocklist(input)
		if err != nil {
			return
		}
		for index, domain := range domains {
			if normalized, err := normalizeHostname(domain); err != nil || normalized != domain {
				t.Fatalf("parser returned unsafe domain %q", domain)
			}
			if index > 0 && domains[index-1] >= domain {
				t.Fatalf("parser result is not sorted and unique: %q >= %q", domains[index-1], domain)
			}
		}
	})
}
