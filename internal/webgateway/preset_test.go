package webgateway

import (
	"reflect"
	"testing"
)

func TestCommonDevelopmentPresetMatchesCuratedSource(t *testing.T) {
	rules, sourceDigest, err := commonDevelopmentPreset()
	if err != nil {
		t.Fatal(err)
	}
	if sourceDigest != "986b65106d38478b8fae51a8822110a794587c89b408059de6420e7bd25dc763" {
		t.Fatalf("source digest=%s", sourceDigest)
	}
	if len(rules) != 190 {
		t.Fatalf("rule count=%d", len(rules))
	}
	var httpRules, subdomainRules int
	for _, rule := range rules {
		if rule.Category != CommonDevelopmentOriginPreset {
			t.Fatalf("unexpected category in rule %+v", rule)
		}
		if rule.AllowHTTP {
			httpRules++
		}
		if rule.IncludeSubdomains {
			subdomainRules++
		}
	}
	if httpRules != 2 || subdomainRules != 8 {
		t.Fatalf("http=%d subdomains=%d", httpRules, subdomainRules)
	}
}

func TestResolveOriginRulesSupportsPresetCustomAndNoPreset(t *testing.T) {
	custom := []OriginRule{{Host: "custom.example", Port: 443, Category: "user", AllowConnect: true}}
	withPreset, digest, err := ResolveOriginRules([]string{CommonDevelopmentOriginPreset}, custom)
	if err != nil || len(withPreset) != 191 || digest != "986b65106d38478b8fae51a8822110a794587c89b408059de6420e7bd25dc763" {
		t.Fatalf("rules=%d digest=%q error=%v", len(withPreset), digest, err)
	}
	withoutPreset, noDigest, err := ResolveOriginRules(nil, custom)
	if err != nil || !reflect.DeepEqual(withoutPreset, custom) || noDigest != "" {
		t.Fatalf("rules=%+v digest=%q error=%v", withoutPreset, noDigest, err)
	}

	duplicate := []OriginRule{{Host: "github.com", Port: 443, Category: "user", AllowConnect: true, IncludeSubdomains: true}}
	resolved, _, err := ResolveOriginRules([]string{CommonDevelopmentOriginPreset}, duplicate)
	if err != nil || len(resolved) != 190 {
		t.Fatalf("overlap was not deduplicated: rules=%d error=%v", len(resolved), err)
	}
	if _, _, err := ResolveOriginRules([]string{"unknown"}, nil); err == nil {
		t.Fatal("unknown preset was accepted")
	}
}
