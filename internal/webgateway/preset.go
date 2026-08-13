package webgateway

import (
	"bufio"
	"bytes"
	"crypto/sha256"
	_ "embed"
	"encoding/hex"
	"encoding/json"
	"fmt"
	"net/url"
	"sort"
	"strings"
	"sync"
)

const CommonDevelopmentOriginPreset = "common-development"

//go:embed common-development-origins.txt
var commonDevelopmentOriginSource []byte

var (
	commonDevelopmentOnce   sync.Once
	commonDevelopmentRules  []OriginRule
	commonDevelopmentDigest string
	commonDevelopmentError  error
)

// ResolveOriginRules expands the selected built-in presets, adds Project-local
// rules, removes exact access duplicates, and returns a canonical effective
// allowlist. The preset digest covers only the selected built-in material so a
// sunaba upgrade cannot silently change an already-applied effective policy.
func ResolveOriginRules(presets []string, custom []OriginRule) ([]OriginRule, string, error) {
	names := append([]string(nil), presets...)
	sort.Strings(names)
	for index, name := range names {
		if name == "" || (index > 0 && name == names[index-1]) {
			return nil, "", fmt.Errorf("Web origin presets must be unique non-empty names")
		}
	}

	presetRules := make([]OriginRule, 0)
	presetSourceDigests := make([]string, 0, len(names))
	for _, name := range names {
		switch name {
		case CommonDevelopmentOriginPreset:
			rules, sourceDigest, err := commonDevelopmentPreset()
			if err != nil {
				return nil, "", err
			}
			presetRules = append(presetRules, rules...)
			presetSourceDigests = append(presetSourceDigests, sourceDigest)
		default:
			return nil, "", fmt.Errorf("unknown Web origin preset %q", name)
		}
	}

	if len(custom) > 0 {
		for _, rule := range custom {
			if rule.Category != "user" {
				return nil, "", fmt.Errorf("Project Web origin rules must use the user category")
			}
		}
		if _, err := canonicalOriginRules(custom); err != nil {
			return nil, "", err
		}
	}

	combined := make([]OriginRule, 0, len(presetRules)+len(custom))
	seen := make(map[string]struct{}, len(presetRules)+len(custom))
	for _, rule := range append(presetRules, custom...) {
		key := originAccessKey(rule)
		if _, exists := seen[key]; exists {
			continue
		}
		seen[key] = struct{}{}
		combined = append(combined, rule)
	}
	canonical, err := canonicalOriginRules(combined)
	if err != nil {
		return nil, "", err
	}
	if len(canonical) > 1024 {
		return nil, "", fmt.Errorf("resolved Web origin policy exceeds 1024 rules")
	}

	presetDigest := ""
	if len(names) == 1 {
		presetDigest = presetSourceDigests[0]
	} else if len(names) > 1 {
		encoded, err := json.Marshal(struct {
			Names   []string `json:"names"`
			Digests []string `json:"digests"`
		}{Names: names, Digests: presetSourceDigests})
		if err != nil {
			return nil, "", err
		}
		digest := sha256.Sum256(encoded)
		presetDigest = hex.EncodeToString(digest[:])
	}
	return canonical, presetDigest, nil
}

func commonDevelopmentPreset() ([]OriginRule, string, error) {
	commonDevelopmentOnce.Do(func() {
		commonDevelopmentRules, commonDevelopmentError = parseOriginPreset(commonDevelopmentOriginSource, CommonDevelopmentOriginPreset)
		if commonDevelopmentError != nil {
			return
		}
		digest := sha256.Sum256(commonDevelopmentOriginSource)
		commonDevelopmentDigest = hex.EncodeToString(digest[:])
	})
	return append([]OriginRule(nil), commonDevelopmentRules...), commonDevelopmentDigest, commonDevelopmentError
}

func parseOriginPreset(data []byte, category string) ([]OriginRule, error) {
	if len(data) == 0 || len(data) > 64<<10 {
		return nil, fmt.Errorf("embedded Web origin preset has an invalid size")
	}
	scanner := bufio.NewScanner(bytes.NewReader(data))
	scanner.Buffer(make([]byte, 4096), 64<<10)
	rules := make([]OriginRule, 0)
	for lineNumber := 1; scanner.Scan(); lineNumber++ {
		line := strings.TrimSpace(scanner.Text())
		if line == "" || strings.HasPrefix(line, "#") {
			continue
		}
		fields := strings.Fields(line)
		if len(fields) < 1 || len(fields) > 2 || (len(fields) == 2 && fields[1] != "include-subdomains") {
			return nil, fmt.Errorf("embedded Web origin preset line %d is invalid", lineNumber)
		}
		rule, err := parsePresetOrigin(fields[0], category, len(fields) == 2)
		if err != nil {
			return nil, fmt.Errorf("embedded Web origin preset line %d: %w", lineNumber, err)
		}
		rules = append(rules, rule)
	}
	if err := scanner.Err(); err != nil {
		return nil, fmt.Errorf("scan embedded Web origin preset: %w", err)
	}
	canonical, err := canonicalOriginRules(rules)
	if err != nil {
		return nil, fmt.Errorf("invalid embedded Web origin preset: %w", err)
	}
	return canonical, nil
}

func parsePresetOrigin(raw, category string, includeSubdomains bool) (OriginRule, error) {
	parsed, err := url.Parse(raw)
	if err != nil || parsed.Opaque != "" || parsed.User != nil || parsed.Host == "" || parsed.RawQuery != "" || parsed.ForceQuery || parsed.Fragment != "" || (parsed.Path != "" && parsed.Path != "/") || strings.ContainsAny(raw, "\x00\r\n") {
		return OriginRule{}, fmt.Errorf("origin must contain only scheme and hostname")
	}
	host := strings.ToLower(parsed.Hostname())
	port := parsed.Port()
	expectedAuthority := host
	if port != "" {
		expectedAuthority += ":" + port
	}
	if strings.ToLower(parsed.Host) != expectedAuthority {
		return OriginRule{}, fmt.Errorf("origin authority is invalid")
	}
	rule := OriginRule{Host: host, Category: category, IncludeSubdomains: includeSubdomains}
	switch parsed.Scheme {
	case "http":
		if port != "" && port != "80" {
			return OriginRule{}, fmt.Errorf("HTTP origin must use port 80")
		}
		rule.Port, rule.AllowHTTP = 80, true
	case "https":
		if port != "" && port != "443" {
			return OriginRule{}, fmt.Errorf("HTTPS origin must use port 443")
		}
		rule.Port, rule.AllowConnect = 443, true
	default:
		return OriginRule{}, fmt.Errorf("origin scheme must be http or https")
	}
	return rule, nil
}

func canonicalOriginRules(rules []OriginRule) ([]OriginRule, error) {
	if len(rules) == 0 {
		return nil, nil
	}
	canonical, err := (Policy{Rules: rules}).canonical()
	if err != nil {
		return nil, err
	}
	return canonical.Rules, nil
}

func originAccessKey(rule OriginRule) string {
	return fmt.Sprintf("%s:%d:%t:%t:%t", strings.ToLower(strings.TrimSuffix(rule.Host, ".")), rule.Port, rule.AllowHTTP, rule.AllowConnect, rule.IncludeSubdomains)
}
