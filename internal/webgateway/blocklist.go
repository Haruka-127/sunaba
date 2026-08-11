package webgateway

import (
	"bufio"
	"bytes"
	"context"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"fmt"
	"io"
	"net/http"
	"net/url"
	"sort"
	"strings"
	"time"
)

const (
	BlocklistFormatHosts = "hosts-v1"
	maxBlocklistBytes    = 8 << 20
	maxBlocklistDomains  = 100_000
	maxBlocklistTTL      = 14 * 24 * time.Hour
)

type BlocklistManifest struct {
	SchemaVersion int       `json:"schema_version"`
	SourceURL     string    `json:"source_url"`
	Format        string    `json:"format"`
	SHA256        string    `json:"sha256"`
	FetchedAt     time.Time `json:"fetched_at"`
	ExpiresAt     time.Time `json:"expires_at"`
}

type BlocklistSnapshot struct {
	Manifest BlocklistManifest
	Data     []byte
	Domains  []string
}

func FetchBlocklist(ctx context.Context, client *http.Client, sourceURL string, now time.Time, ttl time.Duration) (BlocklistSnapshot, error) {
	if _, err := validateBlocklistSource(sourceURL); err != nil {
		return BlocklistSnapshot{}, err
	}
	if ttl <= 0 || ttl > maxBlocklistTTL {
		return BlocklistSnapshot{}, fmt.Errorf("blocklist TTL must be positive and at most %s", maxBlocklistTTL)
	}
	if client == nil {
		transport := http.DefaultTransport.(*http.Transport).Clone()
		transport.Proxy = nil
		client = &http.Client{Transport: transport, Timeout: 30 * time.Second}
	}
	clientCopy := *client
	clientCopy.CheckRedirect = func(_ *http.Request, _ []*http.Request) error { return http.ErrUseLastResponse }
	request, err := http.NewRequestWithContext(ctx, http.MethodGet, sourceURL, nil)
	if err != nil {
		return BlocklistSnapshot{}, err
	}
	request.Header.Set("Accept", "text/plain")
	request.Header.Set("User-Agent", "sunaba-web-blocklist/1")
	response, err := clientCopy.Do(request)
	if err != nil {
		return BlocklistSnapshot{}, fmt.Errorf("fetch blocklist: %w", err)
	}
	defer response.Body.Close()
	if response.StatusCode != http.StatusOK {
		return BlocklistSnapshot{}, fmt.Errorf("blocklist source returned HTTP %d", response.StatusCode)
	}
	data, err := io.ReadAll(io.LimitReader(response.Body, maxBlocklistBytes+1))
	if err != nil || len(data) > maxBlocklistBytes {
		return BlocklistSnapshot{}, fmt.Errorf("blocklist response exceeds its bounded size")
	}
	digest := sha256.Sum256(data)
	manifest := BlocklistManifest{
		SchemaVersion: 1, SourceURL: sourceURL, Format: BlocklistFormatHosts,
		SHA256: hex.EncodeToString(digest[:]), FetchedAt: now.UTC(), ExpiresAt: now.Add(ttl).UTC(),
	}
	return LoadBlocklist(manifest, data, now)
}

func LoadBlocklist(manifest BlocklistManifest, data []byte, now time.Time) (BlocklistSnapshot, error) {
	if manifest.SchemaVersion != 1 || manifest.Format != BlocklistFormatHosts {
		return BlocklistSnapshot{}, fmt.Errorf("unsupported blocklist manifest")
	}
	if _, err := validateBlocklistSource(manifest.SourceURL); err != nil {
		return BlocklistSnapshot{}, err
	}
	if manifest.FetchedAt.IsZero() || manifest.ExpiresAt.IsZero() || !manifest.ExpiresAt.After(manifest.FetchedAt) || manifest.ExpiresAt.Sub(manifest.FetchedAt) > maxBlocklistTTL {
		return BlocklistSnapshot{}, fmt.Errorf("blocklist validity window is invalid")
	}
	if now.Before(manifest.FetchedAt.Add(-5*time.Minute)) || !now.Before(manifest.ExpiresAt) {
		return BlocklistSnapshot{}, fmt.Errorf("blocklist snapshot is not currently valid")
	}
	if len(data) == 0 || len(data) > maxBlocklistBytes {
		return BlocklistSnapshot{}, fmt.Errorf("blocklist data size is invalid")
	}
	digest := sha256.Sum256(data)
	if manifest.SHA256 != hex.EncodeToString(digest[:]) {
		return BlocklistSnapshot{}, fmt.Errorf("blocklist digest does not match its manifest")
	}
	domains, err := parseHostsBlocklist(data)
	if err != nil {
		return BlocklistSnapshot{}, err
	}
	return BlocklistSnapshot{Manifest: manifest, Data: append([]byte(nil), data...), Domains: domains}, nil
}

func (m BlocklistManifest) Marshal() ([]byte, error) {
	return json.MarshalIndent(m, "", "  ")
}

func ParseBlocklistManifest(data []byte) (BlocklistManifest, error) {
	decoder := json.NewDecoder(bytes.NewReader(data))
	decoder.DisallowUnknownFields()
	var manifest BlocklistManifest
	if err := decoder.Decode(&manifest); err != nil {
		return BlocklistManifest{}, fmt.Errorf("decode blocklist manifest: %w", err)
	}
	if decoder.Decode(&struct{}{}) != io.EOF {
		return BlocklistManifest{}, fmt.Errorf("blocklist manifest contains trailing data")
	}
	return manifest, nil
}

func validateBlocklistSource(raw string) (*url.URL, error) {
	parsed, err := url.Parse(raw)
	if err != nil || parsed.Scheme != "https" || parsed.Host == "" || parsed.User != nil || parsed.RawQuery != "" || parsed.Fragment != "" {
		return nil, fmt.Errorf("blocklist source must be a fixed HTTPS URL")
	}
	if _, err := normalizeHostname(parsed.Hostname()); err != nil || parsed.Port() != "" {
		return nil, fmt.Errorf("blocklist source host is invalid")
	}
	return parsed, nil
}

func parseHostsBlocklist(data []byte) ([]string, error) {
	scanner := bufio.NewScanner(bytes.NewReader(data))
	scanner.Buffer(make([]byte, 64<<10), 64<<10)
	domains := make(map[string]struct{})
	for scanner.Scan() {
		line := strings.TrimSpace(scanner.Text())
		if line == "" || strings.HasPrefix(line, "#") {
			continue
		}
		if comment := strings.IndexByte(line, '#'); comment >= 0 {
			line = strings.TrimSpace(line[:comment])
		}
		fields := strings.Fields(line)
		if len(fields) < 2 || (fields[0] != "0.0.0.0" && fields[0] != "127.0.0.1" && fields[0] != "::") {
			return nil, fmt.Errorf("blocklist contains a non-hosts-format record")
		}
		for _, candidate := range fields[1:] {
			domain, err := normalizeHostname(candidate)
			if err != nil {
				return nil, fmt.Errorf("blocklist contains an invalid domain")
			}
			if domain == "localhost" || domain == "localhost.localdomain" {
				continue
			}
			domains[domain] = struct{}{}
			if len(domains) > maxBlocklistDomains {
				return nil, fmt.Errorf("blocklist domain count exceeds its bound")
			}
		}
	}
	if err := scanner.Err(); err != nil {
		return nil, fmt.Errorf("scan blocklist: %w", err)
	}
	if len(domains) == 0 {
		return nil, fmt.Errorf("blocklist contains no domains")
	}
	result := make([]string, 0, len(domains))
	for domain := range domains {
		result = append(result, domain)
	}
	sort.Strings(result)
	return result, nil
}
