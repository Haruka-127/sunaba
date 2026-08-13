// Package updater resolves and quarantines explicit OpenCode v1 updates.
package updater

import (
	"archive/zip"
	"bytes"
	"context"
	"crypto/rand"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"net/http"
	"os"
	"path/filepath"
	"regexp"
	"sort"
	"strconv"
	"strings"
	"time"

	"sunaba/internal/dependency"
	"sunaba/internal/securefs"
	"sunaba/internal/state"
	"sunaba/internal/versionconfig"
)

const (
	CandidateSchemaVersion = 1
	maxAPIBytes            = 4 << 20
	maxArtifactBytes       = 512 << 20
	maxCandidateBytes      = 2 << 20
)

var digestPattern = regexp.MustCompile(`^[0-9a-f]{64}$`)

type CandidateArtifact struct {
	RelativePath string `json:"relative_path"`
	SHA256       string `json:"sha256"`
}

type Candidate struct {
	SchemaVersion     int                 `json:"schema_version"`
	ID                string              `json:"id"`
	CreatedAt         time.Time           `json:"created_at"`
	ExpiresAt         time.Time           `json:"expires_at"`
	ConfigSHA256      string              `json:"config_sha256"`
	CurrentLockSHA256 string              `json:"current_lock_sha256"`
	Target            dependency.Manifest `json:"target_manifest"`
	HostArtifact      CandidateArtifact   `json:"host_artifact"`
	GuestArtifact     CandidateArtifact   `json:"guest_artifact"`
}

type Service struct {
	Client  *http.Client
	APIBase string
	Now     func() time.Time
}

type Store struct {
	State *state.Store
}

type release struct {
	TagName    string `json:"tag_name"`
	Draft      bool   `json:"draft"`
	Prerelease bool   `json:"prerelease"`
	Assets     []struct {
		Name string `json:"name"`
	} `json:"assets"`
}

type gitObject struct {
	Object struct {
		Type string `json:"type"`
		SHA  string `json:"sha"`
	} `json:"object"`
}

func (c Candidate) Validate() error {
	if c.SchemaVersion != CandidateSchemaVersion || !regexp.MustCompile(`^[0-9a-f]{32}$`).MatchString(c.ID) ||
		c.CreatedAt.IsZero() || c.ExpiresAt.IsZero() || !c.ExpiresAt.After(c.CreatedAt) ||
		!digestPattern.MatchString(c.ConfigSHA256) || !digestPattern.MatchString(c.CurrentLockSHA256) {
		return fmt.Errorf("update candidate metadata is invalid")
	}
	if err := dependency.ValidateRuntimeManifest(c.Target); err != nil {
		return fmt.Errorf("update candidate manifest: %w", err)
	}
	for _, artifact := range []CandidateArtifact{c.HostArtifact, c.GuestArtifact} {
		clean := filepath.Clean(artifact.RelativePath)
		if clean != artifact.RelativePath || filepath.IsAbs(clean) || strings.HasPrefix(clean, ".."+string(filepath.Separator)) || !strings.HasPrefix(clean, "artifacts"+string(filepath.Separator)+c.ID+string(filepath.Separator)) || !digestPattern.MatchString(artifact.SHA256) {
			return fmt.Errorf("update candidate artifact binding is invalid")
		}
	}
	return nil
}

func (s Service) Check(ctx context.Context, config versionconfig.Config, current versionconfig.Lock, store *Store) (Candidate, error) {
	if err := config.Validate(); err != nil {
		return Candidate{}, err
	}
	if err := current.Validate(); err != nil {
		return Candidate{}, err
	}
	if store == nil {
		return Candidate{}, fmt.Errorf("candidate store is required")
	}
	version, rel, err := s.resolveRelease(ctx, config)
	if err != nil {
		return Candidate{}, err
	}
	if version == current.Manifest.OpenCode.Version {
		return Candidate{}, fmt.Errorf("OpenCode %s is already the active exact version", version)
	}
	hostName, guestName := "opencode-darwin-arm64.zip", "opencode-linux-arm64.tar.gz"
	if !releaseHasAsset(rel, hostName) || !releaseHasAsset(rel, guestName) {
		return Candidate{}, fmt.Errorf("OpenCode v%s release lacks required darwin/arm64 or linux/arm64 artifacts", version)
	}
	commit, err := s.resolveCommit(ctx, version)
	if err != nil {
		return Candidate{}, err
	}
	id, err := randomID()
	if err != nil {
		return Candidate{}, err
	}
	artifactDirectory, err := store.ArtifactDirectory(id)
	if err != nil {
		return Candidate{}, err
	}
	if err := ensurePrivateDirectory(artifactDirectory); err != nil {
		return Candidate{}, err
	}
	hostPath := filepath.Join(artifactDirectory, hostName)
	guestPath := filepath.Join(artifactDirectory, guestName)
	hostURL := artifactURL(version, hostName)
	guestURL := artifactURL(version, guestName)
	hostDigest, err := s.download(ctx, hostURL, hostPath)
	if err != nil {
		return Candidate{}, err
	}
	guestDigest, err := s.download(ctx, guestURL, guestPath)
	if err != nil {
		return Candidate{}, err
	}
	executableDigest, err := executableSHA256(hostPath)
	if err != nil {
		return Candidate{}, err
	}
	target := current.Manifest
	target.OpenCode.Version = version
	target.OpenCode.Host = dependency.Artifact{OS: "darwin", Arch: "arm64", Artifact: hostName, URL: hostURL, SHA256: hostDigest, ExecutableSHA256: executableDigest}
	target.OpenCode.Guest = dependency.Artifact{OS: "linux", Arch: "arm64", Artifact: guestName, URL: guestURL, SHA256: guestDigest}
	target.AgentImage.Tag = "sunaba-base:" + version + "-secure.1"
	target.Provenance.OpenCode.Tag = "v" + version
	target.Provenance.OpenCode.Commit = commit
	if err := dependency.ValidateOpenCodeUpdateCandidate(current.Manifest, target); err != nil {
		return Candidate{}, err
	}
	configDigest, _ := versionconfig.ConfigDigest(config)
	lockDigest, _ := versionconfig.LockDigest(current)
	now := time.Now().UTC()
	if s.Now != nil {
		now = s.Now().UTC()
	}
	root, _ := store.root()
	candidate := Candidate{
		SchemaVersion: CandidateSchemaVersion, ID: id, CreatedAt: now, ExpiresAt: now.Add(24 * time.Hour),
		ConfigSHA256: configDigest, CurrentLockSHA256: lockDigest, Target: target,
		HostArtifact:  CandidateArtifact{RelativePath: relativeTo(root, hostPath), SHA256: hostDigest},
		GuestArtifact: CandidateArtifact{RelativePath: relativeTo(root, guestPath), SHA256: guestDigest},
	}
	if err := store.Save(candidate); err != nil {
		return Candidate{}, err
	}
	return candidate, nil
}

func (s Service) resolveRelease(ctx context.Context, config versionconfig.Config) (string, release, error) {
	if config.OpenCode.Strategy == "exact" {
		var result release
		if err := s.getJSON(ctx, "/releases/tags/v"+config.OpenCode.Value, &result); err != nil {
			return "", result, err
		}
		if result.Draft || result.Prerelease || result.TagName != "v"+config.OpenCode.Value {
			return "", result, fmt.Errorf("OpenCode release v%s is not a published exact release", config.OpenCode.Value)
		}
		return config.OpenCode.Value, result, nil
	}
	var releases []release
	if err := s.getJSON(ctx, "/releases?per_page=100", &releases); err != nil {
		return "", release{}, err
	}
	type item struct {
		version string
		parts   [3]int
		release release
	}
	items := make([]item, 0, len(releases))
	for _, candidate := range releases {
		parts, ok := parseV1(candidate.TagName)
		if ok && !candidate.Draft && !candidate.Prerelease {
			items = append(items, item{version: strings.TrimPrefix(candidate.TagName, "v"), parts: parts, release: candidate})
		}
	}
	if len(items) == 0 {
		return "", release{}, fmt.Errorf("no stable OpenCode v1 release was found")
	}
	sort.Slice(items, func(i, j int) bool {
		for k := range 3 {
			if items[i].parts[k] != items[j].parts[k] {
				return items[i].parts[k] > items[j].parts[k]
			}
		}
		return false
	})
	return items[0].version, items[0].release, nil
}

func (s Service) resolveCommit(ctx context.Context, version string) (string, error) {
	var ref gitObject
	if err := s.getJSON(ctx, "/git/ref/tags/v"+version, &ref); err != nil {
		return "", err
	}
	object := ref.Object
	if object.Type == "tag" {
		var tag gitObject
		if err := s.getJSON(ctx, "/git/tags/"+object.SHA, &tag); err != nil {
			return "", err
		}
		object = tag.Object
	}
	if object.Type != "commit" || !regexp.MustCompile(`^[0-9a-f]{40}$`).MatchString(object.SHA) {
		return "", fmt.Errorf("OpenCode v%s tag is not bound to a commit", version)
	}
	return object.SHA, nil
}

func (s Service) getJSON(ctx context.Context, path string, target any) error {
	base := strings.TrimRight(s.APIBase, "/")
	if base == "" {
		base = "https://api.github.com/repos/anomalyco/opencode"
	}
	request, err := http.NewRequestWithContext(ctx, http.MethodGet, base+path, nil)
	if err != nil {
		return err
	}
	request.Header.Set("Accept", "application/vnd.github+json")
	request.Header.Set("User-Agent", "sunaba-update-check")
	response, err := s.client().Do(request)
	if err != nil {
		return err
	}
	defer response.Body.Close()
	if response.StatusCode != http.StatusOK {
		return fmt.Errorf("GitHub release API returned %s", response.Status)
	}
	data, err := io.ReadAll(io.LimitReader(response.Body, maxAPIBytes+1))
	if err != nil {
		return err
	}
	if len(data) > maxAPIBytes {
		return fmt.Errorf("GitHub release API response exceeds its size bound")
	}
	decoder := json.NewDecoder(bytes.NewReader(data))
	if err := decoder.Decode(target); err != nil {
		return err
	}
	if err := decoder.Decode(&struct{}{}); err != io.EOF {
		return fmt.Errorf("GitHub release API returned trailing data")
	}
	return nil
}

func (s Service) download(ctx context.Context, url, destination string) (string, error) {
	request, err := http.NewRequestWithContext(ctx, http.MethodGet, url, nil)
	if err != nil {
		return "", err
	}
	request.Header.Set("User-Agent", "sunaba-update-check")
	response, err := s.client().Do(request)
	if err != nil {
		return "", err
	}
	defer response.Body.Close()
	if response.StatusCode != http.StatusOK {
		return "", fmt.Errorf("download %s returned %s", filepath.Base(destination), response.Status)
	}
	if response.ContentLength > maxArtifactBytes {
		return "", fmt.Errorf("artifact exceeds its size bound")
	}
	file, err := os.OpenFile(destination, os.O_WRONLY|os.O_CREATE|os.O_EXCL, 0600)
	if err != nil {
		return "", err
	}
	defer func() { _ = file.Close() }()
	hash := sha256.New()
	written, copyErr := io.Copy(io.MultiWriter(file, hash), io.LimitReader(response.Body, maxArtifactBytes+1))
	if copyErr != nil || written > maxArtifactBytes {
		return "", errors.Join(copyErr, fmt.Errorf("artifact exceeds or failed its size bound"))
	}
	if err := file.Sync(); err != nil {
		return "", err
	}
	if err := file.Close(); err != nil {
		return "", err
	}
	return hex.EncodeToString(hash.Sum(nil)), nil
}

func (s Service) client() *http.Client {
	if s.Client != nil {
		return s.Client
	}
	return &http.Client{Timeout: 10 * time.Minute, CheckRedirect: func(request *http.Request, via []*http.Request) error {
		if len(via) >= 5 || request.URL.Scheme != "https" || (request.URL.Host != "github.com" && !strings.HasSuffix(request.URL.Host, ".githubusercontent.com")) {
			return fmt.Errorf("refusing unexpected artifact redirect to %s", request.URL.Redacted())
		}
		return nil
	}}
}

func (s *Store) root() (string, error) {
	if s == nil || s.State == nil || !filepath.IsAbs(s.State.Root) || filepath.Clean(s.State.Root) != s.State.Root {
		return "", fmt.Errorf("update state root is invalid")
	}
	if err := s.State.Init(); err != nil {
		return "", err
	}
	root := filepath.Join(s.State.Root, "updates")
	if err := ensurePrivateDirectory(root); err != nil {
		return "", err
	}
	return root, nil
}

func (s *Store) ArtifactDirectory(id string) (string, error) {
	if !regexp.MustCompile(`^[0-9a-f]{32}$`).MatchString(id) {
		return "", fmt.Errorf("candidate ID is invalid")
	}
	root, err := s.root()
	if err != nil {
		return "", err
	}
	artifacts := filepath.Join(root, "artifacts")
	if err := ensurePrivateDirectory(artifacts); err != nil {
		return "", err
	}
	return filepath.Join(artifacts, id), nil
}

func (s *Store) Save(candidate Candidate) error {
	if err := candidate.Validate(); err != nil {
		return err
	}
	root, err := s.root()
	if err != nil {
		return err
	}
	return savePrivateJSON(filepath.Join(root, "candidate.json"), candidate)
}

func (s *Store) Load() (Candidate, error) {
	var candidate Candidate
	root, err := s.root()
	if err != nil {
		return candidate, err
	}
	if err := loadPrivateJSON(filepath.Join(root, "candidate.json"), &candidate); err != nil {
		return candidate, err
	}
	if err := candidate.Validate(); err != nil {
		return candidate, err
	}
	for _, artifact := range []CandidateArtifact{candidate.HostArtifact, candidate.GuestArtifact} {
		path := filepath.Join(root, artifact.RelativePath)
		if err := ensurePrivateDirectory(filepath.Dir(path)); err != nil {
			return candidate, err
		}
		digest, err := hashPrivateFile(path, maxArtifactBytes)
		if err != nil {
			return candidate, fmt.Errorf("candidate artifact %s failed quarantine verification: %w", filepath.Base(path), err)
		}
		if digest != artifact.SHA256 {
			return candidate, fmt.Errorf("candidate artifact %s digest changed in quarantine", filepath.Base(path))
		}
	}
	return candidate, nil
}

func releaseHasAsset(value release, name string) bool {
	for _, asset := range value.Assets {
		if asset.Name == name {
			return true
		}
	}
	return false
}

func artifactURL(version, name string) string {
	return "https://github.com/anomalyco/opencode/releases/download/v" + version + "/" + name
}

func parseV1(tag string) ([3]int, bool) {
	var result [3]int
	parts := strings.Split(strings.TrimPrefix(tag, "v"), ".")
	if len(parts) != 3 || parts[0] != "1" || tag != "v"+strings.Join(parts, ".") {
		return result, false
	}
	for index, part := range parts {
		value, err := strconv.Atoi(part)
		if err != nil || value < 0 || (len(part) > 1 && strings.HasPrefix(part, "0")) {
			return result, false
		}
		result[index] = value
	}
	return result, true
}

func executableSHA256(path string) (string, error) {
	archive, err := zip.OpenReader(path)
	if err != nil {
		return "", err
	}
	defer archive.Close()
	for _, entry := range archive.File {
		if filepath.Base(entry.Name) != "opencode" || entry.FileInfo().IsDir() {
			continue
		}
		if entry.Mode()&os.ModeSymlink != 0 || entry.UncompressedSize64 > 256<<20 {
			return "", fmt.Errorf("host archive contains an unsafe OpenCode executable")
		}
		reader, err := entry.Open()
		if err != nil {
			return "", err
		}
		hash := sha256.New()
		written, copyErr := io.Copy(hash, io.LimitReader(reader, 256<<20+1))
		closeErr := reader.Close()
		if copyErr != nil || closeErr != nil || written > 256<<20 {
			return "", errors.Join(copyErr, closeErr, fmt.Errorf("host executable exceeds its size bound"))
		}
		return hex.EncodeToString(hash.Sum(nil)), nil
	}
	return "", fmt.Errorf("host archive does not contain opencode")
}

func randomID() (string, error) {
	data := make([]byte, 16)
	if _, err := rand.Read(data); err != nil {
		return "", err
	}
	return hex.EncodeToString(data), nil
}

func relativeTo(root, path string) string {
	relative, _ := filepath.Rel(root, path)
	return relative
}

func ensurePrivateDirectory(path string) error {
	return securefs.EnsureOwnedDir(path)
}

func savePrivateJSON(path string, value any) error {
	data, err := json.MarshalIndent(value, "", "  ")
	if err != nil {
		return err
	}
	data = append(data, '\n')
	if len(data) > maxCandidateBytes {
		return fmt.Errorf("candidate exceeds its size bound")
	}
	return securefs.AtomicWriteOwned(path, data)
}

func loadPrivateJSON(path string, target any) error {
	data, err := securefs.ReadOwnedRegular(path, maxCandidateBytes)
	if err != nil {
		return err
	}
	if err := securefs.DecodeStrictJSON(data, target); err != nil {
		return err
	}
	return nil
}

func hashPrivateFile(path string, maximum int64) (string, error) {
	file, err := securefs.OpenOwnedRegularNoFollow(path, maximum)
	if err != nil {
		return "", err
	}
	defer file.Close()
	hash := sha256.New()
	if _, err := io.Copy(hash, io.LimitReader(file, maximum+1)); err != nil {
		return "", err
	}
	return hex.EncodeToString(hash.Sum(nil)), nil
}
