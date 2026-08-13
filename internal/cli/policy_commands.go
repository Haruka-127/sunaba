package cli

import (
	"context"
	"errors"
	"fmt"
	"os"
	"path/filepath"
	"sort"
	"strings"
	"time"

	"sunaba/internal/modelcatalog"
	"sunaba/internal/policy"
	"sunaba/internal/projectconfig"
	"sunaba/internal/webgateway"
)

func (a *app) modelPolicy(_ context.Context, action, auth, dir string, models []string) error {
	projectPolicy, path, projectState, err := a.loadPolicy(dir)
	if err != nil {
		return err
	}
	if action == "list" {
		available, err := modelcatalog.Available(projectPolicy.Model.AuthMode)
		if err != nil {
			return err
		}
		allowed := make(map[string]struct{}, len(projectPolicy.Model.AllowedModels))
		for _, id := range projectPolicy.Model.AllowedModels {
			allowed[id] = struct{}{}
		}
		for _, definition := range available {
			_, selected := allowed[definition.ID]
			fmt.Fprintf(a.output, "%s\tallowed=%t\tcontext=%d\tinput=%d\toutput=%d\n", definition.ID, selected, definition.Limit.Context, definition.Limit.Input, definition.Limit.Output)
		}
		return nil
	}
	if err := refuseActivePolicyChange(projectState); err != nil {
		return err
	}
	switch action {
	case "auth":
		mode := modelcatalog.AuthAPIKey
		if auth == "oauth" {
			mode = modelcatalog.AuthOAuth
		}
		defaultModels, err := modelcatalog.DefaultModels(mode)
		if err != nil {
			return err
		}
		projectPolicy.Model.AuthMode = mode
		if _, err := modelcatalog.Resolve(mode, projectPolicy.Model.AllowedModels); err != nil {
			projectPolicy.Model.AllowedModels = defaultModels
		}
	case "set":
		if len(models) == 0 {
			return fmt.Errorf("model set requires at least one --model")
		}
		if _, err := modelcatalog.Resolve(projectPolicy.Model.AuthMode, models); err != nil {
			return err
		}
		projectPolicy.Model.AllowedModels = append([]string(nil), models...)
	default:
		return fmt.Errorf("unknown model policy action %q", action)
	}
	projectPolicy.UpdatedAt = time.Now().UTC()
	if err := a.savePolicyAndConfig(path, projectPolicy); err != nil {
		return err
	}
	fmt.Fprintf(a.output, "Configured Project Model Gateway authentication=%s with models=%s.\n", projectPolicy.Model.AuthMode, strings.Join(projectPolicy.Model.AllowedModels, ","))
	return nil
}

func (a *app) gitPolicy(_ context.Context, action, dir, name, remoteURL string) error {
	projectPolicy, path, projectState, err := a.loadPolicy(dir)
	if err != nil {
		return err
	}
	if action == "remote-list" {
		if len(projectPolicy.Git.Remotes) == 0 {
			fmt.Fprintln(a.output, "No Git Gateway remotes are configured.")
			return nil
		}
		for _, configured := range sortedGitRemotes(projectPolicy.Git.Remotes) {
			fmt.Fprintf(a.output, "%s\t%s\n", configured.Name, configured.URL)
		}
		return nil
	}
	if err := refuseActivePolicyChange(projectState); err != nil {
		return err
	}
	switch action {
	case "remote-add":
		configured := policy.GitRemotePolicy{Name: name, URL: remoteURL}
		if err := policy.ValidateGitRemote(configured); err != nil {
			return err
		}
		for _, existing := range projectPolicy.Git.Remotes {
			if existing.Name == configured.Name {
				return fmt.Errorf("Git remote name %q is already configured; remove it before changing its URL", configured.Name)
			}
			if existing.URL == configured.URL {
				return fmt.Errorf("Git remote URL is already configured as %q", existing.Name)
			}
		}
		projectPolicy.Git.Remotes = append(projectPolicy.Git.Remotes, configured)
	case "remote-remove":
		if name == "" || remoteURL != "" {
			return fmt.Errorf("git remote remove requires only --name")
		}
		removed := false
		kept := make([]policy.GitRemotePolicy, 0, len(projectPolicy.Git.Remotes))
		for _, configured := range projectPolicy.Git.Remotes {
			if configured.Name == name {
				removed = true
				continue
			}
			kept = append(kept, configured)
		}
		if !removed {
			return fmt.Errorf("Git remote %q is not configured", name)
		}
		projectPolicy.Git.Remotes = kept
	case "disable":
		projectPolicy.Git.Remotes = nil
	default:
		return fmt.Errorf("unknown Git policy action %q", action)
	}
	projectPolicy.Git.Remotes = sortedGitRemotes(projectPolicy.Git.Remotes)
	projectPolicy.UpdatedAt = time.Now().UTC()
	if err := a.savePolicyAndConfig(path, projectPolicy); err != nil {
		return err
	}
	if len(projectPolicy.Git.Remotes) == 0 {
		fmt.Fprintln(a.output, "Disabled the Project Git Gateway. Existing host quarantine data was retained and is inactive.")
	} else {
		fmt.Fprintf(a.output, "Configured %d fixed Git Gateway remote(s). Host credential lookup occurs only when an Agent Session starts.\n", len(projectPolicy.Git.Remotes))
	}
	return nil
}

func sortedGitRemotes(remotes []policy.GitRemotePolicy) []policy.GitRemotePolicy {
	sorted := append([]policy.GitRemotePolicy(nil), remotes...)
	sort.Slice(sorted, func(i, j int) bool { return sorted[i].Name < sorted[j].Name })
	return sorted
}

func (a *app) webPolicy(ctx context.Context, action, dir string, includeSubdomains, defaultOrigins bool, origins []string) error {
	projectPolicy, path, projectState, err := a.loadPolicy(dir)
	if err != nil {
		return err
	}
	if err := refuseActivePolicyChange(projectState); err != nil {
		return err
	}
	switch action {
	case "enable":
		rules := make([]webgateway.OriginRule, 0, len(origins))
		for _, origin := range origins {
			rule, err := originRule(origin, includeSubdomains)
			if err != nil {
				return err
			}
			rules = append(rules, rule)
		}
		projectPolicy.Web.OriginPresets = nil
		if defaultOrigins {
			projectPolicy.Web.OriginPresets = []string{webgateway.CommonDevelopmentOriginPreset}
		}
		projectPolicy.Web.CustomRules = rules
		if len(projectPolicy.Web.OriginPresets) == 0 && len(rules) == 0 {
			return fmt.Errorf("web enable requires the default preset or at least one --origin")
		}
		return a.refreshWebPolicy(ctx, projectPolicy, path, projectState)
	case "refresh":
		if !projectPolicy.Web.Enabled {
			return fmt.Errorf("Web Gateway is disabled; use web enable with explicit origins")
		}
		return a.refreshWebPolicy(ctx, projectPolicy, path, projectState)
	case "disable":
		projectPolicy.Web.Enabled = false
		projectPolicy.Web.Rules = nil
		projectPolicy.Web.BlocklistManifest = ""
		projectPolicy.Web.BlocklistSHA256 = ""
		projectPolicy.UpdatedAt = time.Now().UTC()
		if err := a.savePolicyAndConfig(path, projectPolicy); err != nil {
			return err
		}
		fmt.Fprintln(a.output, "Disabled the Project Web Gateway. The pinned blocklist snapshot was retained and is inactive.")
		return nil
	default:
		return fmt.Errorf("unknown web action %q", action)
	}
}

func originRule(raw string, includeSubdomains bool) (webgateway.OriginRule, error) {
	return projectconfig.ParseOrigin(raw, includeSubdomains)
}

func (a *app) refreshWebPolicy(ctx context.Context, projectPolicy policy.ProjectPolicy, policyPath, projectState string) error {
	rules, presetDigest, err := webgateway.ResolveOriginRules(projectPolicy.Web.OriginPresets, projectPolicy.Web.CustomRules)
	if err != nil {
		return fmt.Errorf("resolve Web origin policy: %w", err)
	}
	if len(rules) == 0 {
		return fmt.Errorf("resolve Web origin policy: no origins are selected")
	}
	manifestPath, digest, expiresAt, err := a.fetchAndPersistWebBlocklist(ctx, projectState)
	if err != nil {
		return err
	}
	projectPolicy.Web.Enabled = true
	projectPolicy.Web.Rules = rules
	projectPolicy.Web.OriginPresetSHA256 = presetDigest
	projectPolicy.Web.BlocklistManifest = manifestPath
	projectPolicy.Web.BlocklistSHA256 = digest
	projectPolicy.UpdatedAt = time.Now().UTC()
	if err := a.savePolicyAndConfig(policyPath, projectPolicy); err != nil {
		return err
	}
	fmt.Fprintf(a.output, "Enabled Web Gateway with %d effective origin rules (%d custom) and pinned blocklist %s (expires %s).\n", len(rules), len(projectPolicy.Web.CustomRules), digest, expiresAt.Format(time.RFC3339))
	return nil
}

func writePrivateBytes(path string, data []byte) error {
	if len(data) == 0 || !filepath.IsAbs(path) || filepath.Clean(path) != path {
		return fmt.Errorf("private artifact path or content is invalid")
	}
	parent := filepath.Dir(path)
	info, err := os.Lstat(parent)
	if err != nil || !info.IsDir() || info.Mode()&os.ModeSymlink != 0 || info.Mode().Perm() != 0700 {
		return fmt.Errorf("private artifact directory is unsafe")
	}
	temporary, err := os.CreateTemp(parent, ".sunaba-web-*")
	if err != nil {
		return err
	}
	temporaryPath := temporary.Name()
	defer os.Remove(temporaryPath)
	if err := temporary.Chmod(0600); err != nil {
		temporary.Close()
		return err
	}
	if _, err := temporary.Write(data); err != nil {
		temporary.Close()
		return err
	}
	if err := temporary.Sync(); err != nil {
		temporary.Close()
		return err
	}
	if err := temporary.Close(); err != nil {
		return err
	}
	if current, err := os.Lstat(path); err == nil && (!current.Mode().IsRegular() || current.Mode()&os.ModeSymlink != 0 || current.Mode().Perm() != 0600) {
		return fmt.Errorf("existing private artifact is unsafe")
	} else if err != nil && !errors.Is(err, os.ErrNotExist) {
		return err
	}
	return os.Rename(temporaryPath, path)
}

func refuseActivePolicyChange(projectState string) error {
	path := filepath.Join(projectState, approvalControlLocator)
	if _, err := os.Lstat(path); err == nil {
		return fmt.Errorf("Project policy cannot change while a persistent or foreground Agent Session exists; export or recreate it first")
	} else if !errors.Is(err, os.ErrNotExist) {
		return err
	}
	return nil
}
