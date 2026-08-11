package cli

import (
	"context"
	"errors"
	"flag"
	"fmt"
	"net/http"
	"net/url"
	"os"
	"path/filepath"
	"sort"
	"strings"
	"time"

	"sunaba/internal/policy"
	"sunaba/internal/webgateway"
)

type stringFlags []string

func (f *stringFlags) String() string { return strings.Join(*f, ",") }

func (f *stringFlags) Set(value string) error {
	*f = append(*f, value)
	return nil
}

func (a *app) gitPolicy(_ context.Context, args []string) error {
	if len(args) == 0 {
		return fmt.Errorf("%s", gitPolicyUsage())
	}
	action := args[0]
	flagArguments := args[1:]
	if action == "remote" {
		if len(args) < 2 {
			return fmt.Errorf("%s", gitPolicyUsage())
		}
		action = "remote-" + args[1]
		flagArguments = args[2:]
	}
	fs := flag.NewFlagSet("git "+action, flag.ContinueOnError)
	fs.SetOutput(a.errors)
	dir := fs.String("dir", ".", "Project directory")
	name := fs.String("name", "", "fixed remote name")
	remoteURL := fs.String("url", "", "credential-free fixed HTTPS .git URL")
	if err := fs.Parse(flagArguments); err != nil {
		return err
	}
	if fs.NArg() != 0 {
		return fmt.Errorf("unexpected Git policy arguments")
	}
	projectPolicy, path, projectState, err := a.loadPolicy(*dir)
	if err != nil {
		return err
	}
	if action == "remote-list" {
		if *name != "" || *remoteURL != "" {
			return fmt.Errorf("git remote list does not accept remote changes")
		}
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
		configured := policy.GitRemotePolicy{Name: *name, URL: *remoteURL}
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
		if *name == "" || *remoteURL != "" {
			return fmt.Errorf("git remote remove requires only --name")
		}
		removed := false
		kept := make([]policy.GitRemotePolicy, 0, len(projectPolicy.Git.Remotes))
		for _, configured := range projectPolicy.Git.Remotes {
			if configured.Name == *name {
				removed = true
				continue
			}
			kept = append(kept, configured)
		}
		if !removed {
			return fmt.Errorf("Git remote %q is not configured", *name)
		}
		projectPolicy.Git.Remotes = kept
	case "disable":
		if *name != "" || *remoteURL != "" {
			return fmt.Errorf("git disable does not accept remote options")
		}
		projectPolicy.Git.Remotes = nil
	default:
		return fmt.Errorf("%s", gitPolicyUsage())
	}
	projectPolicy.Git.Remotes = sortedGitRemotes(projectPolicy.Git.Remotes)
	projectPolicy.UpdatedAt = time.Now().UTC()
	if err := policy.Save(path, projectPolicy); err != nil {
		return err
	}
	if len(projectPolicy.Git.Remotes) == 0 {
		fmt.Fprintln(a.output, "Disabled the Project Git Gateway. Existing host quarantine data was retained and is inactive.")
	} else {
		fmt.Fprintf(a.output, "Configured %d fixed Git Gateway remote(s). Host credential lookup occurs only when an Agent Session starts.\n", len(projectPolicy.Git.Remotes))
	}
	return nil
}

func gitPolicyUsage() string {
	return "usage: sunaba git remote add --name <name> --url <https-url> [--dir <path>] | remote remove --name <name> | remote list | disable"
}

func sortedGitRemotes(remotes []policy.GitRemotePolicy) []policy.GitRemotePolicy {
	sorted := append([]policy.GitRemotePolicy(nil), remotes...)
	sort.Slice(sorted, func(i, j int) bool { return sorted[i].Name < sorted[j].Name })
	return sorted
}

func (a *app) webPolicy(ctx context.Context, args []string) error {
	if len(args) == 0 {
		return fmt.Errorf("usage: sunaba web enable --origin <http(s)://host>... [--dir <path>] | refresh|disable [--dir <path>]")
	}
	fs := flag.NewFlagSet("web "+args[0], flag.ContinueOnError)
	fs.SetOutput(a.errors)
	dir := fs.String("dir", ".", "Project directory")
	includeSubdomains := fs.Bool("include-subdomains", false, "apply every supplied origin rule to subdomains")
	var origins stringFlags
	fs.Var(&origins, "origin", "allowed origin; repeat for multiple origins")
	if err := fs.Parse(args[1:]); err != nil {
		return err
	}
	if fs.NArg() != 0 {
		return fmt.Errorf("unexpected Web policy arguments")
	}
	projectPolicy, path, projectState, err := a.loadPolicy(*dir)
	if err != nil {
		return err
	}
	if err := refuseActivePolicyChange(projectState); err != nil {
		return err
	}
	switch args[0] {
	case "enable":
		if len(origins) == 0 {
			return fmt.Errorf("web enable requires at least one --origin")
		}
		rules := make([]webgateway.OriginRule, 0, len(origins))
		for _, origin := range origins {
			rule, err := originRule(origin, *includeSubdomains)
			if err != nil {
				return err
			}
			rules = append(rules, rule)
		}
		return a.refreshWebPolicy(ctx, projectPolicy, path, projectState, rules)
	case "refresh":
		if len(origins) != 0 || *includeSubdomains {
			return fmt.Errorf("web refresh does not accept origin changes")
		}
		if !projectPolicy.Web.Enabled {
			return fmt.Errorf("Web Gateway is disabled; use web enable with explicit origins")
		}
		return a.refreshWebPolicy(ctx, projectPolicy, path, projectState, projectPolicy.Web.Rules)
	case "disable":
		if len(origins) != 0 || *includeSubdomains {
			return fmt.Errorf("web disable does not accept origin options")
		}
		projectPolicy.Web.Enabled = false
		projectPolicy.Web.Rules = nil
		projectPolicy.Web.BlocklistManifest = ""
		projectPolicy.Web.BlocklistSHA256 = ""
		projectPolicy.UpdatedAt = time.Now().UTC()
		if err := policy.Save(path, projectPolicy); err != nil {
			return err
		}
		fmt.Fprintln(a.output, "Disabled the Project Web Gateway. The pinned blocklist snapshot was retained and is inactive.")
		return nil
	default:
		return fmt.Errorf("unknown web action %q", args[0])
	}
}

func originRule(raw string, includeSubdomains bool) (webgateway.OriginRule, error) {
	parsed, err := url.Parse(raw)
	if err != nil || parsed.User != nil || parsed.Host == "" || parsed.RawQuery != "" || parsed.Fragment != "" || (parsed.Path != "" && parsed.Path != "/") || strings.ContainsAny(raw, "\x00\r\n") {
		return webgateway.OriginRule{}, fmt.Errorf("Web origin must contain only scheme and hostname")
	}
	rule := webgateway.OriginRule{Host: parsed.Hostname(), Category: "user", IncludeSubdomains: includeSubdomains}
	switch parsed.Scheme {
	case "http":
		if parsed.Port() != "" && parsed.Port() != "80" {
			return webgateway.OriginRule{}, fmt.Errorf("HTTP Web origins must use port 80")
		}
		rule.Port, rule.AllowHTTP = 80, true
	case "https":
		if parsed.Port() != "" && parsed.Port() != "443" {
			return webgateway.OriginRule{}, fmt.Errorf("HTTPS Web origins must use port 443")
		}
		rule.Port, rule.AllowConnect = 443, true
	default:
		return webgateway.OriginRule{}, fmt.Errorf("Web origin scheme must be http or https")
	}
	if _, err := (webgateway.Policy{Rules: []webgateway.OriginRule{rule}}).Digest(); err != nil {
		return webgateway.OriginRule{}, fmt.Errorf("invalid Web origin: %w", err)
	}
	return rule, nil
}

func (a *app) refreshWebPolicy(ctx context.Context, projectPolicy policy.ProjectPolicy, policyPath, projectState string, rules []webgateway.OriginRule) error {
	fetchContext, cancel := context.WithTimeout(ctx, 45*time.Second)
	defer cancel()
	snapshot, err := webgateway.FetchBlocklist(fetchContext, &http.Client{Timeout: 30 * time.Second}, webgateway.DefaultBlocklistSourceURL, time.Now(), 7*24*time.Hour)
	if err != nil {
		return err
	}
	manifest, err := snapshot.Manifest.Marshal()
	if err != nil {
		return err
	}
	webRoot := filepath.Join(projectState, "web")
	if err := os.MkdirAll(webRoot, 0700); err != nil {
		return err
	}
	manifestPath := filepath.Join(webRoot, "blocklist.json")
	if err := writePrivateBytes(manifestPath, append(manifest, '\n')); err != nil {
		return err
	}
	if err := writePrivateBytes(filepath.Join(webRoot, "blocklist.hosts"), snapshot.Data); err != nil {
		return err
	}
	projectPolicy.Web.Enabled = true
	projectPolicy.Web.Rules = rules
	projectPolicy.Web.BlocklistManifest = manifestPath
	projectPolicy.Web.BlocklistSHA256 = snapshot.Manifest.SHA256
	projectPolicy.UpdatedAt = time.Now().UTC()
	if err := policy.Save(policyPath, projectPolicy); err != nil {
		return err
	}
	fmt.Fprintf(a.output, "Enabled Web Gateway with %d origin rules and pinned blocklist %s (expires %s).\n", len(rules), snapshot.Manifest.SHA256, snapshot.Manifest.ExpiresAt.Format(time.RFC3339))
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
