package cli

import (
	"context"
	"errors"
	"flag"
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

type stringFlags []string

func (a *app) modelPolicy(_ context.Context, args []string) error {
	if len(args) == 0 {
		return fmt.Errorf("%s", modelPolicyUsage())
	}
	action := args[0]
	if action != "auth" && action != "set" && action != "list" {
		return fmt.Errorf("%s", modelPolicyUsage())
	}
	if action == "auth" && (len(args) < 2 || (args[1] != "api-key" && args[1] != "oauth")) {
		return fmt.Errorf("%s", modelPolicyUsage())
	}
	flagArguments := args[1:]
	if action == "auth" {
		flagArguments = args[2:]
	}
	fs := flag.NewFlagSet("model "+action, flag.ContinueOnError)
	fs.SetOutput(a.errors)
	dir := fs.String("dir", ".", "Project directory")
	var models stringFlags
	fs.Var(&models, "model", "allowed model ID; repeat for multiple models")
	if err := fs.Parse(flagArguments); err != nil {
		return err
	}
	if fs.NArg() != 0 {
		return fmt.Errorf("%s", modelPolicyUsage())
	}
	projectPolicy, path, projectState, err := a.loadPolicy(*dir)
	if err != nil {
		return err
	}
	if action == "list" {
		if len(models) != 0 {
			return fmt.Errorf("model list does not accept --model")
		}
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
		if len(models) != 0 {
			return fmt.Errorf("model auth does not accept --model")
		}
		mode := modelcatalog.AuthAPIKey
		if args[1] == "oauth" {
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
		return fmt.Errorf("%s", modelPolicyUsage())
	}
	projectPolicy.UpdatedAt = time.Now().UTC()
	if err := a.savePolicyAndConfig(path, projectPolicy); err != nil {
		return err
	}
	fmt.Fprintf(a.output, "Configured Project Model Gateway authentication=%s with models=%s.\n", projectPolicy.Model.AuthMode, strings.Join(projectPolicy.Model.AllowedModels, ","))
	return nil
}

func modelPolicyUsage() string {
	return "usage: sunaba model auth api-key|oauth [--dir <path>] | model set --model <id>... [--dir <path>] | model list [--dir <path>]"
}

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
		if err := a.savePolicyAndConfig(path, projectPolicy); err != nil {
			return err
		}
		fmt.Fprintln(a.output, "Disabled the Project Web Gateway. The pinned blocklist snapshot was retained and is inactive.")
		return nil
	default:
		return fmt.Errorf("unknown web action %q", args[0])
	}
}

func originRule(raw string, includeSubdomains bool) (webgateway.OriginRule, error) {
	return projectconfig.ParseOrigin(raw, includeSubdomains)
}

func (a *app) refreshWebPolicy(ctx context.Context, projectPolicy policy.ProjectPolicy, policyPath, projectState string, rules []webgateway.OriginRule) error {
	manifestPath, digest, expiresAt, err := a.fetchAndPersistWebBlocklist(ctx, projectState)
	if err != nil {
		return err
	}
	projectPolicy.Web.Enabled = true
	projectPolicy.Web.Rules = rules
	projectPolicy.Web.BlocklistManifest = manifestPath
	projectPolicy.Web.BlocklistSHA256 = digest
	projectPolicy.UpdatedAt = time.Now().UTC()
	if err := a.savePolicyAndConfig(policyPath, projectPolicy); err != nil {
		return err
	}
	fmt.Fprintf(a.output, "Enabled Web Gateway with %d origin rules and pinned blocklist %s (expires %s).\n", len(rules), digest, expiresAt.Format(time.RFC3339))
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
