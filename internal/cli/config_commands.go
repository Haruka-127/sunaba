package cli

import (
	"bytes"
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"net/http"
	"os"
	"os/exec"
	"path/filepath"
	"strings"
	"time"

	"sunaba/internal/configwizard"
	"sunaba/internal/dependency"
	"sunaba/internal/policy"
	"sunaba/internal/projectconfig"
	"sunaba/internal/webgateway"
)

func (a *app) config(ctx context.Context, action, dir string, effectiveOutput bool) error {
	effective, policyPath, projectState, err := a.loadEffectivePolicy(dir)
	if err != nil {
		return err
	}
	configStore, err := a.projectConfigStore()
	if err != nil {
		return err
	}
	paths, err := configStore.ProjectPaths(effective.ProjectID)
	if err != nil {
		return err
	}
	if action == "path" {
		fmt.Fprintf(a.output, "directory\t%s\nproject\t%s\nweb_origins\t%s\n", paths.Directory, paths.Project, paths.WebOrigins)
		return nil
	}
	config, rules, err := configStore.Load(effective.ProjectID)
	if err != nil {
		return fmt.Errorf("load host Project configuration: %w", err)
	}
	if config.ProjectRoot != effective.ProjectRoot {
		return fmt.Errorf("host Project configuration root does not match the registered Project")
	}
	switch action {
	case "edit":
		if err := a.ensureConfigApplyAllowed(ctx, effective, projectState); err != nil {
			return err
		}
		snapshotBefore, err := captureConfigMutationSnapshot(config, rules, effective)
		if err != nil {
			return err
		}
		result, err := configwizard.RunWithOptions(a.input, a.output, config, rules, configwizard.Options{SuggestedGitRemotes: detectProjectGitRemotes(ctx, effective.ProjectRoot)})
		if errors.Is(err, configwizard.ErrCanceled) {
			fmt.Fprintln(a.output, "Project configuration was not changed.")
			return nil
		}
		if err != nil {
			return err
		}
		if projectconfig.Matches(result.Config, result.Rules, effective) {
			fmt.Fprintln(a.output, "Project configuration has no changes.")
			return nil
		}
		lock, err := a.store.AcquireProjectLock(effective.ProjectRoot)
		if err != nil {
			return err
		}
		defer lock.Close()
		latestEffective, latestPolicyPath, latestProjectState, err := a.loadEffectivePolicy(dir)
		if err != nil {
			return err
		}
		latestConfig, latestRules, err := configStore.Load(latestEffective.ProjectID)
		if err != nil {
			return err
		}
		latestSnapshot, err := captureConfigMutationSnapshot(latestConfig, latestRules, latestEffective)
		if err != nil {
			return err
		}
		if latestPolicyPath != policyPath || latestProjectState != projectState || !snapshotBefore.equal(latestSnapshot) {
			return fmt.Errorf("Project configuration changed during the wizard; no wizard changes were saved")
		}
		compiled, err := a.applyProjectConfig(ctx, result.Config, result.Rules, latestEffective, latestPolicyPath, latestProjectState, true, &snapshotBefore)
		if err != nil {
			return err
		}
		fmt.Fprintf(a.output, "Saved and applied the interactive configuration to Project %s. The next Agent Session will use the new policy.\n", compiled.ProjectID)
		return nil
	case "validate":
		resolvedRules, _, err := projectconfig.ResolveWebRules(config, rules)
		if err != nil {
			return err
		}
		fmt.Fprintf(a.output, "Valid host Project configuration for %s with %d custom and %d resolved Web origin rule(s).\n", effective.ProjectID, len(rules), len(resolvedRules))
		return nil
	case "diff":
		if projectconfig.Matches(config, rules, effective) {
			fmt.Fprintln(a.output, "Host Project configuration matches the applied policy.")
			return nil
		}
		desiredJSON, err := projectconfig.Marshal(config)
		if err != nil {
			return err
		}
		applied, appliedRules := projectconfig.FromPolicy(effective)
		appliedJSON, err := projectconfig.Marshal(applied)
		if err != nil {
			return err
		}
		desiredEffectiveRules, desiredPresetDigest, err := projectconfig.ResolveWebRules(config, rules)
		if err != nil {
			return err
		}
		if !config.Web.Enabled {
			desiredEffectiveRules = nil
		}
		fmt.Fprintf(a.output, "Host Project configuration has unapplied changes.\n\n--- applied project.json\n+++ desired project.json\n%s\n--- applied custom web origins\n+++ desired custom web origins\n%s\n--- applied effective web origins\n+++ desired effective web origins\n%s\n- applied origin preset digest: %s\n+ desired origin preset digest: %s\n", renderConfigComparison(appliedJSON, desiredJSON), renderConfigComparison(projectconfig.RenderOrigins(appliedRules), projectconfig.RenderOrigins(rules)), renderConfigComparison(projectconfig.RenderOrigins(effective.Web.Rules), projectconfig.RenderOrigins(desiredEffectiveRules)), effective.Web.OriginPresetSHA256, desiredPresetDigest)
		return nil
	case "show":
		if effectiveOutput {
			encoded, err := policyJSON(effective)
			if err != nil {
				return err
			}
			_, err = a.output.Write(encoded)
			return err
		}
		encoded, err := projectconfig.Marshal(config)
		if err != nil {
			return err
		}
		_, err = a.output.Write(encoded)
		return err
	case "apply":
		if projectconfig.Matches(config, rules, effective) {
			fmt.Fprintln(a.output, "Host Project configuration is already applied.")
			return nil
		}
		snapshotBefore, err := captureConfigMutationSnapshot(config, rules, effective)
		if err != nil {
			return err
		}
		if err := a.ensureConfigApplyAllowed(ctx, effective, projectState); err != nil {
			return err
		}
		lock, err := a.store.AcquireProjectLock(effective.ProjectRoot)
		if err != nil {
			return err
		}
		defer lock.Close()
		compiled, err := a.applyProjectConfig(ctx, config, rules, effective, policyPath, projectState, false, &snapshotBefore)
		if err != nil {
			return err
		}
		fmt.Fprintf(a.output, "Applied host Project configuration for %s. Effective policy digest is now bound to the next Agent Session.\n", compiled.ProjectID)
		return nil
	default:
		return fmt.Errorf("unknown config action %q", action)
	}
}

type boundedCommandOutput struct {
	bytes.Buffer
	maximum int
}

func (b *boundedCommandOutput) Write(data []byte) (int, error) {
	if b.Len()+len(data) > b.maximum {
		return 0, fmt.Errorf("command output exceeds %d bytes", b.maximum)
	}
	return b.Buffer.Write(data)
}

func detectProjectGitRemotes(ctx context.Context, projectRoot string) []policy.GitRemotePolicy {
	detectContext, cancel := context.WithTimeout(ctx, 2*time.Second)
	defer cancel()
	command := exec.CommandContext(detectContext, "/usr/bin/git", "-C", projectRoot, "config", "--local", "--no-includes", "--get-regexp", `^remote\..*\.url$`)
	command.Env = []string{"GIT_CONFIG_NOSYSTEM=1", "GIT_CONFIG_GLOBAL=/dev/null", "GIT_TERMINAL_PROMPT=0", "LC_ALL=C", "PATH=/usr/bin:/bin"}
	output := &boundedCommandOutput{maximum: 64 << 10}
	command.Stdout = output
	if err := command.Run(); err != nil {
		return nil
	}
	return parseDetectedGitRemotes(output.Bytes())
}

func parseDetectedGitRemotes(data []byte) []policy.GitRemotePolicy {
	result := make([]policy.GitRemotePolicy, 0)
	seenNames := make(map[string]struct{})
	seenURLs := make(map[string]struct{})
	for _, line := range strings.Split(string(data), "\n") {
		fields := strings.Fields(line)
		if len(fields) != 2 || !strings.HasPrefix(fields[0], "remote.") || !strings.HasSuffix(fields[0], ".url") {
			continue
		}
		name := strings.TrimSuffix(strings.TrimPrefix(fields[0], "remote."), ".url")
		candidate := policy.GitRemotePolicy{Name: name, URL: fields[1]}
		if policy.ValidateGitRemote(candidate) != nil {
			continue
		}
		if _, exists := seenNames[candidate.Name]; exists {
			continue
		}
		if _, exists := seenURLs[candidate.URL]; exists {
			continue
		}
		seenNames[candidate.Name] = struct{}{}
		seenURLs[candidate.URL] = struct{}{}
		result = append(result, candidate)
		if len(result) == 16 {
			break
		}
	}
	return result
}

func (a *app) ensureConfigApplyAllowed(ctx context.Context, effective policy.ProjectPolicy, projectState string) error {
	if err := refuseActivePolicyChange(projectState); err != nil {
		return err
	}
	if a.runtime != nil {
		items, err := a.runtime.List(ctx)
		if err != nil {
			return err
		}
		for _, item := range items {
			if item.Labels["dev.sunaba.owner"] == "sunaba-supervisor" && item.Labels["dev.sunaba.project"] == effective.ProjectID {
				return fmt.Errorf("Project configuration cannot change while owned Project VM %s exists; export or recreate it first", item.Name)
			}
		}
	}
	if _, err := os.Lstat(filepath.Join(projectState, "pending", "change.json")); err == nil {
		return fmt.Errorf("Project configuration cannot change while a pending Change Set exists; apply or discard it first")
	} else if !errors.Is(err, os.ErrNotExist) {
		return err
	}
	return nil
}

type configMutationSnapshot struct {
	config       []byte
	rules        []byte
	policyDigest string
}

func captureConfigMutationSnapshot(config projectconfig.Config, rules []webgateway.OriginRule, effective policy.ProjectPolicy) (configMutationSnapshot, error) {
	configJSON, err := projectconfig.Marshal(config)
	if err != nil {
		return configMutationSnapshot{}, err
	}
	digest, err := effective.Digest()
	if err != nil {
		return configMutationSnapshot{}, err
	}
	return configMutationSnapshot{config: configJSON, rules: projectconfig.RenderOrigins(rules), policyDigest: digest}, nil
}

func (s configMutationSnapshot) equal(other configMutationSnapshot) bool {
	return s.policyDigest == other.policyDigest && bytes.Equal(s.config, other.config) && bytes.Equal(s.rules, other.rules)
}

func (a *app) verifyConfigMutationSnapshot(policyPath string, projectID string, expected configMutationSnapshot) error {
	latestEffective, _, err := policy.LoadAndMigrate(policyPath, time.Now())
	if err != nil {
		return err
	}
	configStore, err := a.projectConfigStore()
	if err != nil {
		return err
	}
	latestConfig, latestRules, err := configStore.Load(projectID)
	if err != nil {
		return err
	}
	latest, err := captureConfigMutationSnapshot(latestConfig, latestRules, latestEffective)
	if err != nil {
		return err
	}
	if !expected.equal(latest) {
		return fmt.Errorf("Project configuration changed while it was being applied; no configuration files were overwritten")
	}
	return nil
}

func (a *app) applyProjectConfig(ctx context.Context, config projectconfig.Config, rules []webgateway.OriginRule, effective policy.ProjectPolicy, policyPath, projectState string, saveDeclarative bool, expected *configMutationSnapshot) (policy.ProjectPolicy, error) {
	operationLock, err := a.store.AcquireOperationReadLock()
	if err != nil {
		return policy.ProjectPolicy{}, err
	}
	defer operationLock.Close()
	if err := a.ensureConfigApplyAllowed(ctx, effective, projectState); err != nil {
		return policy.ProjectPolicy{}, err
	}
	activeLock, err := a.activeVersionLock()
	if err != nil {
		return policy.ProjectPolicy{}, err
	}
	manifestDigest, err := dependency.ManifestDigest(activeLock.Manifest)
	if err != nil {
		return policy.ProjectPolicy{}, err
	}
	effective.Dependency = policy.DependencyPolicy{
		ManifestSHA256: manifestDigest, OpenCode: activeLock.Manifest.OpenCode.Version,
		AppleContainer: activeLock.Manifest.AppleContainer.Version, AgentImage: activeLock.Manifest.AgentImage.Tag,
	}
	blocklistPath, blocklistDigest := "", ""
	if config.Web.Enabled {
		blocklistPath, blocklistDigest, err = existingWebBlocklist(effective, projectState, time.Now())
		if err != nil {
			blocklistPath, blocklistDigest, _, err = a.fetchAndPersistWebBlocklist(ctx, projectState)
		}
		if err != nil {
			return policy.ProjectPolicy{}, err
		}
	}
	compiled, err := projectconfig.Compile(config, rules, effective, blocklistPath, blocklistDigest, time.Now())
	if err != nil {
		return policy.ProjectPolicy{}, err
	}
	if expected != nil {
		if err := a.verifyConfigMutationSnapshot(policyPath, effective.ProjectID, *expected); err != nil {
			return policy.ProjectPolicy{}, err
		}
	}
	if saveDeclarative {
		configStore, err := a.projectConfigStore()
		if err != nil {
			return policy.ProjectPolicy{}, err
		}
		if err := configStore.Save(effective.ProjectID, config, rules); err != nil {
			return policy.ProjectPolicy{}, err
		}
	}
	if err := policy.Save(policyPath, compiled); err != nil {
		return policy.ProjectPolicy{}, err
	}
	return compiled, nil
}

func policyJSON(value policy.ProjectPolicy) ([]byte, error) {
	encoded, err := json.MarshalIndent(value, "", "  ")
	if err != nil {
		return nil, err
	}
	return append(encoded, '\n'), nil
}

func renderConfigComparison(applied, desired []byte) string {
	if bytes.Equal(applied, desired) {
		return "(no change)\n"
	}
	return "- " + string(bytes.ReplaceAll(bytes.TrimSpace(applied), []byte("\n"), []byte("\n- "))) + "\n+ " + string(bytes.ReplaceAll(bytes.TrimSpace(desired), []byte("\n"), []byte("\n+ "))) + "\n"
}

func existingWebBlocklist(effective policy.ProjectPolicy, projectState string, now time.Time) (string, string, error) {
	manifestPath := filepath.Join(projectState, "web", "blocklist.json")
	dataPath := filepath.Join(projectState, "web", "blocklist.hosts")
	if effective.Web.BlocklistManifest != manifestPath || effective.Web.BlocklistSHA256 == "" {
		return "", "", fmt.Errorf("no reusable Web blocklist is bound to the Project")
	}
	manifestData, err := readOwnedPrivateFile(manifestPath, 1<<20)
	if err != nil {
		return "", "", err
	}
	blocklistData, err := readOwnedPrivateFile(dataPath, 8<<20)
	if err != nil {
		return "", "", err
	}
	manifest, err := webgateway.ParseBlocklistManifest(manifestData)
	if err != nil || manifest.SHA256 != effective.Web.BlocklistSHA256 {
		return "", "", fmt.Errorf("Web blocklist does not match the effective policy")
	}
	if _, err := webgateway.LoadBlocklist(manifest, blocklistData, now); err != nil {
		return "", "", err
	}
	return manifestPath, manifest.SHA256, nil
}

func (a *app) fetchAndPersistWebBlocklist(ctx context.Context, projectState string) (string, string, time.Time, error) {
	fetchContext, cancel := context.WithTimeout(ctx, 45*time.Second)
	defer cancel()
	snapshot, err := webgateway.FetchBlocklist(fetchContext, &http.Client{Timeout: 30 * time.Second}, webgateway.DefaultBlocklistSourceURL, time.Now(), 7*24*time.Hour)
	if err != nil {
		return "", "", time.Time{}, err
	}
	manifest, err := snapshot.Manifest.Marshal()
	if err != nil {
		return "", "", time.Time{}, err
	}
	webRoot := filepath.Join(projectState, "web")
	if err := os.MkdirAll(webRoot, 0700); err != nil {
		return "", "", time.Time{}, err
	}
	manifestPath := filepath.Join(webRoot, "blocklist.json")
	if err := writePrivateBytes(manifestPath, append(manifest, '\n')); err != nil {
		return "", "", time.Time{}, err
	}
	if err := writePrivateBytes(filepath.Join(webRoot, "blocklist.hosts"), snapshot.Data); err != nil {
		return "", "", time.Time{}, err
	}
	return manifestPath, snapshot.Manifest.SHA256, snapshot.Manifest.ExpiresAt, nil
}
