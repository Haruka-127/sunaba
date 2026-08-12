package cli

import (
	"bytes"
	"context"
	"encoding/json"
	"errors"
	"flag"
	"fmt"
	"net/http"
	"os"
	"path/filepath"
	"time"

	"sunaba/internal/dependency"
	"sunaba/internal/policy"
	"sunaba/internal/projectconfig"
	"sunaba/internal/webgateway"
)

func (a *app) config(ctx context.Context, args []string) error {
	if len(args) == 0 {
		return fmt.Errorf("%s", configUsage())
	}
	action := args[0]
	if action != "path" && action != "validate" && action != "diff" && action != "apply" && action != "show" {
		return fmt.Errorf("%s", configUsage())
	}
	fs := flag.NewFlagSet("config "+action, flag.ContinueOnError)
	fs.SetOutput(a.errors)
	dir := fs.String("dir", ".", "Project directory")
	effectiveOutput := fs.Bool("effective", false, "show the compiled effective policy")
	if err := fs.Parse(args[1:]); err != nil {
		return err
	}
	if fs.NArg() != 0 || (action != "show" && *effectiveOutput) {
		return fmt.Errorf("%s", configUsage())
	}
	effective, policyPath, projectState, err := a.loadEffectivePolicy(*dir)
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
		if *effectiveOutput {
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
		manifestDigest, err := dependency.ManifestSHA256()
		if err != nil {
			return err
		}
		pinned := dependency.MustPinned()
		effective.Dependency = policy.DependencyPolicy{
			ManifestSHA256: manifestDigest, OpenCode: dependency.OpenCodeVersion,
			AppleContainer: dependency.AppleContainerVersion, AgentImage: pinned.AgentImage.Tag,
		}
		blocklistPath, blocklistDigest := "", ""
		if config.Web.Enabled {
			blocklistPath, blocklistDigest, err = existingWebBlocklist(effective, projectState, time.Now())
			if err != nil {
				blocklistPath, blocklistDigest, _, err = a.fetchAndPersistWebBlocklist(ctx, projectState)
			}
			if err != nil {
				return err
			}
		}
		compiled, err := projectconfig.Compile(config, rules, effective, blocklistPath, blocklistDigest, time.Now())
		if err != nil {
			return err
		}
		if err := policy.Save(policyPath, compiled); err != nil {
			return err
		}
		fmt.Fprintf(a.output, "Applied host Project configuration for %s. Effective policy digest is now bound to the next Agent Session.\n", effective.ProjectID)
		return nil
	default:
		return fmt.Errorf("%s", configUsage())
	}
}

func configUsage() string {
	return "usage: sunaba config path|validate|diff|apply|show [--effective] [--dir <path>]"
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
