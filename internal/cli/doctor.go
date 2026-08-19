package cli

import (
	"context"
	"errors"
	"fmt"
	"os"
	"os/exec"
	"path/filepath"
	hostruntime "runtime"
	"strings"
	"time"

	"golang.org/x/sys/unix"

	"sunaba/internal/boundedexec"
	"sunaba/internal/opencode"
	"sunaba/internal/policy"
	"sunaba/internal/projectconfig"
	"sunaba/internal/state"
	"sunaba/internal/trustedui"
	"sunaba/internal/webgateway"
)

type doctorReport struct {
	output   interface{ Write([]byte) (int, error) }
	warnings int
	failures int
}

func (r *doctorReport) add(status, name, detail string) {
	switch status {
	case "WARN":
		r.warnings++
	case "FAIL":
		r.failures++
	}
	fmt.Fprintf(r.output, "[%s] %s: %s\n", status, name, trustedui.SanitizeTerminal(detail))
}

func (a *app) doctor(ctx context.Context, dir string) error {
	report := &doctorReport{output: a.output}
	if hostruntime.GOOS == "darwin" && hostruntime.GOARCH == "arm64" {
		report.add("PASS", "platform", "darwin/arm64 (Apple silicon)")
	} else {
		report.add("FAIL", "platform", hostruntime.GOOS+"/"+hostruntime.GOARCH+" is unsupported; darwin/arm64 is required")
	}

	executable, executableErr := os.Executable()
	if executableErr != nil {
		report.add("FAIL", "helper binaries", executableErr.Error())
	} else {
		for _, helper := range []string{"sunaba-guest-relay", "sunaba-git-hook"} {
			path := filepath.Join(filepath.Dir(executable), helper)
			if info, err := os.Lstat(path); err == nil && info.Mode().IsRegular() && info.Mode().Perm()&0111 != 0 {
				report.add("PASS", "helper "+helper, path)
			} else {
				report.add("FAIL", "helper "+helper, "missing or not executable next to sunaba")
			}
		}
	}

	lock, lockErr := a.activeVersionLock()
	versionStore, versionStoreErr := a.versionStore()
	if versionStoreErr != nil {
		report.add("FAIL", "global version configuration", versionStoreErr.Error())
	} else if config, err := versionStore.LoadConfig(); err != nil {
		report.add("FAIL", "global version configuration", err.Error())
	} else {
		report.add("PASS", "global version configuration", config.OpenCode.Strategy+" "+config.OpenCode.Value)
	}
	if lockErr != nil {
		report.add("FAIL", "version lock", lockErr.Error())
	} else {
		report.add("PASS", "version lock", fmt.Sprintf("OpenCode v%s, Apple Container %s, image %s", lock.Manifest.OpenCode.Version, lock.Manifest.AppleContainer.Version, lock.Manifest.AgentImage.Tag))
		managedDir := filepath.Join(a.store.Root, "tools", "opencode", "v"+lock.Manifest.OpenCode.Version)
		managedBinary := filepath.Join(managedDir, "opencode")
		if _, err := os.Lstat(managedBinary); err != nil {
			report.add("FAIL", "OpenCode host TUI", "managed locked binary is unavailable; run sunaba setup")
		} else if _, err := opencode.VerifyHostTUIExecutableVersion(ctx, managedDir, managedBinary, lock.Manifest.OpenCode.Host.ExecutableSHA256, lock.Manifest.OpenCode.Version); err != nil {
			report.add("FAIL", "OpenCode host TUI", err.Error())
		} else {
			report.add("PASS", "OpenCode host TUI", "exact v"+lock.Manifest.OpenCode.Version+" version and digest verified")
		}
		if exists, err := a.runtime.ImageExists(ctx, lock.Manifest.AgentImage.Tag); err != nil {
			report.add("FAIL", "active Agent image", err.Error())
		} else if !exists {
			report.add("FAIL", "active Agent image", lock.Manifest.AgentImage.Tag+" is not installed")
		} else {
			report.add("PASS", "active Agent image", lock.Manifest.AgentImage.Tag)
		}
	}

	containerPath, containerErr := exec.LookPath("container")
	if containerErr != nil {
		report.add("FAIL", "Apple Container", "container command is unavailable")
	} else {
		commandCtx, cancel := context.WithTimeout(ctx, 10*time.Second)
		result, err := boundedexec.Capture(exec.CommandContext(commandCtx, containerPath, "system", "version"), boundedexec.Limits{StdoutBytes: 64 << 10, StderrBytes: 16 << 10})
		cancel()
		if err != nil {
			report.add("FAIL", "Apple Container", "system is unavailable: "+err.Error())
		} else if lockErr == nil && !strings.Contains(string(result.Stdout), lock.Manifest.AppleContainer.Version) {
			report.add("FAIL", "Apple Container", "running version does not match locked "+lock.Manifest.AppleContainer.Version)
		} else {
			report.add("PASS", "Apple Container", "system is available at the locked version")
		}
	}

	checkDoctorDirectory(report, "state directory", a.store.Root)
	configStore, configStoreErr := a.projectConfigStore()
	if configStoreErr != nil {
		report.add("FAIL", "configuration directory", configStoreErr.Error())
	} else {
		checkDoctorDirectory(report, "configuration directory", configStore.Root)
	}

	root, rootErr := state.ResolveProjectPath(dir)
	if rootErr != nil {
		report.add("FAIL", "Project", rootErr.Error())
	} else {
		projectState := a.projectState(root)
		policyPath := filepath.Join(projectState, "policy.json")
		effective, migrated, err := policy.LoadReadOnly(policyPath, time.Now())
		if err != nil || effective.ProjectRoot != root || effective.ProjectID != state.ProjectID(root) {
			report.add("FAIL", "effective Project policy", fmt.Sprint(errors.Join(err, fmt.Errorf("identity must match selected Project"))))
		} else {
			detail := fmt.Sprintf("schema %d", effective.SchemaVersion)
			if migrated {
				detail += " (migration pending; doctor did not write it)"
			}
			report.add("PASS", "effective Project policy", detail)
			if configStoreErr == nil {
				config, rules, configErr := configStore.LoadReadOnly(effective.ProjectID)
				if configErr != nil {
					report.add("FAIL", "Project configuration", configErr.Error())
				} else if !projectconfig.Matches(config, rules, effective) {
					report.add("WARN", "Project configuration", "valid but differs from the applied policy")
				} else {
					report.add("PASS", "Project configuration", "valid and applied")
				}
			}
			checkDoctorBlocklist(report, projectState, effective, time.Now())
		}
		if client, err := openSupervisorClient(projectState); err == nil {
			if info, infoErr := client.info(ctx); infoErr != nil {
				report.add("FAIL", "runtime directory", infoErr.Error())
			} else {
				checkDoctorDirectory(report, "runtime directory", info.RuntimeRoot)
			}
			client.close()
		} else if errors.Is(err, errNoSupervisor) || errors.Is(err, errStaleSupervisor) {
			report.add("WARN", "runtime directory", "no active Supervisor; not applicable")
		} else {
			report.add("FAIL", "runtime directory", err.Error())
		}
	}

	fmt.Fprintf(a.output, "Doctor summary: %d failed, %d warning(s). No host setting was changed.\n", report.failures, report.warnings)
	if report.failures > 0 {
		return fmt.Errorf("doctor found %d failed check(s)", report.failures)
	}
	return nil
}

func checkDoctorDirectory(report *doctorReport, name, path string) {
	info, err := os.Lstat(path)
	var stat unix.Stat_t
	canonical, canonicalErr := filepath.EvalSymlinks(path)
	if err != nil || canonicalErr != nil || unix.Lstat(path, &stat) != nil || canonical != path || !info.IsDir() || info.Mode()&os.ModeSymlink != 0 || info.Mode().Perm() != 0700 || stat.Uid != uint32(os.Geteuid()) {
		report.add("FAIL", name, "must exist as a current-user-owned, non-symlink mode 0700 directory: "+path)
		return
	}
	if unix.Access(path, unix.W_OK) != nil {
		report.add("FAIL", name, "is not writable by the current user: "+path)
		return
	}
	report.add("PASS", name, "safe and writable: "+path)
}

func checkDoctorBlocklist(report *doctorReport, projectState string, effective policy.ProjectPolicy, now time.Time) {
	if !effective.Web.Enabled {
		report.add("PASS", "Web blocklist", "Web Gateway is disabled; blocklist is inactive")
		return
	}
	manifestData, err := readOwnedPrivateFile(filepath.Join(projectState, "web", "blocklist.json"), 64<<10)
	if err != nil {
		report.add("FAIL", "Web blocklist", err.Error())
		return
	}
	data, err := readOwnedPrivateFile(filepath.Join(projectState, "web", "blocklist.hosts"), 8<<20)
	manifest, parseErr := webgateway.ParseBlocklistManifest(manifestData)
	if err != nil || parseErr != nil || manifest.SHA256 != effective.Web.BlocklistSHA256 {
		report.add("FAIL", "Web blocklist", fmt.Sprint(errors.Join(err, parseErr, fmt.Errorf("digest must match applied policy"))))
		return
	}
	if _, err := webgateway.LoadBlocklist(manifest, data, now); err != nil {
		report.add("FAIL", "Web blocklist", err.Error()+"; run 'sunaba web refresh' while no VM exists")
		return
	}
	report.add("PASS", "Web blocklist", "valid until "+manifest.ExpiresAt.UTC().Format(time.RFC3339))
}
