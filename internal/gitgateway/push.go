package gitgateway

import (
	"context"
	"errors"
	"fmt"
	"os"
	"os/exec"
	"path/filepath"
	"strings"

	"golang.org/x/sys/unix"

	"sunaba/internal/audit"
)

type PushExecutor struct {
	Resolver            RepositoryResolver
	Approvals           *PushApprovalManager
	AuthorizationHeader string
	TLSCAInfoPath       string
	Audit               *audit.Recorder
	VMID                string
	SessionID           string
}

func (e PushExecutor) Sync(ctx context.Context) error {
	if e.Audit == nil || !gitIdentityPattern.MatchString(e.Resolver.ProjectID) || !gitIdentityPattern.MatchString(e.VMID) || !gitIdentityPattern.MatchString(e.SessionID) {
		return fmt.Errorf("host Git sync configuration is invalid")
	}
	if err := e.validateTransport(); err != nil {
		return err
	}
	lock, err := lockRepository(e.Resolver.RepositoryPath)
	if err != nil {
		return err
	}
	defer lock.Close()
	binding := PushBinding{ProjectID: e.Resolver.ProjectID, Repository: e.Resolver.Repository, RemoteName: e.Resolver.RemoteName, RemoteURL: e.Resolver.RemoteURL}
	if err := e.runGit(ctx, []string{"fetch", "--atomic", "--prune", "--no-tags", e.Resolver.RemoteURL, "+refs/heads/*:refs/heads/*", "+refs/tags/*:refs/tags/*"}); err != nil {
		return errors.Join(fmt.Errorf("host Git upstream sync failed"), e.recordSync("rejected", binding, "upstream_sync_failed"))
	}
	return e.recordSync("success", binding, "")
}

func (e PushExecutor) Execute(ctx context.Context, grant *PushGrant, proposed []ProposedRefUpdate) error {
	if e.Approvals == nil || e.Audit == nil || e.AuthorizationHeader == "" || len(e.AuthorizationHeader) > 4096 || containsControl(e.AuthorizationHeader) || !gitIdentityPattern.MatchString(e.VMID) || !gitIdentityPattern.MatchString(e.SessionID) {
		return fmt.Errorf("host Git push executor configuration is invalid")
	}
	if !strings.HasPrefix(e.AuthorizationHeader, "Basic ") && !strings.HasPrefix(e.AuthorizationHeader, "Bearer ") {
		return fmt.Errorf("host Git HTTPS authorization scheme is not allowed")
	}
	if e.TLSCAInfoPath != "" {
		if err := validateHostCredentialFile(e.TLSCAInfoPath); err != nil {
			return err
		}
	}
	lock, err := lockRepository(e.Resolver.RepositoryPath)
	if err != nil {
		return err
	}
	defer lock.Close()
	auditBinding := PushBinding{ProjectID: e.Resolver.ProjectID, Repository: e.Resolver.Repository, RemoteName: e.Resolver.RemoteName, RemoteURL: e.Resolver.RemoteURL}
	binding, err := e.Resolver.Resolve(ctx, proposed)
	if err != nil {
		return errors.Join(err, e.record("rejected", auditBinding, "repository_revalidation_failed"))
	}
	if err := e.Approvals.Consume(grant, binding); err != nil {
		return errors.Join(err, e.record("rejected", binding, "approval_invalid"))
	}
	if err := e.record("started", binding, ""); err != nil {
		return err
	}
	if err := e.push(ctx, binding); err != nil {
		return errors.Join(err, e.record("rejected", binding, "upstream_rejected"))
	}
	return e.record("success", binding, "")
}

func (e PushExecutor) push(ctx context.Context, binding PushBinding) error {
	if err := e.validateTransport(); err != nil {
		return err
	}
	args := []string{"push", "--atomic", "--porcelain"}
	for _, update := range binding.Updates {
		expected := update.Old
		if strings.Trim(expected, "0") == "" {
			expected = ""
		}
		args = append(args, "--force-with-lease="+update.Ref+":"+expected)
	}
	args = append(args, binding.RemoteURL)
	for _, update := range binding.Updates {
		source := update.New
		if update.Delete {
			source = ""
		}
		args = append(args, source+":"+update.Ref)
	}
	return e.runGit(ctx, args)
}

func (e PushExecutor) validateTransport() error {
	if !strings.HasPrefix(e.Resolver.RemoteURL, "https://") || e.AuthorizationHeader == "" || len(e.AuthorizationHeader) > 4096 || containsControl(e.AuthorizationHeader) || (!strings.HasPrefix(e.AuthorizationHeader, "Basic ") && !strings.HasPrefix(e.AuthorizationHeader, "Bearer ")) {
		return fmt.Errorf("host Git HTTPS transport configuration is invalid")
	}
	if e.TLSCAInfoPath != "" {
		return validateHostCredentialFile(e.TLSCAInfoPath)
	}
	return nil
}

func (e PushExecutor) runGit(ctx context.Context, operationArgs []string) error {
	gitPath := e.Resolver.GitPath
	if gitPath == "" {
		var err error
		gitPath, err = exec.LookPath("git")
		if err != nil {
			return fmt.Errorf("locate host Git: %w", err)
		}
	}
	if !filepath.IsAbs(gitPath) {
		return fmt.Errorf("host Git path must be absolute")
	}
	args := append([]string{"--git-dir=" + e.Resolver.RepositoryPath}, operationArgs...)
	command := exec.CommandContext(ctx, gitPath, args...)
	command.Dir = e.Resolver.RepositoryPath
	configCount := "1"
	if e.TLSCAInfoPath != "" {
		configCount = "2"
	}
	command.Env = []string{
		"GIT_CONFIG_NOSYSTEM=1",
		"GIT_CONFIG_GLOBAL=/dev/null",
		"GIT_TERMINAL_PROMPT=0",
		"LC_ALL=C",
		"PATH=/usr/bin:/bin:/usr/local/bin:/opt/homebrew/bin",
		"GIT_CONFIG_COUNT=" + configCount,
		"GIT_CONFIG_KEY_0=http.extraHeader",
		"GIT_CONFIG_VALUE_0=Authorization: " + e.AuthorizationHeader,
	}
	if e.Resolver.ObjectDirectory != "" {
		command.Env = append(command.Env,
			"GIT_OBJECT_DIRECTORY="+e.Resolver.ObjectDirectory,
			"GIT_ALTERNATE_OBJECT_DIRECTORIES="+filepath.Join(e.Resolver.RepositoryPath, "objects"),
		)
	}
	if e.TLSCAInfoPath != "" {
		command.Env = append(command.Env,
			"GIT_CONFIG_KEY_1=http.sslCAInfo",
			"GIT_CONFIG_VALUE_1="+e.TLSCAInfoPath,
		)
	}
	command.Stdin = nil
	if _, err := command.CombinedOutput(); err != nil {
		return fmt.Errorf("host Git operation was rejected by fixed upstream")
	}
	return nil
}

func (e PushExecutor) recordSync(outcome string, binding PushBinding, reason string) error {
	details := map[string]string{"repository": binding.Repository, "remote_name": binding.RemoteName, "remote_url": binding.RemoteURL}
	if reason != "" {
		details["reason"] = reason
	}
	return e.Audit.Append(audit.BoundaryEvent{
		Category: "git", Action: "git.fetch.sync", Outcome: outcome, ProjectID: binding.ProjectID,
		VMID: e.VMID, SessionID: e.SessionID, Details: details,
	})
}

func (e PushExecutor) record(outcome string, binding PushBinding, reason string) error {
	details := map[string]string{"repository": binding.Repository, "remote_name": binding.RemoteName, "remote_url": binding.RemoteURL}
	if reason != "" {
		details["reason"] = reason
	}
	return e.Audit.Append(audit.BoundaryEvent{
		Category: "git", Action: "git.push.upstream", Outcome: outcome,
		ProjectID: binding.ProjectID, VMID: e.VMID, SessionID: e.SessionID, Details: details,
	})
}

func validateHostCredentialFile(path string) error {
	if !filepath.IsAbs(path) || filepath.Clean(path) != path {
		return fmt.Errorf("host Git TLS CA path must be absolute and clean")
	}
	info, err := os.Lstat(path)
	if err != nil || !info.Mode().IsRegular() || info.Mode()&os.ModeSymlink != 0 || info.Mode().Perm()&0077 != 0 {
		return fmt.Errorf("host Git TLS CA must be a private regular file")
	}
	canonical, err := filepath.EvalSymlinks(path)
	if err != nil || canonical != path {
		return fmt.Errorf("host Git TLS CA path must not contain symlinks")
	}
	return nil
}

func lockRepository(repository string) (*os.File, error) {
	if _, err := secureRepositoryPath(repository); err != nil {
		return nil, err
	}
	path := filepath.Join(repository, "sunaba-push.lock")
	fd, err := unix.Open(path, unix.O_RDWR|unix.O_CREAT|unix.O_CLOEXEC|unix.O_NOFOLLOW, 0600)
	if err != nil {
		return nil, fmt.Errorf("open host Git transaction lock: %w", err)
	}
	file := os.NewFile(uintptr(fd), path)
	var stat unix.Stat_t
	if err := unix.Fstat(fd, &stat); err != nil || stat.Mode&unix.S_IFMT != unix.S_IFREG || stat.Mode&0777 != 0600 || stat.Uid != uint32(os.Geteuid()) {
		file.Close()
		return nil, fmt.Errorf("host Git transaction lock must be a private owned regular file")
	}
	if err := unix.Flock(fd, unix.LOCK_EX); err != nil {
		file.Close()
		return nil, fmt.Errorf("lock host Git transaction: %w", err)
	}
	return file, nil
}

func containsControl(value string) bool {
	for _, character := range value {
		if character < 0x20 || character == 0x7f {
			return true
		}
	}
	return false
}
