package gitgateway

import (
	"bytes"
	"context"
	"errors"
	"fmt"
	"os"
	"os/exec"
	"path/filepath"
	"strings"
)

type ProposedRefUpdate struct {
	Ref string
	Old string
	New string
}

type RepositoryResolver struct {
	GitPath        string
	RepositoryPath string
	ProjectID      string
	Repository     string
	RemoteName     string
	RemoteURL      string
}

func (r RepositoryResolver) Resolve(ctx context.Context, proposed []ProposedRefUpdate) (PushBinding, error) {
	repositoryPath, err := secureRepositoryPath(r.RepositoryPath)
	if err != nil {
		return PushBinding{}, err
	}
	gitPath := r.GitPath
	if gitPath == "" {
		gitPath, err = exec.LookPath("git")
		if err != nil {
			return PushBinding{}, fmt.Errorf("locate host Git: %w", err)
		}
	}
	if !filepath.IsAbs(gitPath) {
		return PushBinding{}, fmt.Errorf("host Git path must be absolute")
	}
	runner := repositoryGit{binary: gitPath, repository: repositoryPath}
	format, err := runner.output(ctx, "rev-parse", "--show-object-format")
	if err != nil {
		return PushBinding{}, err
	}
	objectLength := 0
	switch strings.TrimSpace(format) {
	case "sha1":
		objectLength = 40
	case "sha256":
		objectLength = 64
	default:
		return PushBinding{}, fmt.Errorf("unsupported Git object format")
	}
	if len(proposed) == 0 || len(proposed) > 128 {
		return PushBinding{}, fmt.Errorf("invalid Git ref update count")
	}
	updates := make([]RefUpdate, 0, len(proposed))
	zero := strings.Repeat("0", objectLength)
	seen := make(map[string]struct{}, len(proposed))
	for _, item := range proposed {
		if _, exists := seen[item.Ref]; exists {
			return PushBinding{}, fmt.Errorf("duplicate Git ref update")
		}
		seen[item.Ref] = struct{}{}
		if err := runner.run(ctx, "check-ref-format", item.Ref); err != nil {
			return PushBinding{}, fmt.Errorf("invalid Git ref %q", item.Ref)
		}
		if len(item.Old) != objectLength || len(item.New) != objectLength || !objectIDPattern.MatchString(item.Old) || !objectIDPattern.MatchString(item.New) {
			return PushBinding{}, fmt.Errorf("invalid Git object ID")
		}
		current, exists, err := runner.ref(ctx, item.Ref)
		if err != nil {
			return PushBinding{}, err
		}
		if !exists {
			current = zero
		}
		if current != item.Old {
			return PushBinding{}, fmt.Errorf("Git ref changed before approval")
		}
		deleting := item.New == zero
		if deleting && item.Old == zero {
			return PushBinding{}, fmt.Errorf("cannot delete absent Git ref")
		}
		force := false
		if !deleting {
			if err := runner.run(ctx, "cat-file", "-e", item.New+"^{object}"); err != nil {
				return PushBinding{}, fmt.Errorf("new Git object is absent from host quarantine")
			}
			if strings.HasPrefix(item.Ref, "refs/heads/") {
				objectType, err := runner.output(ctx, "cat-file", "-t", item.New)
				if err != nil || strings.TrimSpace(objectType) != "commit" {
					return PushBinding{}, fmt.Errorf("branch target must be a commit")
				}
			}
			if item.Old != zero {
				if strings.HasPrefix(item.Ref, "refs/heads/") {
					force = runner.run(ctx, "merge-base", "--is-ancestor", item.Old, item.New) != nil
				} else {
					force = item.Old != item.New
				}
			}
		}
		updates = append(updates, RefUpdate{Ref: item.Ref, Old: item.Old, New: item.New, Force: force, Delete: deleting})
	}
	binding, _, err := canonicalBinding(PushBinding{
		ProjectID:  r.ProjectID,
		Repository: r.Repository,
		RemoteName: r.RemoteName,
		RemoteURL:  r.RemoteURL,
		Updates:    updates,
	})
	return binding, err
}

func secureRepositoryPath(path string) (string, error) {
	if !filepath.IsAbs(path) || filepath.Clean(path) != path {
		return "", fmt.Errorf("host Git quarantine path must be absolute and clean")
	}
	info, err := os.Lstat(path)
	if err != nil || !info.IsDir() || info.Mode()&os.ModeSymlink != 0 || info.Mode().Perm() != 0700 {
		return "", fmt.Errorf("host Git quarantine must be a mode 0700 directory")
	}
	canonical, err := filepath.EvalSymlinks(path)
	if err != nil || canonical != path {
		return "", fmt.Errorf("host Git quarantine path must not contain symlinks")
	}
	return path, nil
}

type repositoryGit struct {
	binary     string
	repository string
}

func (g repositoryGit) run(ctx context.Context, args ...string) error {
	_, err := g.command(ctx, args...).CombinedOutput()
	return err
}

func (g repositoryGit) output(ctx context.Context, args ...string) (string, error) {
	output, err := g.command(ctx, args...).CombinedOutput()
	if err != nil {
		return "", fmt.Errorf("host Git operation failed")
	}
	if bytes.IndexByte(output, 0) >= 0 || len(output) > 4096 {
		return "", fmt.Errorf("invalid host Git output")
	}
	return string(output), nil
}

func (g repositoryGit) ref(ctx context.Context, ref string) (string, bool, error) {
	output, err := g.command(ctx, "show-ref", "--verify", "--hash", ref).CombinedOutput()
	if err != nil {
		var exitError *exec.ExitError
		if errors.As(err, &exitError) && exitError.ExitCode() == 1 && len(output) == 0 {
			return "", false, nil
		}
		return "", false, fmt.Errorf("read host Git ref: operation failed")
	}
	value := strings.TrimSpace(string(output))
	if !objectIDPattern.MatchString(value) {
		return "", false, fmt.Errorf("invalid host Git ref object")
	}
	return value, true, nil
}

func (g repositoryGit) command(ctx context.Context, args ...string) *exec.Cmd {
	commandArgs := append([]string{"--git-dir=" + g.repository}, args...)
	command := exec.CommandContext(ctx, g.binary, commandArgs...)
	command.Env = []string{
		"GIT_CONFIG_NOSYSTEM=1",
		"GIT_CONFIG_GLOBAL=/dev/null",
		"GIT_TERMINAL_PROMPT=0",
		"LC_ALL=C",
		"PATH=/usr/bin:/bin:/usr/local/bin:/opt/homebrew/bin",
	}
	command.Dir = g.repository
	command.Stdin = nil
	return command
}
