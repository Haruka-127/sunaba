package externalgit

import (
	"bytes"
	"context"
	"errors"
	"os"
	"os/exec"
	"path/filepath"
	"strings"
	"testing"
)

type fakeExecutor struct {
	unsafe  bool
	command string
	script  string
}

func (f *fakeExecutor) ExecOutput(_ context.Context, _ string, command []string) (string, error) {
	f.command = strings.Join(command, " ")
	if len(command) == 3 {
		f.script = command[2]
	}
	if f.unsafe {
		return "", errors.New("unsafe")
	}
	return safeMarker, nil
}

func TestCheckBeforeExportFailsClosedForDirtyOrUnpushedRepository(t *testing.T) {
	fake := &fakeExecutor{}
	if err := CheckBeforeExport(context.Background(), fake, "sunaba-project-session", "/workspace/project"); err != nil {
		t.Fatal(err)
	}
	checks := []string{
		"for root in / /workspace/project /var/lib/sunaba/overlay /run/sunaba",
		"find \"$root\" -xdev",
		"-path /proc",
		"-path /var/lib/sunaba/repository",
		"-path /var/lib/sunaba/overlay/repository",
		"-name .git",
		"-name HEAD",
		"--is-bare-repository",
		"status --porcelain --untracked-files=all",
		"rev-list --count HEAD --all --not --remotes",
		"rev-list --count --all --not --remotes",
		"count\" -gt 512",
	}
	for _, check := range checks {
		if !strings.Contains(fake.command, check) {
			t.Fatalf("guard command missed %q: %s", check, fake.command)
		}
	}
	if strings.Contains(fake.command, "-print0 2>/dev/null") {
		t.Fatalf("guard command missed checks: %s", fake.command)
	}
	syntax := exec.Command("/bin/bash", "-n")
	syntax.Stdin = strings.NewReader(fake.script)
	if output, err := syntax.CombinedOutput(); err != nil {
		t.Fatalf("guard script syntax error: %v: %s", err, output)
	}
	fake.unsafe = true
	if err := CheckBeforeExport(context.Background(), fake, "sunaba-project-session", "/workspace/project"); err == nil || !strings.Contains(err.Error(), "dirty or unpushed") {
		t.Fatalf("unsafe state accepted: %v", err)
	}
}

func TestCheckBeforeExportRejectsUntrustedCommandIdentity(t *testing.T) {
	for _, workspace := range []string{"", "/workspace/project;touch /tmp/x", "/workspace/project name"} {
		if err := CheckBeforeExport(context.Background(), &fakeExecutor{}, "container", workspace); err == nil {
			t.Fatalf("unsafe workspace accepted: %q", workspace)
		}
	}
}

func TestDiscoveryAndUnpushedChecksCoverSymlinkMetadataAndUnbornBareHEAD(t *testing.T) {
	root := t.TempDir()
	work := filepath.Join(root, "work")
	if output, err := exec.Command("git", "init", work).CombinedOutput(); err != nil {
		t.Fatalf("init worktree: %v: %s", err, output)
	}
	gitdir := filepath.Join(root, "work-gitdir")
	if err := os.Rename(filepath.Join(work, ".git"), gitdir); err != nil {
		t.Fatal(err)
	}
	if err := os.Symlink(filepath.Join("..", "work-gitdir"), filepath.Join(work, ".git")); err != nil {
		t.Fatal(err)
	}
	bare := filepath.Join(root, "bare.git")
	if output, err := exec.Command("git", "init", "--bare", bare).CombinedOutput(); err != nil {
		t.Fatalf("init bare: %v: %s", err, output)
	}
	if err := os.Remove(filepath.Join(bare, "HEAD")); err != nil {
		t.Fatal(err)
	}
	if err := os.Symlink(filepath.Join("refs", "heads", "unborn"), filepath.Join(bare, "HEAD")); err != nil {
		t.Fatal(err)
	}
	discovered, err := exec.Command("find", root, "-xdev", "(", "-name", ".git", "-o", "-name", "HEAD", ")", "-print0").Output()
	if err != nil {
		t.Fatal(err)
	}
	for _, path := range []string{filepath.Join(work, ".git"), filepath.Join(bare, "HEAD")} {
		if !bytes.Contains(discovered, append([]byte(path), 0)) {
			t.Fatalf("discovery omitted symlink metadata %s: %q", path, discovered)
		}
	}

	seed := filepath.Join(root, "seed")
	if output, err := exec.Command("git", "init", seed).CombinedOutput(); err != nil {
		t.Fatalf("init seed: %v: %s", err, output)
	}
	for _, args := range [][]string{{"-C", seed, "config", "user.name", "sunaba-test"}, {"-C", seed, "config", "user.email", "sunaba@example.invalid"}} {
		if output, err := exec.Command("git", args...).CombinedOutput(); err != nil {
			t.Fatalf("configure seed: %v: %s", err, output)
		}
	}
	if err := os.WriteFile(filepath.Join(seed, "file.txt"), []byte("content\n"), 0600); err != nil {
		t.Fatal(err)
	}
	for _, args := range [][]string{{"-C", seed, "add", "file.txt"}, {"-C", seed, "commit", "-m", "seed"}, {"-C", seed, "push", bare, "HEAD:refs/heads/topic"}} {
		if output, err := exec.Command("git", args...).CombinedOutput(); err != nil {
			t.Fatalf("prepare unborn-HEAD bare ref: %v: %s", err, output)
		}
	}
	if err := exec.Command("git", "--git-dir="+bare, "rev-parse", "--verify", "HEAD").Run(); err == nil {
		t.Fatal("bare HEAD unexpectedly resolved; fixture does not cover the unborn-HEAD branch")
	}
	count, err := exec.Command("git", "--git-dir="+bare, "rev-list", "--count", "--all", "--not", "--remotes").Output()
	if err != nil || strings.TrimSpace(string(count)) != "1" {
		t.Fatalf("unborn-HEAD bare refs were not detected: count=%q error=%v", count, err)
	}
}
