package gitgateway

import (
	"context"
	"os"
	"os/exec"
	"path/filepath"
	"strings"
	"testing"
)

func TestRepositoryResolverComputesFastForwardForceAndDelete(t *testing.T) {
	repository, first, second, divergent := testBareRepository(t)
	resolver := testResolver(t, repository)

	binding, err := resolver.Resolve(context.Background(), []ProposedRefUpdate{{Ref: "refs/heads/main", Old: first, New: second}})
	if err != nil {
		t.Fatal(err)
	}
	if binding.Updates[0].Force || binding.Updates[0].Delete {
		t.Fatalf("fast-forward classified as %+v", binding.Updates[0])
	}
	binding, err = resolver.Resolve(context.Background(), []ProposedRefUpdate{{Ref: "refs/heads/main", Old: first, New: divergent}})
	if err != nil {
		t.Fatal(err)
	}
	if !binding.Updates[0].Force || binding.Updates[0].Delete {
		t.Fatalf("non-fast-forward classified as %+v", binding.Updates[0])
	}
	zero := strings.Repeat("0", len(first))
	binding, err = resolver.Resolve(context.Background(), []ProposedRefUpdate{{Ref: "refs/heads/main", Old: first, New: zero}})
	if err != nil {
		t.Fatal(err)
	}
	if binding.Updates[0].Force || !binding.Updates[0].Delete {
		t.Fatalf("delete classified as %+v", binding.Updates[0])
	}
	testGit(t, resolver.GitPath, repository, "update-ref", "refs/tags/release", first)
	binding, err = resolver.Resolve(context.Background(), []ProposedRefUpdate{{Ref: "refs/tags/release", Old: first, New: second}})
	if err != nil {
		t.Fatal(err)
	}
	if !binding.Updates[0].Force {
		t.Fatalf("tag replacement was not classified as force: %+v", binding.Updates[0])
	}
}

func TestRepositoryResolverRejectsStaleRefMissingObjectAndSymlink(t *testing.T) {
	repository, first, second, _ := testBareRepository(t)
	resolver := testResolver(t, repository)
	zero := strings.Repeat("0", len(first))
	cases := []ProposedRefUpdate{
		{Ref: "refs/heads/main", Old: second, New: first},
		{Ref: "refs/heads/main", Old: first, New: strings.Repeat("e", len(first))},
		{Ref: "refs/heads/bad..name", Old: zero, New: second},
	}
	for _, proposed := range cases {
		if _, err := resolver.Resolve(context.Background(), []ProposedRefUpdate{proposed}); err == nil {
			t.Fatalf("unsafe proposal was accepted: %+v", proposed)
		}
	}
	link := filepath.Join(filepath.Dir(repository), "repository-link")
	if err := os.Symlink(repository, link); err != nil {
		t.Fatal(err)
	}
	resolver.RepositoryPath = link
	if _, err := resolver.Resolve(context.Background(), []ProposedRefUpdate{{Ref: "refs/heads/main", Old: first, New: second}}); err == nil {
		t.Fatal("symlinked repository was accepted")
	}
}

func testResolver(t *testing.T, repository string) RepositoryResolver {
	t.Helper()
	gitPath, err := exec.LookPath("git")
	if err != nil {
		t.Skip("host Git is unavailable")
	}
	return RepositoryResolver{GitPath: gitPath, RepositoryPath: repository, ProjectID: "project", Repository: "repository", RemoteName: "origin", RemoteURL: "https://example.com/repository.git"}
}

func testBareRepository(t *testing.T) (string, string, string, string) {
	t.Helper()
	gitPath, err := exec.LookPath("git")
	if err != nil {
		t.Skip("host Git is unavailable")
	}
	root, err := filepath.EvalSymlinks(t.TempDir())
	if err != nil {
		t.Fatal(err)
	}
	repository := filepath.Join(root, "repository.git")
	testGit(t, gitPath, "", "init", "--bare", repository)
	if err := os.Chmod(repository, 0700); err != nil {
		t.Fatal(err)
	}
	work := filepath.Join(root, "work")
	testGit(t, gitPath, "", "init", work)
	testGit(t, gitPath, work, "config", "user.name", "Sunaba Test")
	testGit(t, gitPath, work, "config", "user.email", "sunaba@example.invalid")
	if err := os.WriteFile(filepath.Join(work, "file"), []byte("first\n"), 0600); err != nil {
		t.Fatal(err)
	}
	testGit(t, gitPath, work, "add", "file")
	testGit(t, gitPath, work, "commit", "-m", "first")
	first := strings.TrimSpace(testGit(t, gitPath, work, "rev-parse", "HEAD"))
	testGit(t, gitPath, work, "push", repository, "HEAD:refs/heads/main")
	if err := os.WriteFile(filepath.Join(work, "file"), []byte("second\n"), 0600); err != nil {
		t.Fatal(err)
	}
	testGit(t, gitPath, work, "commit", "-am", "second")
	second := strings.TrimSpace(testGit(t, gitPath, work, "rev-parse", "HEAD"))
	testGit(t, gitPath, repository, "fetch", work, second)
	tree := strings.TrimSpace(testGit(t, gitPath, work, "rev-parse", first+"^{tree}"))
	command := exec.Command(gitPath, "--git-dir="+repository, "commit-tree", tree)
	command.Env = append(testGitEnvironment(), "GIT_AUTHOR_NAME=Sunaba Test", "GIT_AUTHOR_EMAIL=sunaba@example.invalid", "GIT_COMMITTER_NAME=Sunaba Test", "GIT_COMMITTER_EMAIL=sunaba@example.invalid")
	command.Stdin = strings.NewReader("divergent\n")
	output, err := command.CombinedOutput()
	if err != nil {
		t.Fatalf("git commit-tree: %v: %s", err, output)
	}
	return repository, first, second, strings.TrimSpace(string(output))
}

func testGit(t *testing.T, gitPath, directory string, args ...string) string {
	t.Helper()
	command := exec.Command(gitPath, args...)
	command.Dir = directory
	command.Env = testGitEnvironment()
	output, err := command.CombinedOutput()
	if err != nil {
		t.Fatalf("git %v: %v: %s", args, err, output)
	}
	return string(output)
}

func testGitEnvironment() []string {
	return []string{
		"GIT_CONFIG_NOSYSTEM=1",
		"GIT_CONFIG_GLOBAL=/dev/null",
		"GIT_TERMINAL_PROMPT=0",
		"LC_ALL=C",
		"PATH=/usr/bin:/bin:/usr/local/bin:/opt/homebrew/bin",
	}
}
