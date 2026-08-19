package externalgit

import (
	"context"
	"errors"
	"strings"
	"testing"
)

type fakeExecutor struct {
	unsafe  bool
	command string
}

func (f *fakeExecutor) ExecOutput(_ context.Context, _ string, command []string) (string, error) {
	f.command = strings.Join(command, " ")
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
	if !strings.Contains(fake.command, "status --porcelain") || !strings.Contains(fake.command, "rev-list --count HEAD --all --not --remotes") || !strings.Contains(fake.command, "-name .git -print0") || strings.Contains(fake.command, "-type d -name .git") || strings.Contains(fake.command, "-print0 2>/dev/null") {
		t.Fatalf("guard command missed checks: %s", fake.command)
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
