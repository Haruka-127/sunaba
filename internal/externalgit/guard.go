// Package externalgit prevents loss of Git state stored outside sunaba's managed workspace gitdir.
package externalgit

import (
	"context"
	"fmt"
	"strings"
)

const safeMarker = "SUNABA_EXTERNAL_GIT_SAFE"

type Executor interface {
	ExecOutput(context.Context, string, []string) (string, error)
}

func CheckBeforeExport(ctx context.Context, executor Executor, container, workspacePath string) error {
	if executor == nil || container == "" || workspacePath == "" || strings.ContainsAny(workspacePath, "\x00\r\n ' \t") {
		return fmt.Errorf("external Git guard configuration is invalid")
	}
	script := strings.Join([]string{
		"set -eu", "unsafe=0", "paths=$(mktemp /run/sunaba/external-git.XXXXXX)", "trap 'rm -f \"$paths\"' EXIT",
		"find " + workspacePath + " /var/lib/sunaba/overlay -path /var/lib/sunaba/overlay/repository -prune -o -name .git -print0 >\"$paths\"",
		"while IFS= read -r -d '' gitmeta; do", "  repo=${gitmeta%/.git}",
		"  if ! dirty=$(runuser -u sunaba-agent -- git -C \"$repo\" status --porcelain --untracked-files=normal 2>/dev/null); then unsafe=1; continue; fi",
		"  if test -n \"$dirty\"; then unsafe=1; continue; fi",
		"  if runuser -u sunaba-agent -- git -C \"$repo\" rev-parse --verify HEAD >/dev/null 2>&1; then",
		"    unpushed=$(runuser -u sunaba-agent -- git -C \"$repo\" rev-list --count HEAD --all --not --remotes 2>/dev/null || echo invalid)",
		"  else unpushed=0; fi",
		"  case $unpushed in ''|*[!0-9]*) unsafe=1 ;; 0) ;; *) unsafe=1 ;; esac", "done <\"$paths\"",
		"test \"$unsafe\" -eq 0", "printf " + safeMarker,
	}, "\n")
	out, err := executor.ExecOutput(ctx, container, []string{"/bin/bash", "-lc", script})
	if err != nil || strings.TrimSpace(out) != safeMarker {
		return fmt.Errorf("external Git working tree has dirty or unpushed state outside sunaba's managed gitdir; commit and push it, copy its working files into the main workspace, or explicitly discard the VM")
	}
	return nil
}
