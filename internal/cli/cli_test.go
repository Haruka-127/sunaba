package cli

import (
	"context"
	"strings"
	"testing"
)

func TestEnvWithoutActionReturnsUsage(t *testing.T) {
	t.Setenv("XDG_DATA_HOME", t.TempDir())
	err := Run(context.Background(), []string{"env", "--dir", t.TempDir()})
	if err == nil || !strings.Contains(err.Error(), "usage: sunaba env") {
		t.Fatalf("error=%v", err)
	}
}
