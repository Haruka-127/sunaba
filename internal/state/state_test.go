package state

import (
	"os"
	"path/filepath"
	"testing"
)

func TestProjectID(t *testing.T) {
	id := ProjectID("/Users/alice/work/myapp")
	if len(id) != 12 {
		t.Fatalf("len=%d", len(id))
	}
	if id != ProjectID("/Users/alice/work/myapp") {
		t.Fatal("ProjectID is not stable")
	}
}

func TestEnvRoundTrip(t *testing.T) {
	dir := t.TempDir()
	path := filepath.Join(dir, "env")
	in := map[string]string{"GITHUB_TOKEN": "github_pat_xxx", "SUNABA_TEST": "abc"}
	if err := WriteEnvFile(path, in); err != nil {
		t.Fatal(err)
	}
	st, err := os.Stat(path)
	if err != nil {
		t.Fatal(err)
	}
	if st.Mode().Perm() != 0600 {
		t.Fatalf("mode=%v", st.Mode().Perm())
	}
	got, err := ReadEnvFile(path)
	if err != nil {
		t.Fatal(err)
	}
	for k, v := range in {
		if got[k] != v {
			t.Fatalf("%s=%q", k, got[k])
		}
	}
}

func TestInvalidEnv(t *testing.T) {
	dir := t.TempDir()
	path := filepath.Join(dir, "env")
	if err := os.WriteFile(path, []byte("1BAD=x\n"), 0600); err != nil {
		t.Fatal(err)
	}
	if _, err := ReadEnvFile(path); err == nil {
		t.Fatal("expected invalid env error")
	}
}
