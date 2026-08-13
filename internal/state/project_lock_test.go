package state

import (
	"bufio"
	"errors"
	"fmt"
	"os"
	"os/exec"
	"os/signal"
	"path/filepath"
	"strings"
	"syscall"
	"testing"
	"time"
)

func TestProjectLockSerializesCanonicalProjectAliases(t *testing.T) {
	root := t.TempDir()
	project := filepath.Join(root, "project")
	if err := os.Mkdir(project, 0700); err != nil {
		t.Fatal(err)
	}
	alias := filepath.Join(root, "project-alias")
	if err := os.Symlink(project, alias); err != nil {
		t.Fatal(err)
	}
	store := &Store{Root: filepath.Join(root, "state")}
	first, err := store.AcquireProjectLock(project)
	if err != nil {
		t.Fatal(err)
	}
	canonicalProject, err := ResolveProjectPath(project)
	if err != nil {
		t.Fatal(err)
	}
	if first.ProjectRoot != canonicalProject || first.ProjectID != ProjectID(canonicalProject) {
		t.Fatalf("lock identity=%+v", first)
	}
	if _, err := store.AcquireProjectLock(alias); !errors.Is(err, ErrProjectLocked) {
		t.Fatalf("canonical alias lock error=%v", err)
	}
	info, err := os.Lstat(first.Path)
	if err != nil {
		t.Fatal(err)
	}
	if !info.Mode().IsRegular() || info.Mode().Perm() != 0600 {
		t.Fatalf("lock mode=%v", info.Mode())
	}
	if err := first.Close(); err != nil {
		t.Fatal(err)
	}
	second, err := store.AcquireProjectLock(alias)
	if err != nil {
		t.Fatalf("lock was not released: %v", err)
	}
	defer second.Close()
}

func TestProjectLockRejectsSymlinkLockFile(t *testing.T) {
	root := t.TempDir()
	project := filepath.Join(root, "project")
	if err := os.Mkdir(project, 0700); err != nil {
		t.Fatal(err)
	}
	store := &Store{Root: filepath.Join(root, "state")}
	lockDirectory := filepath.Join(store.Root, "locks")
	if err := os.MkdirAll(lockDirectory, 0700); err != nil {
		t.Fatal(err)
	}
	target := filepath.Join(root, "outside")
	if err := os.WriteFile(target, []byte("do not touch"), 0600); err != nil {
		t.Fatal(err)
	}
	canonicalProject, err := ResolveProjectPath(project)
	if err != nil {
		t.Fatal(err)
	}
	if err := os.Symlink(target, filepath.Join(lockDirectory, ProjectID(canonicalProject)+".lock")); err != nil {
		t.Fatal(err)
	}
	if _, err := store.AcquireProjectLock(project); err == nil {
		t.Fatal("symlink Project lock was accepted")
	}
	contents, err := os.ReadFile(target)
	if err != nil {
		t.Fatal(err)
	}
	if string(contents) != "do not touch" {
		t.Fatalf("symlink target was modified: %q", contents)
	}
}

func TestProjectLockIsReleasedAfterHolderProcessCrash(t *testing.T) {
	root := t.TempDir()
	project := filepath.Join(root, "project")
	if err := os.Mkdir(project, 0700); err != nil {
		t.Fatal(err)
	}
	executable, err := os.Executable()
	if err != nil {
		t.Fatal(err)
	}
	command := exec.Command(executable, "-test.run=TestProjectLockHelperProcess")
	command.Env = append(os.Environ(),
		"SUNABA_PROJECT_LOCK_HELPER=1",
		"SUNABA_PROJECT_LOCK_STATE="+filepath.Join(root, "state"),
		"SUNABA_PROJECT_LOCK_ROOT="+project,
	)
	stdout, err := command.StdoutPipe()
	if err != nil {
		t.Fatal(err)
	}
	command.Stderr = command.Stdout
	if err := command.Start(); err != nil {
		t.Fatal(err)
	}
	waited := false
	defer func() {
		if !waited {
			_ = command.Process.Kill()
			_ = command.Wait()
		}
	}()
	ready := make(chan string, 1)
	go func() {
		scanner := bufio.NewScanner(stdout)
		if scanner.Scan() {
			ready <- scanner.Text()
			return
		}
		ready <- ""
	}()
	select {
	case line := <-ready:
		if line != "ready" {
			t.Fatalf("lock helper output=%q", line)
		}
	case <-time.After(5 * time.Second):
		t.Fatal("lock helper did not become ready")
	}
	store := &Store{Root: filepath.Join(root, "state")}
	if _, err := store.AcquireProjectLock(project); !errors.Is(err, ErrProjectLocked) {
		t.Fatalf("live helper lock error=%v", err)
	}
	if err := command.Process.Kill(); err != nil {
		t.Fatal(err)
	}
	_ = command.Wait()
	waited = true
	lock, err := store.AcquireProjectLock(project)
	if err != nil {
		t.Fatalf("kernel did not release lock after process crash: %v", err)
	}
	defer lock.Close()
}

func TestProjectLockHelperProcess(t *testing.T) {
	if os.Getenv("SUNABA_PROJECT_LOCK_HELPER") != "1" {
		return
	}
	store := &Store{Root: os.Getenv("SUNABA_PROJECT_LOCK_STATE")}
	lock, err := store.AcquireProjectLock(os.Getenv("SUNABA_PROJECT_LOCK_ROOT"))
	if err != nil {
		fmt.Println("error:" + strings.ReplaceAll(err.Error(), "\n", " "))
		os.Exit(2)
	}
	defer lock.Close()
	fmt.Println("ready")
	interrupt := make(chan os.Signal, 1)
	signal.Notify(interrupt, os.Interrupt, syscall.SIGTERM)
	<-interrupt
}
