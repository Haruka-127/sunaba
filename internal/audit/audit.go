package audit

import (
	"bufio"
	"context"
	"encoding/json"
	"fmt"
	"net/http"
	"os"
	"os/exec"
	"path/filepath"
	"strconv"
	"strings"
	"syscall"
	"time"

	"sunaba/internal/opencode"
	"sunaba/internal/runtime"
	"sunaba/internal/state"
)

type Record struct {
	TS    string          `json:"ts"`
	Event json.RawMessage `json:"event"`
}

var directHTTPClient = opencode.DirectHTTPClient(0)

func ParseSSE(sc *bufio.Scanner, emit func([]byte) error) error {
	var data []string
	for sc.Scan() {
		line := sc.Text()
		if line == "" {
			if len(data) > 0 {
				if err := emit([]byte(strings.Join(data, "\n"))); err != nil {
					return err
				}
				data = nil
			}
			continue
		}
		if strings.HasPrefix(line, "data:") {
			data = append(data, strings.TrimSpace(strings.TrimPrefix(line, "data:")))
		}
	}
	if len(data) > 0 {
		if err := emit([]byte(strings.Join(data, "\n"))); err != nil {
			return err
		}
	}
	return sc.Err()
}

func StartDaemon(p *state.Project) error {
	if Running(p.AuditPIDPath()) {
		return nil
	}
	unlock, err := acquireStartLock(p.AuditPIDPath() + ".lock")
	if err != nil {
		return err
	}
	defer unlock()
	if Running(p.AuditPIDPath()) {
		return nil
	}
	exe, err := os.Executable()
	if err != nil {
		return err
	}
	devnull, err := os.OpenFile(os.DevNull, os.O_RDWR, 0)
	if err != nil {
		return err
	}
	defer devnull.Close()
	proc, err := os.StartProcess(exe, []string{exe, "_audit", "--project", p.ID}, &os.ProcAttr{
		Files: []*os.File{devnull, devnull, devnull},
		Env:   os.Environ(),
	})
	if err != nil {
		return err
	}
	if err := os.WriteFile(p.AuditPIDPath(), []byte(strconv.Itoa(proc.Pid)+"\n"), 0600); err != nil {
		_ = proc.Kill()
		_ = proc.Release()
		return err
	}
	return proc.Release()
}

func StopDaemon(pidPath string) {
	b, err := os.ReadFile(pidPath)
	if err != nil {
		return
	}
	pid, err := strconv.Atoi(strings.TrimSpace(string(b)))
	if err != nil {
		_ = os.Remove(pidPath)
		return
	}
	projectID := filepath.Base(filepath.Dir(pidPath))
	if !auditProcessMatches(pid, projectID) {
		_ = os.Remove(pidPath)
		return
	}
	if proc, err := os.FindProcess(pid); err == nil {
		_ = proc.Signal(syscall.SIGTERM)
		deadline := time.Now().Add(5 * time.Second)
		for time.Now().Before(deadline) && auditProcessMatches(pid, projectID) {
			time.Sleep(50 * time.Millisecond)
		}
	}
	if auditProcessMatches(pid, projectID) {
		return
	}
	_ = os.Remove(pidPath)
}

func Running(pidPath string) bool {
	b, err := os.ReadFile(pidPath)
	if err != nil {
		return false
	}
	pid, err := strconv.Atoi(strings.TrimSpace(string(b)))
	if err != nil {
		return false
	}
	return auditProcessMatches(pid, filepath.Base(filepath.Dir(pidPath)))
}

func Run(ctx context.Context, st *state.Store, rt runtime.Runtime, projectID string) error {
	projects, err := st.Projects()
	if err != nil {
		return err
	}
	var p *state.Project
	for i := range projects {
		if projects[i].ID == projectID {
			p = &projects[i]
			break
		}
	}
	if p == nil {
		return fmt.Errorf("project %s not found", projectID)
	}
	defer removePIDIfOwner(p.AuditPIDPath(), os.Getpid())
	password, err := p.Password()
	if err != nil {
		return err
	}
	backoff := time.Second
	for {
		select {
		case <-ctx.Done():
			return nil
		default:
		}
		stt, err := rt.ContainerState(ctx, p.Cfg.Container)
		if err != nil || stt != runtime.StateRunning {
			return nil
		}
		ip, err := rt.IPAddress(ctx, p.Cfg.Container)
		if err != nil {
			return nil
		}
		err = streamOnce(ctx, "http://"+ip+":4096/event", password, p.AuditLogDir())
		if ctx.Err() != nil {
			return nil
		}
		if err == nil {
			backoff = time.Second
		} else {
			timer := time.NewTimer(backoff)
			select {
			case <-ctx.Done():
				timer.Stop()
				return nil
			case <-timer.C:
			}
			backoff *= 2
			if backoff > 30*time.Second {
				backoff = 30 * time.Second
			}
		}
	}
}

func streamOnce(ctx context.Context, url, password, logDir string) error {
	req, err := http.NewRequestWithContext(ctx, http.MethodGet, url, nil)
	if err != nil {
		return err
	}
	req.Header.Set("Accept", "text/event-stream")
	req.SetBasicAuth("opencode", password)
	resp, err := directHTTPClient.Do(req)
	if err != nil {
		return err
	}
	defer resp.Body.Close()
	if resp.StatusCode != http.StatusOK {
		return fmt.Errorf("event stream returned %s", resp.Status)
	}
	sc := bufio.NewScanner(resp.Body)
	sc.Buffer(make([]byte, 1024), 1024*1024)
	return ParseSSE(sc, func(data []byte) error {
		if !json.Valid(data) {
			data = []byte(strconv.Quote(string(data)))
		}
		rec := Record{TS: time.Now().UTC().Format(time.RFC3339Nano), Event: json.RawMessage(data)}
		b, err := json.Marshal(rec)
		if err != nil {
			return err
		}
		if err := os.MkdirAll(logDir, 0700); err != nil {
			return err
		}
		path := filepath.Join(logDir, "audit-"+time.Now().Format("20060102")+".jsonl")
		f, err := os.OpenFile(path, os.O_CREATE|os.O_WRONLY|os.O_APPEND, 0600)
		if err != nil {
			return err
		}
		defer f.Close()
		_, err = f.Write(append(b, '\n'))
		return err
	})
}

func acquireStartLock(path string) (func(), error) {
	for i := 0; i < 20; i++ {
		f, err := os.OpenFile(path, os.O_CREATE|os.O_EXCL|os.O_WRONLY, 0600)
		if err == nil {
			_ = f.Close()
			return func() { _ = os.Remove(path) }, nil
		}
		if !os.IsExist(err) {
			return nil, err
		}
		if info, statErr := os.Stat(path); statErr == nil && time.Since(info.ModTime()) > 30*time.Second {
			_ = os.Remove(path)
			continue
		}
		time.Sleep(50 * time.Millisecond)
	}
	return nil, fmt.Errorf("timed out waiting for audit daemon start lock")
}

func auditProcessMatches(pid int, projectID string) bool {
	if pid <= 0 || projectID == "" {
		return false
	}
	ctx, cancel := context.WithTimeout(context.Background(), 2*time.Second)
	defer cancel()
	out, err := exec.CommandContext(ctx, "ps", "-p", strconv.Itoa(pid), "-o", "command=").Output()
	if err != nil {
		return false
	}
	return auditCommandMatches(string(out), projectID)
}

func auditCommandMatches(command, projectID string) bool {
	fields := strings.Fields(command)
	for i := 0; i+2 < len(fields); i++ {
		if fields[i] == "_audit" && fields[i+1] == "--project" && fields[i+2] == projectID {
			return true
		}
	}
	return false
}

func removePIDIfOwner(path string, pid int) {
	b, err := os.ReadFile(path)
	if err != nil {
		return
	}
	owner, err := strconv.Atoi(strings.TrimSpace(string(b)))
	if err == nil && owner == pid {
		_ = os.Remove(path)
	}
}
