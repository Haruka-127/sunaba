package runtime

import (
	"bytes"
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"os"
	"os/exec"
	"path/filepath"
	"sort"
	"strings"
	"time"
)

type AppleContainer struct {
	Verbose bool
	Stdout  *os.File
	Stderr  *os.File
	Timeout time.Duration
}

func NewAppleContainer(verbose bool) *AppleContainer {
	return &AppleContainer{Verbose: verbose, Stdout: os.Stdout, Stderr: os.Stderr, Timeout: 60 * time.Second}
}

func (r *AppleContainer) ImageExists(ctx context.Context, tag string) (bool, error) {
	ctx, cancel := context.WithTimeout(ctx, r.timeout())
	defer cancel()
	out, err := r.output(ctx, "container", "image", "ls", "--format", "json")
	if err != nil {
		out, err = r.output(ctx, "container", "images", "--format", "json")
	}
	if err != nil {
		return false, err
	}
	var payload any
	if err := json.Unmarshal([]byte(out), &payload); err != nil {
		return false, fmt.Errorf("cannot parse container image list JSON: %w", err)
	}
	return containsExactString(payload, tag), nil
}

func (r *AppleContainer) BuildImage(ctx context.Context, tag, contextDir string, buildArgs map[string]string) error {
	ctx, cancel := context.WithTimeout(ctx, 30*time.Minute)
	defer cancel()
	args := []string{"build", "--platform", "linux/arm64", "--no-cache", "--tag", tag}
	for k, v := range buildArgs {
		args = append(args, "--build-arg", k+"="+v)
	}
	args = append(args, contextDir)
	return r.run(ctx, "container", args...)
}

func (r *AppleContainer) ContainerState(ctx context.Context, name string) (State, error) {
	info, err := r.Inspect(ctx, name)
	if err != nil {
		if isNotFound(err) {
			return StateNotFound, nil
		}
		return StateUnknown, err
	}
	return info.State, nil
}

func (r *AppleContainer) Create(ctx context.Context, spec ContainerSpec) error {
	if !strings.HasPrefix(spec.Name, "sunaba-") {
		return fmt.Errorf("refusing to create non-sunaba container %q", spec.Name)
	}
	ctx, cancel := context.WithTimeout(ctx, r.timeout())
	defer cancel()
	return r.run(ctx, "container", createArgs(spec)...)
}

func createArgs(spec ContainerSpec) []string {
	args := []string{"run", "--detach", "--name", spec.Name}
	if spec.CPUs > 0 {
		args = append(args, "--cpus", fmt.Sprint(spec.CPUs))
	}
	if spec.Memory != "" {
		args = append(args, "--memory", spec.Memory)
	}
	limitKeys := make([]string, 0, len(spec.Ulimits))
	for name := range spec.Ulimits {
		limitKeys = append(limitKeys, name)
	}
	sort.Strings(limitKeys)
	for _, name := range limitKeys {
		limit := spec.Ulimits[name]
		args = append(args, "--ulimit", fmt.Sprintf("%s=%d:%d", name, limit.Soft, limit.Hard))
	}
	for _, network := range spec.Networks {
		args = append(args, "--network", network)
	}
	if spec.NoDNS {
		args = append(args, "--no-dns")
	}
	if spec.ReadOnly {
		args = append(args, "--read-only")
	}
	for _, capability := range spec.CapDrop {
		args = append(args, "--cap-drop", capability)
	}
	for _, capability := range spec.CapAdd {
		args = append(args, "--cap-add", capability)
	}
	for _, m := range spec.Mounts {
		if m.Type == "" || m.Type == "socket" {
			value := m.Source + ":" + m.Target
			if m.ReadOnly {
				value += ":ro"
			}
			args = append(args, "--volume", value)
			continue
		}
		value := "type=" + m.Type + ",source=" + m.Source + ",target=" + m.Target
		if m.ReadOnly {
			value += ",readonly"
		}
		args = append(args, "--mount", value)
	}
	for _, socket := range spec.Sockets {
		args = append(args, "--publish-socket", socket.HostPath+":"+socket.GuestPath)
	}
	for _, f := range spec.EnvFiles {
		args = append(args, "--env-file", f)
	}
	envKeys := make([]string, 0, len(spec.Env))
	for k := range spec.Env {
		envKeys = append(envKeys, k)
	}
	sort.Strings(envKeys)
	for _, k := range envKeys {
		v := spec.Env[k]
		args = append(args, "--env", k+"="+v)
	}
	labelKeys := make([]string, 0, len(spec.Labels))
	for k := range spec.Labels {
		labelKeys = append(labelKeys, k)
	}
	sort.Strings(labelKeys)
	for _, k := range labelKeys {
		v := spec.Labels[k]
		args = append(args, "--label", k+"="+v)
	}
	if spec.Workdir != "" {
		args = append(args, "--workdir", spec.Workdir)
	}
	if spec.Entrypoint != "" {
		args = append(args, "--entrypoint", spec.Entrypoint)
	}
	args = append(args, spec.Image)
	args = append(args, spec.Args...)
	return args
}

func (r *AppleContainer) Start(ctx context.Context, name string) error {
	ctx, cancel := context.WithTimeout(ctx, r.timeout())
	defer cancel()
	return r.run(ctx, "container", "start", name)
}

func (r *AppleContainer) Stop(ctx context.Context, name string) error {
	ctx, cancel := context.WithTimeout(ctx, r.timeout())
	defer cancel()
	return r.run(ctx, "container", "stop", name)
}

func (r *AppleContainer) Remove(ctx context.Context, name string) error {
	if !strings.HasPrefix(name, "sunaba-") {
		return fmt.Errorf("refusing to remove non-sunaba container %q", name)
	}
	ctx, cancel := context.WithTimeout(ctx, r.timeout())
	defer cancel()
	return r.run(ctx, "container", "rm", name)
}

func (r *AppleContainer) Exec(ctx context.Context, name string, interactive bool, command []string) error {
	args := []string{"exec"}
	if interactive {
		args = append(args, "--interactive", "--tty")
	}
	args = append(args, name)
	args = append(args, command...)
	return r.run(ctx, "container", args...)
}

func (r *AppleContainer) ExecOutput(ctx context.Context, name string, command []string) (string, error) {
	ctx, cancel := context.WithTimeout(ctx, r.timeout())
	defer cancel()
	args := append([]string{"exec", name}, command...)
	return r.output(ctx, "container", args...)
}

func (r *AppleContainer) CopyTo(ctx context.Context, name, source, target string) error {
	if !strings.HasPrefix(name, "sunaba-") {
		return fmt.Errorf("refusing to copy into non-sunaba container %q", name)
	}
	if !strings.HasPrefix(target, "/") {
		return fmt.Errorf("container copy target must be absolute: %q", target)
	}
	ctx, cancel := context.WithTimeout(ctx, r.timeout())
	defer cancel()
	return r.run(ctx, "container", "cp", source, name+":"+target)
}

func (r *AppleContainer) Export(ctx context.Context, name, output string) error {
	if !strings.HasPrefix(name, "sunaba-") {
		return fmt.Errorf("refusing to export non-sunaba container %q", name)
	}
	if !filepath.IsAbs(output) {
		return fmt.Errorf("container export output must be absolute: %q", output)
	}
	parent := filepath.Dir(output)
	if !strings.HasPrefix(filepath.Base(parent), "sunaba-") {
		return fmt.Errorf("container export parent must have sunaba- prefix: %q", parent)
	}
	info, err := os.Lstat(parent)
	if err != nil {
		return fmt.Errorf("inspect export quarantine: %w", err)
	}
	if !info.IsDir() || info.Mode().Perm() != 0700 {
		return fmt.Errorf("export quarantine must be a mode 0700 directory: %q", parent)
	}
	canonicalParent, err := filepath.EvalSymlinks(parent)
	if err != nil {
		return fmt.Errorf("resolve export quarantine: %w", err)
	}
	output = filepath.Join(canonicalParent, filepath.Base(output))
	if _, err := os.Lstat(output); err == nil {
		return fmt.Errorf("container export output already exists: %q", output)
	} else if !errors.Is(err, os.ErrNotExist) {
		return err
	}
	state, err := r.ContainerState(ctx, name)
	if err != nil {
		return err
	}
	if state != StateStopped {
		return fmt.Errorf("container %s must be stopped before export; state=%s", name, state)
	}
	ctx, cancel := context.WithTimeout(ctx, 10*time.Minute)
	defer cancel()
	return r.run(ctx, "container", "export", "--output", output, name)
}

func (r *AppleContainer) IPAddress(ctx context.Context, name string) (string, error) {
	info, err := r.Inspect(ctx, name)
	if err != nil {
		return "", err
	}
	if info.IP == "" {
		return "", fmt.Errorf("container %s has no IP address in inspect output", name)
	}
	return info.IP, nil
}

func (r *AppleContainer) Inspect(ctx context.Context, name string) (Info, error) {
	ctx, cancel := context.WithTimeout(ctx, r.timeout())
	defer cancel()
	out, err := r.output(ctx, "container", "inspect", name)
	if err != nil {
		return Info{}, err
	}
	return parseInspect(out, name)
}

func (r *AppleContainer) List(ctx context.Context) ([]Info, error) {
	ctx, cancel := context.WithTimeout(ctx, r.timeout())
	defer cancel()
	out, err := r.output(ctx, "container", "list", "--all", "--format", "json")
	if err != nil {
		return nil, err
	}
	return parseList(out), nil
}

func (r *AppleContainer) timeout() time.Duration {
	if r.Timeout > 0 {
		return r.Timeout
	}
	return 60 * time.Second
}

func (r *AppleContainer) run(ctx context.Context, name string, args ...string) error {
	if r.Verbose {
		fmt.Fprintf(r.Stderr, "+ %s %s\n", name, strings.Join(args, " "))
	}
	cmd := exec.CommandContext(ctx, name, args...)
	cmd.Stdin = os.Stdin
	cmd.Stdout = r.Stdout
	cmd.Stderr = r.Stderr
	return cmd.Run()
}

func (r *AppleContainer) output(ctx context.Context, name string, args ...string) (string, error) {
	if r.Verbose {
		fmt.Fprintf(r.Stderr, "+ %s %s\n", name, strings.Join(args, " "))
	}
	cmd := exec.CommandContext(ctx, name, args...)
	var out, errb bytes.Buffer
	cmd.Stdout = &out
	cmd.Stderr = &errb
	err := cmd.Run()
	if err != nil {
		if errb.Len() > 0 {
			return out.String(), fmt.Errorf("%s %s failed: %w: %s", name, strings.Join(args, " "), err, strings.TrimSpace(errb.String()))
		}
		return out.String(), fmt.Errorf("%s %s failed: %w", name, strings.Join(args, " "), err)
	}
	return out.String(), nil
}

func parseInspect(out, fallbackName string) (Info, error) {
	var v any
	if err := json.Unmarshal([]byte(out), &v); err != nil {
		return Info{}, err
	}
	if arr, ok := v.([]any); ok && len(arr) > 0 {
		v = arr[0]
	}
	m, ok := v.(map[string]any)
	if !ok {
		return Info{}, errors.New("unexpected inspect JSON")
	}
	info := Info{Name: fallbackName}
	info.Labels = findStringMap(m, "labels")
	walk(m, func(path []string, val any) {
		key := strings.ToLower(path[len(path)-1])
		s, _ := val.(string)
		switch key {
		case "id", "name":
			if info.Name == "" && s != "" {
				info.Name = s
			}
		case "image", "imagename":
			if info.Image == "" {
				info.Image = s
			}
		case "status", "state":
			if info.State == "" {
				info.State = normalizeState(s)
			}
		case "ipaddress", "address", "ipv4address":
			if info.IP == "" && looksIPv4(s) {
				info.IP = strings.Split(s, "/")[0]
			}
		case "cpus":
			if info.CPUs == "" {
				info.CPUs = fmt.Sprint(val)
			}
		case "memory":
			if info.Memory == "" {
				info.Memory = fmt.Sprint(val)
			}
		}
	})
	if info.State == "" {
		info.State = StateUnknown
	}
	return info, nil
}

func findStringMap(value any, wantKey string) map[string]string {
	switch x := value.(type) {
	case map[string]any:
		for key, child := range x {
			if strings.EqualFold(key, wantKey) {
				if raw, ok := child.(map[string]any); ok {
					out := make(map[string]string, len(raw))
					for label, value := range raw {
						if text, ok := value.(string); ok {
							out[label] = text
						}
					}
					return out
				}
			}
			if found := findStringMap(child, wantKey); found != nil {
				return found
			}
		}
	case []any:
		for _, child := range x {
			if found := findStringMap(child, wantKey); found != nil {
				return found
			}
		}
	}
	return nil
}

func parseList(out string) []Info {
	var arr []map[string]any
	if err := json.Unmarshal([]byte(out), &arr); err != nil {
		return nil
	}
	infos := make([]Info, 0, len(arr))
	for _, m := range arr {
		info := Info{}
		walk(m, func(path []string, val any) {
			key := strings.ToLower(path[len(path)-1])
			s, _ := val.(string)
			switch key {
			case "id", "name":
				if info.Name == "" {
					info.Name = s
				}
			case "image", "imagename":
				if info.Image == "" {
					info.Image = s
				}
			case "status", "state":
				if info.State == "" {
					info.State = normalizeState(s)
				}
			case "ipaddress", "address", "ipv4address":
				if info.IP == "" && looksIPv4(s) {
					info.IP = strings.Split(s, "/")[0]
				}
			}
		})
		if info.State == "" {
			info.State = StateUnknown
		}
		infos = append(infos, info)
	}
	return infos
}

func walk(v any, fn func([]string, any)) {
	var rec func([]string, any)
	rec = func(path []string, cur any) {
		switch x := cur.(type) {
		case map[string]any:
			for k, v := range x {
				rec(append(path, k), v)
			}
		case []any:
			for _, v := range x {
				rec(path, v)
			}
		default:
			if len(path) > 0 {
				fn(path, cur)
			}
		}
	}
	rec(nil, v)
}

func containsExactString(v any, want string) bool {
	switch x := v.(type) {
	case map[string]any:
		for _, value := range x {
			if containsExactString(value, want) {
				return true
			}
		}
	case []any:
		for _, value := range x {
			if containsExactString(value, want) {
				return true
			}
		}
	case string:
		return x == want
	}
	return false
}

func normalizeState(s string) State {
	switch strings.ToLower(s) {
	case "running":
		return StateRunning
	case "stopped", "exited", "created":
		return StateStopped
	case "":
		return StateUnknown
	default:
		if strings.Contains(strings.ToLower(s), "running") {
			return StateRunning
		}
		return StateStopped
	}
}

func looksIPv4(s string) bool {
	parts := strings.Split(strings.Split(s, "/")[0], ".")
	if len(parts) != 4 {
		return false
	}
	for _, p := range parts {
		if p == "" {
			return false
		}
	}
	return true
}

func isNotFound(err error) bool {
	msg := strings.ToLower(err.Error())
	return strings.Contains(msg, "not found") || strings.Contains(msg, "no such")
}
