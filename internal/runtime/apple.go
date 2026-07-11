package runtime

import (
	"bytes"
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"os"
	"os/exec"
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
	ctx, cancel := context.WithTimeout(ctx, r.timeout())
	defer cancel()
	args := []string{"run", "--detach", "--name", spec.Name}
	if spec.CPUs > 0 {
		args = append(args, "--cpus", fmt.Sprint(spec.CPUs))
	}
	if spec.Memory != "" {
		args = append(args, "--memory", spec.Memory)
	}
	for _, m := range spec.Mounts {
		args = append(args, "--volume", m.Source+":"+m.Target)
	}
	for _, f := range spec.EnvFiles {
		args = append(args, "--env-file", f)
	}
	for k, v := range spec.Env {
		args = append(args, "--env", k+"="+v)
	}
	for k, v := range spec.Labels {
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
	return r.run(ctx, "container", args...)
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
