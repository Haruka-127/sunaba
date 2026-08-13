package runtime

import (
	"bytes"
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"net/netip"
	"os"
	"os/exec"
	"path/filepath"
	"sort"
	"strings"
	"time"

	"sunaba/internal/boundedexec"
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
		return false, err
	}
	return parseImageList(out, tag)
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
	if spec.Init {
		args = append(args, "--init")
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
	_, err := r.output(ctx, "container", "start", name)
	return err
}

func (r *AppleContainer) Stop(ctx context.Context, name string) error {
	ctx, cancel := context.WithTimeout(ctx, r.timeout())
	defer cancel()
	_, err := r.output(ctx, "container", stopArgs(name)...)
	return err
}

func stopArgs(name string) []string {
	// Agent channels and capabilities are revoked before this call. Keep a
	// bounded SIGTERM grace period without paying Apple Container's five-second
	// default on every interactive pause.
	return []string{"stop", "--time", "1", name}
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
	_, err = r.output(ctx, "container", "export", "--output", output, name)
	return err
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
	return parseList(out)
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
	result, err := boundedexec.Capture(cmd, boundedexec.Limits{StdoutBytes: 16 << 20, StderrBytes: 1 << 20})
	if err != nil {
		return string(result.Stdout), fmt.Errorf("%s operation failed: %w", name, err)
	}
	return string(result.Stdout), nil
}

type appleContainerDocument struct {
	ID            string                       `json:"id"`
	Configuration *appleContainerConfiguration `json:"configuration"`
	Status        *appleContainerStatus        `json:"status"`
}

type appleContainerConfiguration struct {
	ID        string            `json:"id"`
	Image     appleImage        `json:"image"`
	Labels    map[string]string `json:"labels"`
	Resources appleResources    `json:"resources"`
}

type appleImage struct {
	Reference string `json:"reference"`
}

type appleResources struct {
	CPUs          int    `json:"cpus"`
	MemoryInBytes uint64 `json:"memoryInBytes"`
}

type appleContainerStatus struct {
	State    string         `json:"state"`
	Networks []appleNetwork `json:"networks"`
}

type appleNetwork struct {
	IPv4Address string `json:"ipv4Address"`
}

type appleImageListEntry struct {
	Configuration *struct {
		Name string `json:"name"`
	} `json:"configuration"`
}

func parseImageList(out, tag string) (bool, error) {
	if tag == "" {
		return false, fmt.Errorf("container image tag is required")
	}
	data := []byte(out)
	if err := rejectDuplicateJSONKeys(data); err != nil {
		return false, fmt.Errorf("cannot parse container image list JSON: %w", err)
	}
	var entries []appleImageListEntry
	if err := json.Unmarshal(data, &entries); err != nil {
		return false, fmt.Errorf("cannot parse container image list JSON: %w", err)
	}
	if entries == nil {
		return false, fmt.Errorf("container image list JSON must be an array")
	}
	for index, entry := range entries {
		if entry.Configuration == nil || entry.Configuration.Name == "" {
			return false, fmt.Errorf("container image list entry %d is missing configuration.name", index)
		}
		if entry.Configuration.Name == tag {
			return true, nil
		}
	}
	return false, nil
}

func parseInspect(out, expectedName string) (Info, error) {
	infos, err := parseContainerDocuments(out)
	if err != nil {
		return Info{}, err
	}
	if len(infos) != 1 || expectedName == "" || infos[0].Name != expectedName {
		return Info{}, fmt.Errorf("container inspect identity does not match %q", expectedName)
	}
	return infos[0], nil
}

func parseList(out string) ([]Info, error) {
	return parseContainerDocuments(out)
}

func parseContainerDocuments(out string) ([]Info, error) {
	data := []byte(out)
	if err := rejectDuplicateJSONKeys(data); err != nil {
		return nil, fmt.Errorf("cannot parse Apple Container JSON: %w", err)
	}
	var documents []appleContainerDocument
	if err := json.Unmarshal(data, &documents); err != nil {
		return nil, fmt.Errorf("cannot parse Apple Container JSON: %w", err)
	}
	if documents == nil {
		return nil, fmt.Errorf("Apple Container JSON must be an array")
	}
	infos := make([]Info, 0, len(documents))
	seen := make(map[string]struct{}, len(documents))
	for index, document := range documents {
		if document.Configuration == nil || document.Status == nil || document.ID == "" ||
			document.Configuration.ID == "" || document.ID != document.Configuration.ID ||
			document.Configuration.Image.Reference == "" || document.Configuration.Labels == nil ||
			document.Configuration.Resources.CPUs <= 0 || document.Configuration.Resources.MemoryInBytes == 0 ||
			document.Status.Networks == nil {
			return nil, fmt.Errorf("Apple Container entry %d is missing required identity, configuration, resources, or status", index)
		}
		if _, exists := seen[document.ID]; exists {
			return nil, fmt.Errorf("Apple Container list contains duplicate identity %q", document.ID)
		}
		seen[document.ID] = struct{}{}
		state, err := parseAppleContainerState(document.Status.State)
		if err != nil {
			return nil, fmt.Errorf("Apple Container %q: %w", document.ID, err)
		}
		ip, err := parseAppleContainerIP(document.Status.Networks)
		if err != nil {
			return nil, fmt.Errorf("Apple Container %q: %w", document.ID, err)
		}
		infos = append(infos, Info{
			Name: document.ID, Image: document.Configuration.Image.Reference, State: state, IP: ip,
			CPUs: fmt.Sprint(document.Configuration.Resources.CPUs), Memory: fmt.Sprint(document.Configuration.Resources.MemoryInBytes),
			Labels: document.Configuration.Labels,
		})
	}
	return infos, nil
}

func parseAppleContainerState(value string) (State, error) {
	switch value {
	case "running":
		return StateRunning, nil
	case "stopped":
		return StateStopped, nil
	default:
		return StateUnknown, fmt.Errorf("unsupported runtime state %q", value)
	}
}

func parseAppleContainerIP(networks []appleNetwork) (string, error) {
	ip := ""
	for _, network := range networks {
		prefix, err := netip.ParsePrefix(network.IPv4Address)
		if err != nil || !prefix.Addr().Is4() {
			return "", fmt.Errorf("invalid ipv4Address %q", network.IPv4Address)
		}
		candidate := prefix.Addr().String()
		if ip != "" && ip != candidate {
			return "", fmt.Errorf("multiple IPv4 addresses are ambiguous")
		}
		ip = candidate
	}
	return ip, nil
}

func rejectDuplicateJSONKeys(data []byte) error {
	decoder := json.NewDecoder(bytes.NewReader(data))
	decoder.UseNumber()
	var consume func() error
	consume = func() error {
		token, err := decoder.Token()
		if err != nil {
			return err
		}
		delimiter, ok := token.(json.Delim)
		if !ok {
			return nil
		}
		switch delimiter {
		case '{':
			seen := make(map[string]struct{})
			for decoder.More() {
				keyToken, err := decoder.Token()
				if err != nil {
					return err
				}
				key, ok := keyToken.(string)
				if !ok {
					return fmt.Errorf("JSON object key is not a string")
				}
				if _, exists := seen[key]; exists {
					return fmt.Errorf("duplicate JSON key %q", key)
				}
				seen[key] = struct{}{}
				if err := consume(); err != nil {
					return err
				}
			}
		case '[':
			for decoder.More() {
				if err := consume(); err != nil {
					return err
				}
			}
		default:
			return fmt.Errorf("unexpected JSON delimiter %q", delimiter)
		}
		_, err = decoder.Token()
		return err
	}
	if err := consume(); err != nil {
		return err
	}
	if _, err := decoder.Token(); !errors.Is(err, io.EOF) {
		if err == nil {
			return fmt.Errorf("multiple JSON values")
		}
		return err
	}
	return nil
}

func isNotFound(err error) bool {
	msg := strings.ToLower(err.Error())
	return strings.Contains(msg, "not found") || strings.Contains(msg, "no such")
}
