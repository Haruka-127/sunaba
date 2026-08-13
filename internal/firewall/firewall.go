package firewall

import (
	"bytes"
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"net"
	"os"
	"os/exec"
	"path/filepath"
	"regexp"
	"strings"
	"time"
)

const (
	beginMarker = "# BEGIN sunaba"
	endMarker   = "# END sunaba"
	anchorPath  = "/etc/pf.anchors/sunaba"
	pfConfPath  = "/etc/pf.conf"
	backupPath  = "/etc/pf.conf.sunaba.bak"
)

type Network struct {
	Interface  string `json:"interface,omitempty"`
	Subnet     string `json:"subnet"`
	Gateway    string `json:"gateway"`
	IPv6Subnet string `json:"ipv6_subnet"`
}

type livePFState struct {
	Enabled    bool
	MainAnchor bool
	IPv4Block  bool
	IPv6Block  bool
}

func (s livePFState) loaded() bool {
	return s.Enabled && s.MainAnchor && s.IPv4Block && s.IPv6Block
}

type fileSnapshot struct {
	data   []byte
	mode   os.FileMode
	exists bool
}

func GenerateRules(n Network) string {
	private4 := []string{"0.0.0.0/8", "10.0.0.0/8", "100.64.0.0/10", "127.0.0.0/8", "169.254.0.0/16", "172.16.0.0/12", "192.0.0.0/24", "192.0.2.0/24", "192.168.0.0/16", "198.18.0.0/15", "198.51.100.0/24", "203.0.113.0/24", "224.0.0.0/4", "240.0.0.0/4"}
	private6 := []string{"::/128", "::1/128", "64:ff9b:1::/48", "100::/64", "2001:db8::/32", "fc00::/7", "fe80::/10", "ff00::/8"}
	var rules strings.Builder
	rules.WriteString("# Managed by sunaba. Do not edit.\n")
	fmt.Fprintf(&rules, "pass in quick inet proto udp from %s port 68 to any port 67 keep state\n", n.Subnet)
	fmt.Fprintf(&rules, "pass in quick inet proto { tcp udp } from %s to %s port 53 keep state\n", n.Subnet, n.Gateway)
	fmt.Fprintf(&rules, "block drop in quick inet from %s to self\n", n.Subnet)
	for _, destination := range private4 {
		fmt.Fprintf(&rules, "block drop in quick inet from %s to %s\n", n.Subnet, destination)
	}
	fmt.Fprintf(&rules, "pass in quick inet from %s to any keep state\n", n.Subnet)
	fmt.Fprintf(&rules, "block drop out quick inet from any to %s\n", n.Subnet)
	fmt.Fprintf(&rules, "block drop in quick inet6 from %s to self\n", n.IPv6Subnet)
	for _, destination := range private6 {
		fmt.Fprintf(&rules, "block drop in quick inet6 from %s to %s\n", n.IPv6Subnet, destination)
	}
	fmt.Fprintf(&rules, "pass in quick inet6 from %s to any keep state\n", n.IPv6Subnet)
	fmt.Fprintf(&rules, "block drop out quick inet6 from any to %s\n", n.IPv6Subnet)
	return rules.String()
}

func GenerateQuiescedRules(n Network) string {
	return fmt.Sprintf("# Managed by sunaba. Dev export is quiesced. Do not edit.\nblock drop in quick inet from %s to any\nblock drop out quick inet from any to %s\nblock drop in quick inet6 from %s to any\nblock drop out quick inet6 from any to %s\n", n.Subnet, n.Subnet, n.IPv6Subnet, n.IPv6Subnet)
}

func ValidateNetwork(n Network) error {
	if n.Interface != "" && !regexp.MustCompile(`^[a-zA-Z0-9]+$`).MatchString(n.Interface) {
		return fmt.Errorf("invalid network interface %q", n.Interface)
	}
	subnetIP, _, err := net.ParseCIDR(n.Subnet)
	if err != nil {
		return fmt.Errorf("invalid network subnet %q: %w", n.Subnet, err)
	}
	if subnetIP.To4() == nil {
		return fmt.Errorf("invalid network subnet %q: only IPv4 is supported", n.Subnet)
	}
	if ip := net.ParseIP(n.Gateway); ip == nil || ip.To4() == nil {
		return fmt.Errorf("invalid network gateway %q", n.Gateway)
	}
	ipv6, parsed6, err := net.ParseCIDR(n.IPv6Subnet)
	if err != nil || ipv6.To4() != nil || parsed6.String() != n.IPv6Subnet {
		return fmt.Errorf("invalid network IPv6 subnet %q", n.IPv6Subnet)
	}
	return nil
}

func EnsureAnchorBlock(conf string) string {
	block := beginMarker + "\nanchor \"sunaba\"\nload anchor \"sunaba\" from \"" + anchorPath + "\"\n" + endMarker
	conf = RemoveAnchorBlock(conf)
	if strings.TrimSpace(conf) == "" {
		return block + "\n"
	}
	if !strings.HasSuffix(conf, "\n") {
		conf += "\n"
	}
	return conf + block + "\n"
}

func RemoveAnchorBlock(conf string) string {
	start := strings.Index(conf, beginMarker)
	if start < 0 {
		return conf
	}
	end := strings.Index(conf[start:], endMarker)
	if end < 0 {
		return conf
	}
	endAbs := start + end + len(endMarker)
	if endAbs < len(conf) && conf[endAbs] == '\n' {
		endAbs++
	}
	return strings.TrimRight(conf[:start]+conf[endAbs:], "\n") + "\n"
}

func HasAnchorBlock(conf string) bool {
	return strings.Contains(conf, beginMarker) &&
		strings.Contains(conf, `anchor "sunaba"`) &&
		strings.Contains(conf, `load anchor "sunaba" from "`+anchorPath+`"`) &&
		strings.Contains(conf, endMarker)
}

func Detect(ctx context.Context, stateRoot string, containerIP string) (Network, error) {
	if n, ok := networkInspect(ctx); ok {
		return n, cacheNetwork(stateRoot, n)
	}
	if containerIP != "" {
		if n, ok := fromIPAndIfconfig(ctx, containerIP); ok {
			return n, cacheNetwork(stateRoot, n)
		}
	}
	if n, err := readCached(stateRoot); err == nil {
		return n, nil
	}
	n := Network{Interface: "bridge100", Subnet: "192.168.64.0/24", Gateway: "192.168.64.1"}
	return n, cacheNetwork(stateRoot, n)
}

func Enable(ctx context.Context, n Network) error {
	if err := ValidateNetwork(n); err != nil {
		return err
	}
	if os.Geteuid() != 0 {
		return rerunEnableWithSudo(n)
	}
	conf, err := os.ReadFile(pfConfPath)
	if err != nil {
		return err
	}
	if _, err := os.Stat(backupPath); errors.Is(err, os.ErrNotExist) {
		if err := os.WriteFile(backupPath, conf, 0644); err != nil {
			return err
		}
	}
	oldAnchor, err := snapshotFile(anchorPath)
	if err != nil {
		return err
	}
	rollbackAnchor := func() { _ = restoreFile(anchorPath, oldAnchor) }
	if err := writeValidatedFile(anchorPath, []byte(GenerateRules(n)), 0644, func(path string) error {
		return pfctl(ctx, "-a", "sunaba", "-nf", path)
	}); err != nil {
		return err
	}
	mainChanged := false
	if HasAnchorBlock(string(conf)) {
		live, err := inspectLivePF(ctx, n)
		if err != nil {
			rollbackAnchor()
			return err
		}
		if live.MainAnchor {
			if err := pfctl(ctx, "-a", "sunaba", "-f", anchorPath); err != nil {
				rollbackAnchor()
				return err
			}
		} else {
			if err := pfctl(ctx, "-nf", pfConfPath); err != nil {
				rollbackAnchor()
				return err
			}
			if err := pfctl(ctx, "-f", pfConfPath); err != nil {
				rollbackAnchor()
				return err
			}
		}
	} else {
		next := EnsureAnchorBlock(string(conf))
		if err := writeValidatedFile(pfConfPath, []byte(next), 0644, func(path string) error {
			return pfctl(ctx, "-nf", path)
		}); err != nil {
			rollbackAnchor()
			return err
		}
		mainChanged = true
		if err := pfctl(ctx, "-f", pfConfPath); err != nil {
			_ = os.WriteFile(pfConfPath, conf, 0644)
			rollbackAnchor()
			return err
		}
	}
	live, err := inspectLivePF(ctx, n)
	if err != nil {
		return err
	}
	if !live.Enabled {
		if err := pfctl(ctx, "-E"); err != nil {
			if mainChanged {
				_ = os.WriteFile(pfConfPath, conf, 0644)
			}
			rollbackAnchor()
			return err
		}
	}
	live, err = inspectLivePF(ctx, n)
	if err != nil || !live.loaded() {
		if err != nil {
			return fmt.Errorf("cannot verify enabled firewall: %w", err)
		}
		return fmt.Errorf("cannot verify enabled firewall: enabled=%t main-anchor=%t ipv4-block=%t ipv6-block=%t", live.Enabled, live.MainAnchor, live.IPv4Block, live.IPv6Block)
	}
	return nil
}

func Disable(ctx context.Context) error {
	if os.Geteuid() != 0 {
		return rerunWithSudo("disable")
	}
	conf, err := os.ReadFile(pfConfPath)
	if err != nil {
		return err
	}
	next := []byte(RemoveAnchorBlock(string(conf)))
	if err := writeValidatedFile(pfConfPath, next, 0644, func(path string) error {
		return pfctl(ctx, "-nf", path)
	}); err != nil {
		return err
	}
	if err := pfctl(ctx, "-f", pfConfPath); err != nil {
		_ = os.WriteFile(pfConfPath, conf, 0644)
		return err
	}
	if err := os.Remove(anchorPath); err != nil && !errors.Is(err, os.ErrNotExist) {
		return err
	}
	return nil
}

// Quiesce atomically replaces an already-installed sunaba anchor with a
// deny-all policy for the exact dev source subnets. It intentionally refuses
// to create or repair the main pf anchor; Enable must have established and
// verified that boundary first.
func Quiesce(ctx context.Context, n Network) error {
	if err := ValidateNetwork(n); err != nil {
		return err
	}
	if os.Geteuid() != 0 {
		return rerunQuiesceWithSudo(n)
	}
	conf, err := os.ReadFile(pfConfPath)
	if err != nil || !HasAnchorBlock(string(conf)) {
		return fmt.Errorf("refusing to quiesce without the verified sunaba main anchor")
	}
	oldAnchor, err := snapshotFile(anchorPath)
	if err != nil || !oldAnchor.exists {
		return fmt.Errorf("refusing to quiesce without the active sunaba child anchor")
	}
	rollback := func() {
		_ = restoreFile(anchorPath, oldAnchor)
		_ = pfctl(context.Background(), "-a", "sunaba", "-f", anchorPath)
	}
	if err := writeValidatedFile(anchorPath, []byte(GenerateQuiescedRules(n)), 0644, func(path string) error {
		return pfctl(ctx, "-a", "sunaba", "-nf", path)
	}); err != nil {
		return err
	}
	if err := pfctl(ctx, "-a", "sunaba", "-f", anchorPath); err != nil {
		rollback()
		return err
	}
	if err := verifyQuiesced(ctx, n); err != nil {
		rollback()
		return err
	}
	return nil
}

func verifyQuiesced(ctx context.Context, n Network) error {
	info, err := pfctlOutput(ctx, "-s", "info")
	if err != nil || !strings.Contains(strings.ToLower(info), "status: enabled") {
		return fmt.Errorf("cannot verify quiesced firewall status")
	}
	mainRules, err := pfctlOutput(ctx, "-sr")
	if err != nil || !strings.Contains(mainRules, `anchor "sunaba"`) {
		return fmt.Errorf("cannot verify quiesced main anchor")
	}
	childRules, err := pfctlOutput(ctx, "-a", "sunaba", "-sr")
	if err != nil {
		return err
	}
	configured, err := os.ReadFile(anchorPath)
	if err != nil {
		return err
	}
	for _, item := range []struct{ family, source string }{{"inet", n.Subnet}, {"inet6", n.IPv6Subnet}} {
		if !hasBlockToAny(string(configured), item.family, item.source) || !hasBlockToAny(childRules, item.family, item.source) {
			return fmt.Errorf("cannot verify quiesced %s source policy", item.family)
		}
	}
	return nil
}

func hasBlockToAny(rules, family, source string) bool {
	for _, line := range strings.Split(rules, "\n") {
		fields := strings.Fields(line)
		if len(fields) >= 8 && fields[0] == "block" && fields[1] == "drop" && containsFieldSequence(fields, family, "from", source, "to", "any") {
			return true
		}
	}
	return false
}

func Status(ctx context.Context) (string, error) {
	n, ok := networkInspect(ctx)
	if !ok {
		return "sunaba firewall: status unavailable", fmt.Errorf("cannot inspect default container network")
	}
	live, err := inspectLivePF(ctx, n)
	if err != nil {
		return "sunaba firewall: status unavailable", err
	}
	if live.loaded() {
		return "sunaba firewall: loaded", nil
	}
	return fmt.Sprintf("sunaba firewall: not loaded (pf-enabled=%t main-anchor=%t ipv4-block=%t ipv6-block=%t)", live.Enabled, live.MainAnchor, live.IPv4Block, live.IPv6Block), nil
}

func IsLoaded(ctx context.Context) bool {
	n, ok := networkInspect(ctx)
	if !ok {
		return false
	}
	live, err := inspectLivePF(ctx, n)
	return err == nil && live.loaded()
}

func inspectLivePF(ctx context.Context, n Network) (livePFState, error) {
	info, err := pfctlOutput(ctx, "-s", "info")
	if err != nil {
		return livePFState{}, err
	}
	mainRules, err := pfctlOutput(ctx, "-sr")
	if err != nil {
		return livePFState{}, err
	}
	childRules, err := pfctlOutput(ctx, "-a", "sunaba", "-sr")
	if err != nil {
		return livePFState{}, err
	}
	configuredRules, err := os.ReadFile(anchorPath)
	if err != nil {
		return livePFState{}, fmt.Errorf("cannot read %s: %w", anchorPath, err)
	}
	return parseLivePFState(info, mainRules, childRules, string(configuredRules), n), nil
}

func parseLivePFState(info, mainRules, childRules, configuredRules string, n Network) livePFState {
	return livePFState{
		Enabled:    strings.Contains(strings.ToLower(info), "status: enabled"),
		MainAnchor: strings.Contains(mainRules, `anchor "sunaba"`),
		IPv4Block: hasConfiguredBlockRule(configuredRules, n.Interface, "inet", n.Subnet) &&
			hasLiveBlockRule(childRules, n.Interface, "inet", n.Subnet),
		IPv6Block: hasConfiguredBlockRule(configuredRules, n.Interface, "inet6", n.IPv6Subnet) &&
			hasLiveBlockRule(childRules, n.Interface, "inet6", n.IPv6Subnet),
	}
}

func hasConfiguredBlockRule(rules, iface, family, source string) bool {
	return findBlockRule(rules, iface, family, source, true)
}

func hasLiveBlockRule(rules, iface, family, source string) bool {
	return findBlockRule(rules, iface, family, source, false)
}

func findBlockRule(rules, iface, family, source string, requireSelf bool) bool {
	for _, line := range strings.Split(rules, "\n") {
		fields := strings.Fields(line)
		if len(fields) < 7 || fields[0] != "block" || fields[1] != "drop" {
			continue
		}
		matches := containsFieldSequence(fields, family, "from", source)
		if iface != "" {
			matches = matches && containsFieldSequence(fields, "on", iface)
		}
		if requireSelf {
			matches = matches && (containsFieldSequence(fields, "to", "self") || containsFieldSequence(fields, "to", "(self)"))
		}
		if matches {
			return true
		}
	}
	return false
}

func containsFieldSequence(fields []string, sequence ...string) bool {
	if len(sequence) == 0 || len(sequence) > len(fields) {
		return false
	}
	for i := 0; i <= len(fields)-len(sequence); i++ {
		matched := true
		for j := range sequence {
			if fields[i+j] != sequence[j] {
				matched = false
				break
			}
		}
		if matched {
			return true
		}
	}
	return false
}

func rerunWithSudo(action string) error {
	exe, err := os.Executable()
	if err != nil {
		return err
	}
	args := sudoRerunArgs(exe, action, os.Args)
	cmd := exec.Command("sudo", args...)
	cmd.Stdin = os.Stdin
	cmd.Stdout = os.Stdout
	cmd.Stderr = os.Stderr
	return cmd.Run()
}

func rerunEnableWithSudo(n Network) error {
	exe, err := os.Executable()
	if err != nil {
		return err
	}
	args := []string{exe, "firewall", "enable", "--subnet", n.Subnet, "--gateway", n.Gateway, "--ipv6-subnet", n.IPv6Subnet}
	if n.Interface != "" {
		args = append(args, "--interface", n.Interface)
	}
	cmd := exec.Command("sudo", args...)
	cmd.Stdin = os.Stdin
	cmd.Stdout = os.Stdout
	cmd.Stderr = os.Stderr
	return cmd.Run()
}

func rerunQuiesceWithSudo(n Network) error {
	exe, err := os.Executable()
	if err != nil {
		return err
	}
	args := []string{exe, "firewall", "quiesce", "--subnet", n.Subnet, "--gateway", n.Gateway, "--ipv6-subnet", n.IPv6Subnet}
	cmd := exec.Command("sudo", args...)
	cmd.Stdin = os.Stdin
	cmd.Stdout = os.Stdout
	cmd.Stderr = os.Stderr
	return cmd.Run()
}

func sudoRerunArgs(exe, action string, argv []string) []string {
	args := []string{exe, "firewall", action}
	for i := 1; i+1 < len(argv); i++ {
		if argv[i] == "firewall" && argv[i+1] == action {
			return append(args, argv[i+2:]...)
		}
	}
	return args
}

func pfctl(ctx context.Context, args ...string) error {
	c, cancel := context.WithTimeout(ctx, 30*time.Second)
	defer cancel()
	cmd := exec.CommandContext(c, "/sbin/pfctl", args...)
	var errb bytes.Buffer
	cmd.Stderr = &errb
	cmd.Stdout = os.Stdout
	if err := cmd.Run(); err != nil {
		return fmt.Errorf("pfctl %s failed: %w: %s", strings.Join(args, " "), err, strings.TrimSpace(errb.String()))
	}
	return nil
}

func pfctlOutput(ctx context.Context, args ...string) (string, error) {
	c, cancel := context.WithTimeout(ctx, 30*time.Second)
	defer cancel()
	out, err := exec.CommandContext(c, "/sbin/pfctl", args...).CombinedOutput()
	if err != nil {
		return string(out), fmt.Errorf("pfctl %s failed: %w: %s", strings.Join(args, " "), err, strings.TrimSpace(string(out)))
	}
	return string(out), nil
}

func snapshotFile(path string) (fileSnapshot, error) {
	info, err := os.Stat(path)
	if errors.Is(err, os.ErrNotExist) {
		return fileSnapshot{}, nil
	}
	if err != nil {
		return fileSnapshot{}, err
	}
	b, err := os.ReadFile(path)
	if err != nil {
		return fileSnapshot{}, err
	}
	return fileSnapshot{data: b, mode: info.Mode().Perm(), exists: true}, nil
}

func restoreFile(path string, snapshot fileSnapshot) error {
	if !snapshot.exists {
		if err := os.Remove(path); err != nil && !errors.Is(err, os.ErrNotExist) {
			return err
		}
		return nil
	}
	return os.WriteFile(path, snapshot.data, snapshot.mode)
}

func writeValidatedFile(path string, data []byte, mode os.FileMode, validate func(string) error) error {
	if err := os.MkdirAll(filepath.Dir(path), 0755); err != nil {
		return err
	}
	tmp, err := os.CreateTemp(filepath.Dir(path), ".sunaba-"+filepath.Base(path)+"-*")
	if err != nil {
		return err
	}
	tmpPath := tmp.Name()
	defer os.Remove(tmpPath)
	if err := tmp.Chmod(mode); err != nil {
		tmp.Close()
		return err
	}
	if _, err := io.Copy(tmp, bytes.NewReader(data)); err != nil {
		tmp.Close()
		return err
	}
	if err := tmp.Sync(); err != nil {
		tmp.Close()
		return err
	}
	if err := tmp.Close(); err != nil {
		return err
	}
	if err := validate(tmpPath); err != nil {
		return err
	}
	if err := os.Rename(tmpPath, path); err != nil {
		return err
	}
	directory, err := os.Open(filepath.Dir(path))
	if err != nil {
		return err
	}
	return errors.Join(directory.Sync(), directory.Close())
}

func networkInspect(ctx context.Context) (Network, bool) {
	c, cancel := context.WithTimeout(ctx, 10*time.Second)
	defer cancel()
	out, err := exec.CommandContext(c, "container", "network", "inspect", "default").Output()
	if err != nil {
		return Network{}, false
	}
	var arr []map[string]any
	if err := json.Unmarshal(out, &arr); err != nil || len(arr) == 0 {
		return Network{}, false
	}
	var subnet, gw, ipv6Subnet string
	walk(arr[0], func(k string, v any) {
		if s, ok := v.(string); ok {
			switch strings.ToLower(k) {
			case "ipv4subnet":
				subnet = strings.ReplaceAll(s, "\\/", "/")
			case "ipv4gateway":
				gw = s
			case "ipv6subnet":
				ipv6Subnet = strings.ReplaceAll(s, "\\/", "/")
			}
		}
	})
	if subnet == "" || gw == "" || ipv6Subnet == "" {
		return Network{}, false
	}
	iface := interfaceForGateway(ctx, gw)
	if iface == "" {
		iface = "bridge100"
	}
	return Network{Interface: iface, Subnet: subnet, Gateway: gw, IPv6Subnet: ipv6Subnet}, true
}

func fromIPAndIfconfig(ctx context.Context, ip string) (Network, bool) {
	parsed := net.ParseIP(ip)
	if parsed == nil {
		return Network{}, false
	}
	p4 := parsed.To4()
	if p4 == nil {
		return Network{}, false
	}
	gw := fmt.Sprintf("%d.%d.%d.1", p4[0], p4[1], p4[2])
	subnet := fmt.Sprintf("%d.%d.%d.0/24", p4[0], p4[1], p4[2])
	iface := interfaceForGateway(ctx, gw)
	if iface == "" {
		iface = "bridge100"
	}
	return Network{Interface: iface, Subnet: subnet, Gateway: gw}, true
}

func interfaceForGateway(ctx context.Context, gw string) string {
	c, cancel := context.WithTimeout(ctx, 10*time.Second)
	defer cancel()
	out, err := exec.CommandContext(c, "ifconfig").Output()
	if err != nil {
		return ""
	}
	re := regexp.MustCompile(`(?m)^([a-zA-Z0-9]+):`)
	var current string
	for _, line := range strings.Split(string(out), "\n") {
		if m := re.FindStringSubmatch(line); m != nil {
			current = m[1]
		}
		if current != "" && strings.Contains(line, gw) {
			return current
		}
	}
	return ""
}

func cacheNetwork(root string, n Network) error {
	if err := os.MkdirAll(root, 0700); err != nil {
		return err
	}
	b, err := json.MarshalIndent(n, "", "  ")
	if err != nil {
		return err
	}
	return os.WriteFile(filepath.Join(root, "network.json"), append(b, '\n'), 0600)
}

func readCached(root string) (Network, error) {
	var n Network
	b, err := os.ReadFile(filepath.Join(root, "network.json"))
	if err != nil {
		return n, err
	}
	return n, json.Unmarshal(b, &n)
}

func walk(v any, fn func(string, any)) {
	switch x := v.(type) {
	case map[string]any:
		for k, v := range x {
			fn(k, v)
			walk(v, fn)
		}
	case []any:
		for _, v := range x {
			walk(v, fn)
		}
	}
}
