package firewall

import (
	"bytes"
	"context"
	"encoding/json"
	"errors"
	"fmt"
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
	Interface string `json:"interface"`
	Subnet    string `json:"subnet"`
	Gateway   string `json:"gateway"`
}

func GenerateRules(n Network) string {
	return fmt.Sprintf(`# Managed by sunaba. Do not edit.
pass in quick on %s inet proto udp from any port 68 to any port 67
pass in quick on %s inet proto { tcp udp } from %s to %s port 53
pass in quick on %s inet proto tcp from %s to self flags A/A
block drop in quick on %s inet from %s to self
`, n.Interface, n.Interface, n.Subnet, n.Gateway, n.Interface, n.Subnet, n.Interface, n.Subnet)
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
	if os.Geteuid() != 0 {
		return rerunWithSudo("enable")
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
	if err := os.MkdirAll(filepath.Dir(anchorPath), 0755); err != nil {
		return err
	}
	if err := os.WriteFile(anchorPath, []byte(GenerateRules(n)), 0644); err != nil {
		return err
	}
	if HasAnchorBlock(string(conf)) {
		if err := pfctl(ctx, "-a", "sunaba", "-nf", anchorPath); err != nil {
			return err
		}
		if err := pfctl(ctx, "-a", "sunaba", "-f", anchorPath); err != nil {
			return err
		}
	} else {
		next := EnsureAnchorBlock(string(conf))
		if err := os.WriteFile(pfConfPath, []byte(next), 0644); err != nil {
			return err
		}
		if err := pfctl(ctx, "-nf", pfConfPath); err != nil {
			return err
		}
		if err := pfctl(ctx, "-f", pfConfPath); err != nil {
			return err
		}
	}
	_ = pfctl(ctx, "-E")
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
	if err := os.WriteFile(pfConfPath, []byte(RemoveAnchorBlock(string(conf))), 0644); err != nil {
		return err
	}
	_ = os.Remove(anchorPath)
	if err := pfctl(ctx, "-nf", pfConfPath); err != nil {
		return err
	}
	return pfctl(ctx, "-f", pfConfPath)
}

func Status(ctx context.Context) (string, error) {
	c, cancel := context.WithTimeout(ctx, 15*time.Second)
	defer cancel()
	out, err := exec.CommandContext(c, "/sbin/pfctl", "-a", "sunaba", "-sr").CombinedOutput()
	if err != nil {
		return string(out), err
	}
	if strings.TrimSpace(string(out)) == "" {
		return "sunaba firewall: not loaded", nil
	}
	return "sunaba firewall: loaded\n" + string(out), nil
}

func IsLoaded(ctx context.Context) bool {
	out, err := Status(ctx)
	return err == nil && strings.Contains(out, "block drop")
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
	var subnet, gw string
	walk(arr[0], func(k string, v any) {
		if s, ok := v.(string); ok {
			switch strings.ToLower(k) {
			case "ipv4subnet":
				subnet = strings.ReplaceAll(s, "\\/", "/")
			case "ipv4gateway":
				gw = s
			}
		}
	})
	if subnet == "" || gw == "" {
		return Network{}, false
	}
	iface := interfaceForGateway(ctx, gw)
	if iface == "" {
		iface = "bridge100"
	}
	return Network{Interface: iface, Subnet: subnet, Gateway: gw}, true
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
