package runtime

import (
	"context"
	"os"
	"path/filepath"
	"reflect"
	"strings"
	"testing"
)

func TestParseImageListMatchesOnlyConfigurationName(t *testing.T) {
	payload := `[{"id":"sunaba-base:1.2","configuration":{"name":"sunaba-base:1.20"},"variants":[]}]`
	if exists, err := parseImageList(payload, "sunaba-base:1.2"); err != nil || exists {
		t.Fatal("partial image tag matched")
	}
	if exists, err := parseImageList(payload, "sunaba-base:1.20"); err != nil || !exists {
		t.Fatalf("exact image tag did not match: exists=%t error=%v", exists, err)
	}
	if _, err := parseImageList(`[{"configuration":{"name":"ok","name":"other"}}]`, "ok"); err == nil {
		t.Fatal("duplicate image schema key was accepted")
	}
}

func TestCreateArgsForSecureSocketOnlyContainer(t *testing.T) {
	spec := ContainerSpec{
		Name:     "sunaba-test-project",
		Image:    "example.invalid/image@sha256:abc",
		CPUs:     2,
		Memory:   "2G",
		Ulimits:  map[string]RLimit{"nproc": {Soft: 64, Hard: 64}, "fsize": {Soft: 1024, Hard: 1024}},
		Networks: []string{"none"},
		NoDNS:    true,
		Init:     true,
		CapDrop:  []string{"NET_RAW"},
		Mounts: []Mount{{
			Type: "socket", Source: "/private/tmp/gateway.sock", Target: "/run/sunaba/model.sock",
		}},
		Sockets: []PublishedSocket{{HostPath: "/private/tmp/attach.sock", GuestPath: "/run/sunaba/attach.sock"}},
		Env:     map[string]string{"Z": "last", "A": "first"},
		Labels:  map[string]string{"z": "last", "a": "first"},
		Args:    []string{"sleep", "infinity"},
	}
	want := []string{
		"run", "--detach", "--name", "sunaba-test-project",
		"--cpus", "2", "--memory", "2G", "--ulimit", "fsize=1024:1024", "--ulimit", "nproc=64:64", "--network", "none", "--no-dns", "--init", "--cap-drop", "NET_RAW",
		"--volume", "/private/tmp/gateway.sock:/run/sunaba/model.sock",
		"--publish-socket", "/private/tmp/attach.sock:/run/sunaba/attach.sock",
		"--env", "A=first", "--env", "Z=last", "--label", "a=first", "--label", "z=last",
		"example.invalid/image@sha256:abc", "sleep", "infinity",
	}
	if got := createArgs(spec); !reflect.DeepEqual(got, want) {
		t.Fatalf("createArgs() = %#v\nwant %#v", got, want)
	}
}

func TestStopArgsUseBoundedGracePeriod(t *testing.T) {
	want := []string{"stop", "--time", "1", "sunaba-test-project"}
	if got := stopArgs("sunaba-test-project"); !reflect.DeepEqual(got, want) {
		t.Fatalf("stopArgs() = %#v, want %#v", got, want)
	}
}

func TestParseInspectLabels(t *testing.T) {
	info, err := parseInspect(`[{
		"id": "sunaba-test",
		"configuration": {
			"id": "sunaba-test",
			"image": {"reference": "sunaba-base:test"},
			"labels": {"dev.sunaba.test": "run-1"},
			"resources": {"cpus": 2, "memoryInBytes": 2147483648},
			"nested": {"id": "attacker", "state": "stopped"}
		},
		"status": {"state": "running", "networks": [{"ipv4Address": "192.168.64.3/24"}]}
	}]`, "sunaba-test")
	if err != nil {
		t.Fatal(err)
	}
	if info.Name != "sunaba-test" || info.State != StateRunning || info.Image != "sunaba-base:test" || info.IP != "192.168.64.3" || info.CPUs != "2" || info.Memory != "2147483648" || info.Labels["dev.sunaba.test"] != "run-1" {
		t.Fatalf("info=%+v", info)
	}
}

func TestParseListPreservesOwnershipLabels(t *testing.T) {
	items, err := parseList(`[{
		"id": "sunaba-project-session",
		"configuration": {"id": "sunaba-project-session", "image": {"reference": "sunaba-base:test"}, "labels": {
			"dev.sunaba.owner": "sunaba-supervisor",
			"dev.sunaba.project": "project",
			"dev.sunaba.session": "session"
		}, "resources": {"cpus": 2, "memoryInBytes": 2147483648}},
		"status": {"state": "running", "networks": []}
	}]`)
	if err != nil || len(items) != 1 || items[0].Name != "sunaba-project-session" || items[0].State != StateRunning || items[0].Labels["dev.sunaba.owner"] != "sunaba-supervisor" {
		t.Fatalf("parsed list=%+v error=%v", items, err)
	}
}

func TestAppleContainerParserRejectsSchemaDriftAndAmbiguity(t *testing.T) {
	valid := `[{"id":"sunaba-test","configuration":{"id":"sunaba-test","image":{"reference":"sunaba-base:test"},"labels":{},"resources":{"cpus":2,"memoryInBytes":2147483648}},"status":{"state":"running","networks":[]}}]`
	tests := map[string]string{
		"malformed":         `[`,
		"null list":         `null`,
		"missing identity":  `[{"configuration":{"id":"sunaba-test","image":{"reference":"sunaba-base:test"},"labels":{},"resources":{"cpus":2,"memoryInBytes":2147483648}},"status":{"state":"running","networks":[]}}]`,
		"identity mismatch": strings.Replace(valid, `"id":"sunaba-test","image"`, `"id":"other","image"`, 1),
		"unknown state":     strings.Replace(valid, `"state":"running"`, `"state":"paused"`, 1),
		"duplicate field":   strings.Replace(valid, `"state":"running"`, `"state":"running","state":"stopped"`, 1),
	}
	for name, payload := range tests {
		t.Run(name, func(t *testing.T) {
			if _, err := parseList(payload); err == nil {
				t.Fatal("unsafe Apple Container JSON was accepted")
			}
		})
	}
	if _, err := parseInspect(valid, "different-name"); err == nil {
		t.Fatal("inspect fallback identity mismatch was accepted")
	}
}

func TestExportRejectsUnsafeOutputBeforeRuntimeAccess(t *testing.T) {
	rt := NewAppleContainer(false)
	if err := rt.Export(context.Background(), "other-container", "/private/tmp/sunaba-test/rootfs.tar"); err == nil {
		t.Fatal("non-sunaba container was accepted")
	}
	if err := rt.Export(context.Background(), "sunaba-test", "relative.tar"); err == nil {
		t.Fatal("relative export path was accepted")
	}
}

func TestExportRejectsSymlinkQuarantineBeforeRuntimeAccess(t *testing.T) {
	root := t.TempDir()
	target := filepath.Join(root, "target")
	if err := os.Mkdir(target, 0700); err != nil {
		t.Fatal(err)
	}
	quarantine := filepath.Join(root, "sunaba-link")
	if err := os.Symlink(target, quarantine); err != nil {
		t.Fatal(err)
	}
	if err := NewAppleContainer(false).Export(context.Background(), "sunaba-test", filepath.Join(quarantine, "rootfs.tar")); err == nil {
		t.Fatal("symlink quarantine was accepted")
	}
}
