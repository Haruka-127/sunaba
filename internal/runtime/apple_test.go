package runtime

import (
	"encoding/json"
	"reflect"
	"testing"
)

func TestContainsExactImageTag(t *testing.T) {
	var payload any
	if err := json.Unmarshal([]byte(`[{"configuration":{"name":"sunaba-base:1.20"}}]`), &payload); err != nil {
		t.Fatal(err)
	}
	if containsExactString(payload, "sunaba-base:1.2") {
		t.Fatal("partial image tag matched")
	}
	if !containsExactString(payload, "sunaba-base:1.20") {
		t.Fatal("exact image tag did not match")
	}
}

func TestCreateArgsForSecureSocketOnlyContainer(t *testing.T) {
	spec := ContainerSpec{
		Name:     "sunaba-test-project",
		Image:    "example.invalid/image@sha256:abc",
		CPUs:     2,
		Memory:   "2G",
		Networks: []string{"none"},
		NoDNS:    true,
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
		"--cpus", "2", "--memory", "2G", "--network", "none", "--no-dns", "--cap-drop", "NET_RAW",
		"--volume", "/private/tmp/gateway.sock:/run/sunaba/model.sock",
		"--publish-socket", "/private/tmp/attach.sock:/run/sunaba/attach.sock",
		"--env", "A=first", "--env", "Z=last", "--label", "a=first", "--label", "z=last",
		"example.invalid/image@sha256:abc", "sleep", "infinity",
	}
	if got := createArgs(spec); !reflect.DeepEqual(got, want) {
		t.Fatalf("createArgs() = %#v\nwant %#v", got, want)
	}
}

func TestParseInspectLabels(t *testing.T) {
	info, err := parseInspect(`{
		"configuration": {"labels": {"dev.sunaba.test": "run-1"}},
		"status": "running"
	}`, "sunaba-test")
	if err != nil {
		t.Fatal(err)
	}
	if info.Labels["dev.sunaba.test"] != "run-1" {
		t.Fatalf("labels=%v", info.Labels)
	}
}
