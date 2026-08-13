package runtime

import (
	"net"
	"os"
	"path/filepath"
	"testing"

	"sunaba/internal/testutil"
)

func TestValidateSecureSessionSpec(t *testing.T) {
	policy, spec, closeSocket := secureFixture(t)
	defer closeSocket()
	if err := ValidateSecureSessionSpec(spec, policy); err != nil {
		t.Fatal(err)
	}
}

func TestValidateDevSessionSpecUsesExactDedicatedNetwork(t *testing.T) {
	policy, spec, closeSocket := secureFixture(t)
	defer closeSocket()
	policy.Mode = "dev"
	policy.NetworkName = "sunaba-project-test-net"
	spec.Networks = []string{policy.NetworkName}
	spec.NoDNS = false
	spec.Labels["dev.sunaba.mode"] = "dev"
	digest, err := policy.Digest()
	if err != nil {
		t.Fatal(err)
	}
	spec.Labels["dev.sunaba.policy-digest"] = digest
	if err := ValidateSecureSessionSpec(spec, policy); err != nil {
		t.Fatal(err)
	}
	for _, network := range []string{"default", "sunaba-other-test-net", "none"} {
		mutated := cloneContainerSpec(spec)
		mutated.Networks = []string{network}
		if err := ValidateSecureSessionSpec(mutated, policy); err == nil {
			t.Fatalf("dev network %q was accepted", network)
		}
	}
	mutated := cloneContainerSpec(spec)
	mutated.NoDNS = true
	if err := ValidateSecureSessionSpec(mutated, policy); err == nil {
		t.Fatal("dev network with DNS disabled was accepted")
	}
}

func TestValidateSecureSessionSpecFailsClosed(t *testing.T) {
	policy, valid, closeSocket := secureFixture(t)
	defer closeSocket()
	tests := []struct {
		name   string
		mutate func(*ContainerSpec)
	}{
		{name: "default network", mutate: func(spec *ContainerSpec) { spec.Networks = []string{"default"} }},
		{name: "extra network", mutate: func(spec *ContainerSpec) { spec.Networks = []string{"none", "default"} }},
		{name: "dns", mutate: func(spec *ContainerSpec) { spec.NoDNS = false }},
		{name: "missing signal-forwarding init", mutate: func(spec *ContainerSpec) { spec.Init = false }},
		{name: "host directory mount", mutate: func(spec *ContainerSpec) {
			spec.Mounts = append(spec.Mounts, Mount{Type: "bind", Source: "/tmp", Target: "/host"})
		}},
		{name: "other project socket", mutate: func(spec *ContainerSpec) {
			spec.Mounts[0].Source = filepath.Join(filepath.Dir(policy.SessionRoot), "other.sock")
		}},
		{name: "extra published socket", mutate: func(spec *ContainerSpec) {
			spec.Sockets = append(spec.Sockets, PublishedSocket{HostPath: filepath.Join(policy.SessionRoot, "other.sock"), GuestPath: "/run/other.sock"})
		}},
		{name: "env file", mutate: func(spec *ContainerSpec) { spec.EnvFiles = []string{"/tmp/secret.env"} }},
		{name: "inline env", mutate: func(spec *ContainerSpec) { spec.Env = map[string]string{"TOKEN": "secret"} }},
		{name: "missing hard limit", mutate: func(spec *ContainerSpec) { delete(spec.Ulimits, "nproc") }},
		{name: "raised hard limit", mutate: func(spec *ContainerSpec) { spec.Ulimits["fsize"] = RLimit{Soft: 1 << 30, Hard: 1 << 30} }},
		{name: "extra capability", mutate: func(spec *ContainerSpec) { spec.CapAdd = []string{"SYS_ADMIN", "ALL"} }},
		{name: "bootstrap", mutate: func(spec *ContainerSpec) { spec.Args = []string{"-lc", "curl example.com"} }},
		{name: "mode label", mutate: func(spec *ContainerSpec) { spec.Labels["dev.sunaba.mode"] = "dev" }},
		{name: "policy digest", mutate: func(spec *ContainerSpec) { spec.Labels["dev.sunaba.policy-digest"] = "forged" }},
	}
	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			spec := cloneContainerSpec(valid)
			tc.mutate(&spec)
			if err := ValidateSecureSessionSpec(spec, policy); err == nil {
				t.Fatal("unsafe secure session configuration was accepted")
			}
		})
	}
}

func TestSecureSessionPolicyRejectsSymlinkRoot(t *testing.T) {
	root := t.TempDir()
	target := filepath.Join(root, "sunaba-session-test")
	if err := os.Mkdir(target, 0700); err != nil {
		t.Fatal(err)
	}
	link := filepath.Join(t.TempDir(), "sunaba-session-test")
	if err := os.Symlink(target, link); err != nil {
		t.Fatal(err)
	}
	policy := SecureSessionPolicy{ProjectID: "project", SessionID: "test", Image: "image", SessionRoot: link}
	if _, err := policy.Digest(); err == nil {
		t.Fatal("symlink session root was accepted")
	}
}

func TestValidateSecureSessionSpecBindsOptionalWebGateway(t *testing.T) {
	policy, spec, closeModel := secureFixture(t)
	defer closeModel()
	webPath := filepath.Join(policy.SessionRoot, "web-gateway.sock")
	webListener, err := net.Listen("unix", webPath)
	if err != nil {
		t.Fatal(err)
	}
	defer webListener.Close()
	if err := os.Chmod(webPath, 0600); err != nil {
		t.Fatal(err)
	}
	policy.WebGateway = true
	spec.Mounts = append(spec.Mounts, Mount{Type: "socket", Source: webPath, Target: SecureWebGatewayGuestPath})
	digest, err := policy.Digest()
	if err != nil {
		t.Fatal(err)
	}
	spec.Labels["dev.sunaba.policy-digest"] = digest
	if err := ValidateSecureSessionSpec(spec, policy); err != nil {
		t.Fatal(err)
	}
	spec.Mounts[1].Source = filepath.Join(policy.SessionRoot, "other.sock")
	if err := ValidateSecureSessionSpec(spec, policy); err == nil {
		t.Fatal("unbound Web Gateway socket was accepted")
	}
}

func secureFixture(t *testing.T) (SecureSessionPolicy, ContainerSpec, func()) {
	t.Helper()
	parent := testutil.PrivateTempDir(t, "sunaba-secure-test-")
	sessionRoot := filepath.Join(parent, "sunaba-session-test")
	if err := os.Mkdir(sessionRoot, 0700); err != nil {
		t.Fatal(err)
	}
	canonicalRoot, err := filepath.EvalSymlinks(sessionRoot)
	if err != nil {
		t.Fatal(err)
	}
	gatewayPath := filepath.Join(canonicalRoot, "model-gateway.sock")
	listener, err := net.Listen("unix", gatewayPath)
	if err != nil {
		t.Fatal(err)
	}
	if err := os.Chmod(gatewayPath, 0600); err != nil {
		listener.Close()
		t.Fatal(err)
	}
	policy := SecureSessionPolicy{
		ProjectID: "project", SessionID: "test", Image: "sunaba-base:test", SessionRoot: canonicalRoot,
		CPUs: 1, Memory: "2G", DiskBytes: 128 << 20, ProcessMax: 64, FileSizeMax: 128 << 20, OpenFileMax: 1024,
	}
	digest, err := policy.Digest()
	if err != nil {
		listener.Close()
		t.Fatal(err)
	}
	spec := ContainerSpec{
		Name: "sunaba-test", Image: policy.Image, CPUs: 1, Memory: "2G",
		Ulimits:  map[string]RLimit{"nproc": {Soft: 64, Hard: 64}, "fsize": {Soft: 128 << 20, Hard: 128 << 20}, "nofile": {Soft: 1024, Hard: 1024}},
		Networks: []string{"none"}, NoDNS: true, Init: true, CapAdd: []string{"SYS_ADMIN"},
		Entrypoint: "/bin/bash", Args: []string{"-lc", "exec tail -f /dev/null"},
		Mounts:  []Mount{{Type: "socket", Source: gatewayPath, Target: SecureGatewayGuestPath}},
		Sockets: []PublishedSocket{{HostPath: filepath.Join(canonicalRoot, "attach.sock"), GuestPath: SecureAttachGuestPath}},
		Labels: map[string]string{
			"dev.sunaba.owner": "sunaba-supervisor", "dev.sunaba.project": policy.ProjectID,
			"dev.sunaba.session": policy.SessionID, "dev.sunaba.mode": "secure",
			"dev.sunaba.policy-digest": digest,
		},
	}
	return policy, spec, func() { _ = listener.Close() }
}

func cloneContainerSpec(spec ContainerSpec) ContainerSpec {
	clone := spec
	clone.Networks = append([]string(nil), spec.Networks...)
	clone.CapAdd = append([]string(nil), spec.CapAdd...)
	clone.CapDrop = append([]string(nil), spec.CapDrop...)
	clone.Mounts = append([]Mount(nil), spec.Mounts...)
	clone.Sockets = append([]PublishedSocket(nil), spec.Sockets...)
	clone.EnvFiles = append([]string(nil), spec.EnvFiles...)
	clone.Ulimits = make(map[string]RLimit, len(spec.Ulimits))
	for key, value := range spec.Ulimits {
		clone.Ulimits[key] = value
	}
	clone.Labels = make(map[string]string, len(spec.Labels))
	for key, value := range spec.Labels {
		clone.Labels[key] = value
	}
	return clone
}
