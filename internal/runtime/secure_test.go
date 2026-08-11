package runtime

import (
	"net"
	"os"
	"path/filepath"
	"testing"
)

func TestValidateSecureSessionSpec(t *testing.T) {
	policy, spec, closeSocket := secureFixture(t)
	defer closeSocket()
	if err := ValidateSecureSessionSpec(spec, policy); err != nil {
		t.Fatal(err)
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

func secureFixture(t *testing.T) (SecureSessionPolicy, ContainerSpec, func()) {
	t.Helper()
	parent, err := os.MkdirTemp("/private/tmp", "sunaba-secure-test-")
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = os.RemoveAll(parent) })
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
	policy := SecureSessionPolicy{ProjectID: "project", SessionID: "test", Image: "sunaba-base:test", SessionRoot: canonicalRoot}
	digest, err := policy.Digest()
	if err != nil {
		listener.Close()
		t.Fatal(err)
	}
	spec := ContainerSpec{
		Name: "sunaba-test", Image: policy.Image, CPUs: 1, Memory: "2G",
		Networks: []string{"none"}, NoDNS: true,
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
	clone.Mounts = append([]Mount(nil), spec.Mounts...)
	clone.Sockets = append([]PublishedSocket(nil), spec.Sockets...)
	clone.EnvFiles = append([]string(nil), spec.EnvFiles...)
	clone.Labels = make(map[string]string, len(spec.Labels))
	for key, value := range spec.Labels {
		clone.Labels[key] = value
	}
	return clone
}
