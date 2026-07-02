package runtime

import "context"

type State string

const (
	StateNotFound State = "not-found"
	StateStopped  State = "stopped"
	StateRunning  State = "running"
	StateUnknown  State = "unknown"
)

type ContainerSpec struct {
	Name       string
	Image      string
	CPUs       int
	Memory     string
	Mounts     []Mount
	Env        map[string]string
	EnvFiles   []string
	Workdir    string
	Labels     map[string]string
	Entrypoint string
	Args       []string
}

type Mount struct {
	Source string
	Target string
}

type Info struct {
	Name   string
	Image  string
	State  State
	IP     string
	CPUs   string
	Memory string
}

type Runtime interface {
	ImageExists(ctx context.Context, tag string) (bool, error)
	BuildImage(ctx context.Context, tag, contextDir string, buildArgs map[string]string) error
	ContainerState(ctx context.Context, name string) (State, error)
	Create(ctx context.Context, spec ContainerSpec) error
	Start(ctx context.Context, name string) error
	Stop(ctx context.Context, name string) error
	Remove(ctx context.Context, name string) error
	Exec(ctx context.Context, name string, interactive bool, cmd []string) error
	ExecOutput(ctx context.Context, name string, cmd []string) (string, error)
	IPAddress(ctx context.Context, name string) (string, error)
	Inspect(ctx context.Context, name string) (Info, error)
	List(ctx context.Context) ([]Info, error)
}
