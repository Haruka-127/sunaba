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
	Ulimits    map[string]RLimit
	Networks   []string
	NoDNS      bool
	Init       bool
	ReadOnly   bool
	CapAdd     []string
	CapDrop    []string
	Mounts     []Mount
	Sockets    []PublishedSocket
	Env        map[string]string
	EnvFiles   []string
	Workdir    string
	Labels     map[string]string
	Entrypoint string
	Args       []string
}

type RLimit struct {
	Soft int64
	Hard int64
}

type Mount struct {
	Source   string
	Target   string
	Type     string
	ReadOnly bool
}

type PublishedSocket struct {
	HostPath  string
	GuestPath string
}

type Info struct {
	Name   string
	Image  string
	State  State
	IP     string
	CPUs   string
	Memory string
	Labels map[string]string
}

// ExecResult is bounded output from one argv-based command in an Agent VM.
// It never represents a host shell command.
type ExecResult struct {
	Stdout          string
	Stderr          string
	ExitCode        int
	TimedOut        bool
	StdoutTruncated bool
	StderrTruncated bool
}

type Runtime interface {
	ImageExists(ctx context.Context, tag string) (bool, error)
	BuildImage(ctx context.Context, tag, contextDir string, buildArgs map[string]string) error
	ContainerState(ctx context.Context, name string) (State, error)
	Create(ctx context.Context, spec ContainerSpec) error
	CreateSecure(ctx context.Context, spec ContainerSpec, policy SecureSessionPolicy) error
	Start(ctx context.Context, name string) error
	Stop(ctx context.Context, name string) error
	Remove(ctx context.Context, name string) error
	Exec(ctx context.Context, name string, interactive bool, cmd []string) error
	ExecOutput(ctx context.Context, name string, cmd []string) (string, error)
	CopyTo(ctx context.Context, name, source, target string) error
	Export(ctx context.Context, name, output string) error
	IPAddress(ctx context.Context, name string) (string, error)
	Inspect(ctx context.Context, name string) (Info, error)
	List(ctx context.Context) ([]Info, error)
}
