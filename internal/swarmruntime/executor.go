package swarmruntime

import (
	"context"
	"errors"
	"fmt"
	"io"
	"os"
	"path/filepath"
	"runtime"
	"slices"
	"strings"
	"sync"

	containerd "github.com/containerd/containerd/v2/client"
	"github.com/containerd/containerd/v2/core/runtime/v2/logging"
	"github.com/containerd/containerd/v2/pkg/namespaces"
	"github.com/moby/swarmkit/v2/agent/exec"
	"github.com/moby/swarmkit/v2/api"
	"golang.org/x/sys/unix"
)

const runtimeNamespace = "terrascale"
const logSegmentBytes = 1 << 20

// Executor translates upstream SwarmKit tasks directly into containerd objects.
type Executor struct {
	client           *containerd.Client
	socket           string
	logRoot          string
	executable       string
	mu               sync.Mutex
	functionMaterial FunctionMaterialProvider
	functionIdentity FunctionTaskBinding
	functionNodeID   string
}

var _ exec.Executor = (*Executor)(nil)

func NewExecutor(socket, stateDir string) (*Executor, error) {
	if !filepath.IsAbs(socket) || !filepath.IsAbs(stateDir) {
		return nil, fmt.Errorf("runtime socket and state directory must be absolute")
	}
	if runtime.GOOS != "linux" {
		return nil, fmt.Errorf("container runtime requires Linux")
	}
	socket, err := filepath.EvalSymlinks(socket)
	if err != nil {
		return nil, fmt.Errorf("resolve local runtime socket: %w", err)
	}
	executable, err := os.Executable()
	if err != nil {
		return nil, err
	}
	root := filepath.Join(stateDir, "runtime-logs")
	if err := os.MkdirAll(root, 0700); err != nil {
		return nil, err
	}
	c, err := containerd.New(socket, containerd.WithDefaultNamespace(runtimeNamespace))
	if err != nil {
		return nil, err
	}
	return &Executor{client: c, socket: socket, logRoot: root, executable: executable}, nil
}

func runtimeContext(ctx context.Context) context.Context {
	return namespaces.WithNamespace(ctx, runtimeNamespace)
}

func (e *Executor) Describe(ctx context.Context) (*api.NodeDescription, error) {
	v, err := e.client.Version(runtimeContext(ctx))
	if err != nil {
		return nil, err
	}
	host, err := os.Hostname()
	if err != nil {
		return nil, err
	}
	var info unix.Sysinfo_t
	if err := unix.Sysinfo(&info); err != nil {
		return nil, err
	}
	return &api.NodeDescription{
		Hostname:  host,
		Platform:  &api.Platform{OS: runtime.GOOS, Architecture: runtime.GOARCH},
		Resources: &api.Resources{NanoCPUs: int64(max(runtime.NumCPU()-1, 0)) * 1_000_000_000, MemoryBytes: max(int64(info.Totalram)*int64(info.Unit)-(256<<20), 0)},
		Engine:    &api.EngineDescription{EngineVersion: v.Version, Plugins: []api.PluginDescription{{Type: "Runtime", Name: ContainerKind}}},
	}, nil
}

func (e *Executor) Configure(_ context.Context, node *api.Node) error {
	if node == nil || node.ID == "" {
		return errors.New("runtime requires an authenticated node identity")
	}
	e.mu.Lock()
	defer e.mu.Unlock()
	if e.functionNodeID != "" && e.functionNodeID != node.ID {
		return errors.New("runtime node identity is immutable")
	}
	e.functionNodeID = node.ID
	return nil
}

// SwarmKit broadcasts overlay keys to every agent; host-only tasks never use them.
func (e *Executor) SetNetworkBootstrapKeys([]*api.EncryptionKey) error { return nil }

func (e *Executor) Controller(t *api.Task) (exec.Controller, error) {
	s, err := DecodeContainer(t)
	if err != nil {
		return nil, err
	}
	return &controller{executor: e, task: t.Copy(), spec: s, id: "ts-" + t.ID, fingerprint: taskFingerprint(t)}, nil
}

// Close disconnects the agent; shim-owned tasks and logging continue running.
func (e *Executor) Close() error { return e.client.Close() }

// RunRuntimeLogger is the containerd shim callback dispatched by the same binary.
func RunRuntimeLogger(root string) {
	logging.Run(func(ctx context.Context, cfg *logging.Config, ready func() error) error {
		platformTask := cfg.Namespace == runtimeNamespace && strings.HasPrefix(cfg.ID, "ts-")
		foundation := cfg.Namespace == "terrascale-netbird" && slices.Contains([]string{"netbird-server", "netbird-dashboard", "netbird-ingress"}, cfg.ID)
		if !filepath.IsAbs(root) || (!platformTask && !foundation) || strings.ContainsAny(cfg.ID, "/\\") {
			return fmt.Errorf("invalid runtime log identity")
		}
		dir := filepath.Join(root, cfg.ID)
		if err := os.MkdirAll(dir, 0700); err != nil {
			return err
		}
		out, err := os.OpenFile(filepath.Join(dir, "stdout"), os.O_CREATE|os.O_WRONLY|os.O_APPEND, 0600)
		if err != nil {
			return err
		}
		defer out.Close()
		stderr, err := os.OpenFile(filepath.Join(dir, "stderr"), os.O_CREATE|os.O_WRONLY|os.O_APPEND, 0600)
		if err != nil {
			return err
		}
		defer stderr.Close()
		if err := ready(); err != nil {
			return err
		}
		result := make(chan error, 2)
		go func() { result <- copyBoundedLog(out, cfg.Stdout) }()
		go func() { result <- copyBoundedLog(stderr, cfg.Stderr) }()
		var errs []error
		for range 2 {
			select {
			case err := <-result:
				errs = append(errs, err)
			case <-ctx.Done():
				return ctx.Err()
			}
		}
		return errors.Join(errs...)
	})
}

func copyBoundedLog(file *os.File, src io.Reader) error {
	info, err := file.Stat()
	if err != nil {
		return err
	}
	size := info.Size()
	buffer := make([]byte, 16<<10)
	for {
		n, readErr := src.Read(buffer)
		if n > 0 {
			if size+int64(n) > logSegmentBytes {
				if err := file.Truncate(0); err != nil {
					return err
				}
				size = 0
			}
			if _, err := file.Write(buffer[:n]); err != nil {
				return err
			}
			size += int64(n)
		}
		if errors.Is(readErr, io.EOF) {
			return nil
		}
		if readErr != nil {
			return readErr
		}
	}
}
