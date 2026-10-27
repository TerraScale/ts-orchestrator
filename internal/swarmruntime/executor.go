package swarmruntime

import (
	"bytes"
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

	"github.com/TerraScale/ts-orchestrator/internal/hostload"
	"github.com/TerraScale/ts-orchestrator/internal/storage/execution"

	containerd "github.com/containerd/containerd/v2/client"
	"github.com/containerd/containerd/v2/core/remotes"
	"github.com/containerd/containerd/v2/core/runtime/v2/logging"
	"github.com/containerd/containerd/v2/pkg/namespaces"
	"github.com/containerd/errdefs"
	"github.com/moby/swarmkit/v2/agent/exec"
	"github.com/moby/swarmkit/v2/api"
	"github.com/moby/swarmkit/v2/api/genericresource"
	"golang.org/x/sys/unix"
)

const runtimeNamespace = "terrascale"
const logSegmentBytes = 1 << 20

// overlayfs shares unpacked layers between images and containers; a native
// snapshot copies the whole rootfs per layer and per container.
const imageSnapshotter = "overlayfs"

// HostContainerdSocket is the host containerd a single host executes on.
const HostContainerdSocket = "/run/containerd/containerd.sock"

// Executor translates upstream SwarmKit tasks directly into containerd objects.
type Executor struct {
	client            *containerd.Client
	socket            string
	logRoot           string
	executable        string
	mu                sync.Mutex
	functionMaterial  FunctionMaterialProvider
	containerMaterial ContainerMaterialProvider
	vaultSecrets      SecretResolver
	containerIdentity ContainerTaskBinding
	functionIdentity  FunctionTaskBinding
	functionNodeID    string
	node              *api.Node
	registry          RegistryResolver
	stateful          *execution.Source
	loadMu            sync.Mutex
	loadTasks         map[string]*controller
	loadSampler       *hostload.Sampler
	pulls             sync.Map               // image reference -> *sync.Mutex
	restarts          map[string]slotRestart // guarded by mu
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
	resources := &api.Resources{NanoCPUs: max(int64(runtime.NumCPU())*1_000_000_000-250_000_000, 0), MemoryBytes: max(int64(info.Totalram)*int64(info.Unit)-(256<<20), 0)}
	// Missing storage measurements hold new disk placements without failing
	// node description or disturbing an already running healthy task.
	if disk, err := e.schedulableDisk(ctx); err == nil && disk > 0 {
		resources.Generic = append(resources.Generic, genericresource.NewDiscrete(DiskResource, disk))
	}
	e.mu.Lock()
	if e.functionMaterial != nil {
		resources.Generic = append(resources.Generic, genericresource.NewDiscrete(FunctionWorkerSlot, 1))
	}
	e.mu.Unlock()
	return &api.NodeDescription{
		Hostname:  host,
		Platform:  &api.Platform{OS: runtime.GOOS, Architecture: runtime.GOARCH},
		Resources: resources,
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
	e.node = node.Copy()
	return nil
}

// SetRegistryResolver installs the trusted release/Vault verifier before tasks
// execute. An unbound executor uses the anonymous resolver.
func (e *Executor) SetRegistryResolver(resolver RegistryResolver) error {
	if resolver == nil {
		return errors.New("registry resolver is required")
	}
	e.mu.Lock()
	defer e.mu.Unlock()
	if e.registry != nil {
		return errors.New("registry admission authority is immutable")
	}
	e.registry = resolver
	return nil
}

// SwarmKit broadcasts overlay keys to every agent; host-only tasks never use them.
func (e *Executor) SetNetworkBootstrapKeys([]*api.EncryptionKey) error { return nil }

func (e *Executor) Controller(t *api.Task) (exec.Controller, error) {
	if t != nil && t.Spec.GetGeneric() != nil && t.Spec.GetGeneric().Kind == execution.StatefulContainerKind {
		spec, err := decodeStateful(t)
		if err != nil {
			return nil, err
		}
		e.mu.Lock()
		source := e.stateful
		nodeID := e.functionNodeID
		e.mu.Unlock()
		if source == nil || nodeID == "" || t.NodeID != nodeID {
			return nil, execution.ErrUnsafe
		}
		fingerprint, err := execution.TaskSHA256(t)
		if err != nil {
			return nil, err
		}
		base := &controller{executor: e, task: t.Copy(), spec: spec, id: "ts-" + t.ID, fingerprint: fingerprint}
		stateful := &statefulController{controller: base, source: source, hooks: source.Hooks()}
		base.stateful = stateful
		return stateful, nil
	}
	s, err := DecodeContainer(t)
	if err != nil {
		return nil, err
	}
	controller := &controller{executor: e, task: t.Copy(), spec: s, id: "ts-" + t.ID, fingerprint: taskFingerprint(t)}
	e.mu.Lock()
	e.trackLoadTask(controller)
	e.mu.Unlock()
	return controller, nil
}

// PrePull fetches and unpacks a digest-pinned public image ahead of its task,
// so a later Prepare only creates the container. It is idempotent and safe
// to run concurrently with Prepare. Admitted registries pull per task only.
// labels are the service annotations its tasks carry, so a GHCR pull reads
// the token from the Vault the service names.
func (e *Executor) PrePull(ctx context.Context, imageRef string, labels map[string]string) error {
	if err := pinnedImage(imageRef); err != nil {
		return err
	}
	e.mu.Lock()
	registry := e.registry
	var node *api.Node
	if e.node != nil {
		node = e.node.Copy()
	}
	e.mu.Unlock()
	if registry == nil {
		registry = publicRegistryResolver
	}
	// Registry authority is per task; a pre-pull presents only the image. A
	// per-image resolver (single-host GHCR) answers it, a task-admitting one
	// refuses it and the task pulls in Prepare instead.
	runtime, err := ContainerRuntime(&api.ContainerSpec{Image: imageRef, User: "65532:65532"})
	if err != nil {
		return err
	}
	limits := &api.Resources{NanoCPUs: 1_000_000_000, MemoryBytes: 1 << 30, Generic: []*api.GenericResource{genericresource.NewDiscrete(DiskResource, 1<<30)}}
	task := &api.Task{ID: "prepull", ServiceID: "prepull", Spec: api.TaskSpec{Runtime: runtime, Resources: &api.ResourceRequirements{Limits: limits, Reservations: limits.Copy()}},
		ServiceAnnotations: api.Annotations{Labels: labels}}
	resolver, err := registry(runtimeContext(ctx), task, node)
	if err != nil {
		return fmt.Errorf("resolve pre-pull registry: %w", err)
	}
	if resolver == nil {
		return errors.New("registry admission returned no resolver")
	}
	return e.pullImage(ctx, imageRef, resolver)
}

// pullImage serialises work per image only; distinct images pull in parallel.
func (e *Executor) pullImage(ctx context.Context, ref string, resolver remotes.Resolver) error {
	lock, _ := e.pulls.LoadOrStore(ref, new(sync.Mutex))
	lock.(*sync.Mutex).Lock()
	defer lock.(*sync.Mutex).Unlock()
	guard, err := e.imageGuard(ctx)
	if err != nil {
		return err
	}
	defer guard.Close()
	ctx, release, err := e.client.WithLease(runtimeContext(ctx))
	if err != nil {
		return err
	}
	defer release(context.WithoutCancel(ctx))
	image, err := e.client.GetImage(ctx, ref)
	if errdefs.IsNotFound(err) {
		_, err = e.client.Pull(ctx, ref, containerd.WithResolver(resolver), containerd.WithPullUnpack, containerd.WithPullSnapshotter(imageSnapshotter))
		return err
	}
	if err != nil {
		return err
	}
	if unpacked, err := image.IsUnpacked(ctx, imageSnapshotter); err != nil || unpacked {
		return err
	}
	return image.Unpack(ctx, imageSnapshotter)
}

// Close disconnects the agent; shim-owned tasks and logging continue running.
func (e *Executor) Close() error { return e.client.Close() }

// RunRuntimeLogger is the containerd shim callback dispatched by the same binary.
func RunRuntimeLogger(argument string) {
	logging.Run(func(ctx context.Context, cfg *logging.Config, ready func() error) error {
		root, guard, disk, err := parseRuntimeLoggerInvocation(argument)
		if err != nil {
			return err
		}
		if guard != nil && (cfg.Namespace != runtimeNamespace || cfg.ID != guard.TaskID) {
			return errors.New("runtime credential guard recipient differs from logger")
		}
		platformTask := cfg.Namespace == runtimeNamespace && strings.HasPrefix(cfg.ID, "ts-")
		foundation := cfg.Namespace == "terrascale-netbird" && slices.Contains([]string{"netbird-server", "netbird-dashboard", "netbird-ingress"}, cfg.ID)
		if !filepath.IsAbs(root) || (!platformTask && !foundation) || strings.ContainsAny(cfg.ID, "/\\") {
			return fmt.Errorf("invalid runtime log identity")
		}
		dir := filepath.Join(root, cfg.ID)
		if err := os.MkdirAll(dir, 0700); err != nil {
			return err
		}
		if disk != nil {
			confirmed, err := readDiskWitness(root, cfg.ID)
			if err != nil || cfg.Namespace != runtimeNamespace || disk.TaskID != cfg.ID || confirmed != *disk {
				return errors.Join(ErrDiskPending, err)
			}
		}
		out, err := os.OpenFile(filepath.Join(dir, "stdout"), os.O_CREATE|os.O_RDWR|os.O_APPEND|unix.O_NOFOLLOW, 0600)
		if err != nil {
			return err
		}
		defer out.Close()
		stderr, err := os.OpenFile(filepath.Join(dir, "stderr"), os.O_CREATE|os.O_RDWR|os.O_APPEND|unix.O_NOFOLLOW, 0600)
		if err != nil {
			return err
		}
		defer stderr.Close()
		if err := ready(); err != nil {
			return err
		}
		guardCtx, cancelGuard := context.WithCancel(ctx)
		defer cancelGuard()
		var guarded chan error
		if guard != nil {
			guarded = make(chan error, 1)
			guardResult := guarded
			go func() { guardResult <- guardRuntimeCredential(guardCtx, *guard) }()
		}
		result := make(chan error, 2)
		go func() { result <- copyBoundedLog(out, cfg.Stdout) }()
		go func() { result <- copyBoundedLog(stderr, cfg.Stderr) }()
		var errs []error
		for remaining := 2; remaining != 0 || guarded != nil; {
			select {
			case err := <-result:
				remaining--
				errs = append(errs, err)
			case err := <-guarded:
				guarded = nil
				errs = append(errs, err)
			case <-ctx.Done():
				cancelGuard()
				if guarded != nil {
					<-guarded
				}
				return ctx.Err()
			}
		}
		return errors.Join(errs...)
	})
}

// copyBoundedLog appends src to file, which never exceeds logSegmentBytes. A
// full file keeps its newest half from a line start instead of emptying: on
// gru TerraBase fills 1 MiB in about 25 minutes, and truncating to zero left
// operators no log right before an incident. file must be opened read-write.
func copyBoundedLog(file *os.File, src io.Reader) error {
	info, err := file.Stat()
	if err != nil {
		return err
	}
	size := info.Size()
	if !info.Mode().IsRegular() || size > logSegmentBytes {
		return ErrDiskPending
	}
	buffer := make([]byte, 16<<10)
	for {
		n, readErr := src.Read(buffer)
		if n > 0 {
			if size+int64(n) > logSegmentBytes {
				if size, err = keepLogTail(file, size); err != nil {
					return err
				}
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

// keepLogTail rewrites a full log as its newest logSegmentBytes/2 bytes,
// starting after the first newline in them, and returns the new size.
func keepLogTail(file *os.File, size int64) (int64, error) {
	keep := min(size, logSegmentBytes/2)
	tail := make([]byte, keep)
	if _, err := file.ReadAt(tail, size-keep); err != nil {
		return 0, err
	}
	if i := bytes.IndexByte(tail, '\n'); i >= 0 && size > keep {
		tail = tail[i+1:]
	}
	if err := file.Truncate(0); err != nil {
		return 0, err
	}
	if _, err := file.Write(tail); err != nil {
		return 0, err
	}
	return int64(len(tail)), nil
}
