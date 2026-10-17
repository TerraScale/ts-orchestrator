package foundation

import (
	"context"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json/v2"
	"errors"
	"fmt"
	"io/fs"
	"os"
	"path/filepath"
	"runtime"
	"strings"
	"syscall"
	"time"

	managerbundle "github.com/TerraScale/ts-orchestrator/deploy/netbird/manager"
	containerd "github.com/containerd/containerd/v2/client"
	"github.com/containerd/containerd/v2/core/snapshots"
	"github.com/containerd/containerd/v2/pkg/cio"
	"github.com/containerd/containerd/v2/pkg/namespaces"
	"github.com/containerd/containerd/v2/pkg/oci"
	"github.com/containerd/errdefs"
	"github.com/opencontainers/image-spec/identity"
	spec "github.com/opencontainers/runtime-spec/specs-go"
	"golang.org/x/sys/unix"
)

const foundationNamespace = "terrascale-netbird"

type foundationRuntime struct {
	client              *containerd.Client
	executable, logRoot string
}
type foundationComponent struct {
	ID, Image     string
	Args, Env     []string
	Mounts        []spec.Mount
	Memory        uint64
	Configuration string
}

func newFoundationRuntime() (*foundationRuntime, error) {
	executable, err := os.Executable()
	if err != nil {
		return nil, err
	}
	client, err := containerd.New("/run/containerd/containerd.sock", containerd.WithDefaultNamespace(foundationNamespace))
	if err != nil {
		return nil, errors.New("NetBird local containerd unavailable")
	}
	return &foundationRuntime{client: client, executable: executable, logRoot: DataDirectory + "/runtime-logs"}, nil
}
func foundationContext(ctx context.Context) context.Context {
	return namespaces.WithNamespace(ctx, foundationNamespace)
}

func foundationComponents() ([]foundationComponent, error) {
	var server, dashboard, ingress string
	switch runtime.GOARCH {
	case "arm64":
		server = "4ef9ce41c29a62b864805c948a1bcb173d4b909d72a581853ffb29743ac6f9ee"
		dashboard = "44a250c04d91b46aa666de4b2b25602f0580b64dee0682fedfb9d012cb020ff7"
		ingress = "8dbca3525dd8dce671e495665a0eb297a83ec87ee30f373947d0ea93115949db"
	case "amd64":
		server = "8eb63a41f572bd11a160c8444d9dbd7178dd1de71965f848cf788991a58a6c16"
		dashboard = "86f5fbb16c5bae1918dc2f09da6182144c30e45ecf75d7902038743094e7bdcd"
		ingress = "d8c17a862962def15cde69863a3a463f25a2664942eafd7bdbf050e9c3116b83"
	default:
		return nil, errors.New("NetBird foundation requires qualified arm64 or amd64 upstream components")
	}
	config, err := os.ReadFile(ConfigPath)
	if err != nil {
		return nil, errors.New("NetBird delivered runtime config unavailable")
	}
	sum := sha256.Sum256(config)
	clear(config)
	dashboardEnv, err := fs.ReadFile(managerbundle.Files, "dashboard.environment")
	if err != nil {
		return nil, err
	}
	env := []string{}
	for line := range strings.SplitSeq(string(dashboardEnv), "\n") {
		if line != "" && !strings.HasPrefix(line, "#") {
			env = append(env, line)
		}
	}
	bind := func(source, target string, readOnly bool) spec.Mount {
		options := []string{"rbind", "nosuid", "nodev"}
		if readOnly {
			options = append(options, "ro")
		}
		return spec.Mount{Source: source, Destination: target, Type: "bind", Options: options}
	}
	return []foundationComponent{
		{ID: "netbird-server", Image: "docker.io/netbirdio/netbird-server@sha256:" + server, Args: []string{"/go/bin/netbird-server", "--config", "/etc/netbird/config.yaml"}, Mounts: []spec.Mount{bind(DataDirectory+"/data", "/var/lib/netbird", false), bind(filepath.Dir(ConfigPath), "/etc/netbird", true)}, Memory: 512 << 20, Configuration: hex.EncodeToString(sum[:])},
		{ID: "netbird-dashboard", Image: "docker.io/netbirdio/dashboard@sha256:" + dashboard, Env: env, Args: []string{"/bin/bash", "-ec", `sed -i 's/listen 80 default_server;/listen 127.0.0.1:18080 default_server;/; /listen \[::\]:80 default_server;/d' /etc/nginx/http.d/default.conf; exec /usr/local/init_react_envs.sh /usr/sbin/nginx`}, Memory: 192 << 20},
		{ID: "netbird-ingress", Image: "docker.io/library/caddy@sha256:" + ingress, Mounts: []spec.Mount{bind(stackDirectory+"/Caddyfile.netbird", "/etc/caddy/Caddyfile", true), bind(DataDirectory+"/data/foundation-tls", "/data", false)}, Memory: 192 << 20},
	}, nil
}

func (r *foundationRuntime) ensure(ctx context.Context, component foundationComponent, check func() error) error {
	if check == nil {
		return errors.New("NetBird component authority unavailable")
	}
	if err := check(); err != nil {
		return err
	}
	ctx = foundationContext(ctx)
	version, err := r.client.Version(ctx)
	if err != nil || strings.TrimPrefix(version.Version, "v") != "2.4.2" {
		return errors.New("NetBird foundation requires qualified containerd 2.4.2")
	}
	encoded, err := json.Marshal(component)
	if err != nil {
		return err
	}
	digest := sha256.Sum256(encoded)
	fingerprint := hex.EncodeToString(digest[:])
	container, err := r.client.LoadContainer(ctx, component.ID)
	if err == nil {
		labels, labelErr := container.Labels(ctx)
		if labelErr != nil {
			return labelErr
		}
		if labels["terrascale.foundation"] != "netbird-v1" {
			return errors.New("NetBird component container ownership mismatch")
		}
		if labels["terrascale.spec"] != fingerprint {
			if err = r.stop(ctx, component.ID, check); err != nil {
				return err
			}
			if err = check(); err != nil {
				return err
			}
			if err = container.Delete(ctx, containerd.WithSnapshotCleanup); err != nil {
				return err
			}
			container = nil
		}
	} else if !errdefs.IsNotFound(err) {
		return err
	}
	if container == nil {
		if err = check(); err != nil {
			return err
		}
		leaseCtx, release, err := r.client.WithLease(ctx)
		if err != nil {
			return err
		}
		defer release(leaseCtx)
		image, err := r.client.GetImage(leaseCtx, component.Image)
		if errdefs.IsNotFound(err) {
			image, err = r.client.Pull(leaseCtx, component.Image, containerd.WithPullUnpack, containerd.WithPullSnapshotter("native"))
		}
		if err != nil {
			return fmt.Errorf("NetBird component image unavailable: %w", err)
		}
		if err = image.Unpack(leaseCtx, "native"); err != nil {
			return err
		}
		config, err := image.Spec(leaseCtx)
		if err != nil {
			return err
		}
		if config.OS != "linux" || config.Architecture != runtime.GOARCH {
			return errors.New("NetBird component image architecture mismatch")
		}
		if err = check(); err != nil {
			return err
		}
		container, err = r.client.NewContainer(leaseCtx, component.ID, containerd.WithSnapshotter("native"), containerd.WithImage(image), containerd.WithSpec(&spec.Spec{Version: spec.Version}), containerd.WithRuntime("io.containerd.runc.v2", nil), containerd.WithContainerLabels(map[string]string{"terrascale.foundation": "netbird-v1", "terrascale.spec": fingerprint}))
		if err != nil {
			return err
		}
	}
	info, err := container.Info(ctx)
	if err != nil {
		return err
	}
	if info.SnapshotKey == "" {
		image, err := container.Image(ctx)
		if err != nil {
			return err
		}
		if err = image.Unpack(ctx, "native"); err != nil {
			return err
		}
		if err = check(); err != nil {
			return err
		}
		err = container.Update(ctx, containerd.UpdateContainerOpts(containerd.WithNewSnapshot(component.ID, image, snapshots.WithLabels(map[string]string{"terrascale.foundation": "netbird-v1", "terrascale.spec": fingerprint}))))
		if errdefs.IsAlreadyExists(err) {
			snapshot, statErr := r.client.SnapshotService(info.Snapshotter).Stat(ctx, component.ID)
			if statErr != nil {
				return statErr
			}
			rootfs, rootErr := image.RootFS(ctx)
			if rootErr != nil {
				return rootErr
			}
			if snapshot.Kind != snapshots.KindActive || snapshot.Parent != identity.ChainID(rootfs).String() || snapshot.Labels["terrascale.foundation"] != "netbird-v1" || snapshot.Labels["terrascale.spec"] != fingerprint {
				return errors.New("NetBird component snapshot ownership mismatch")
			}
			err = container.Update(ctx, containerd.UpdateContainerOpts(containerd.WithSnapshot(component.ID)))
		}
		if err != nil {
			return err
		}
	}
	// The metadata must exist before snapshot attachment; only a fully built spec can start.
	if info.Labels["terrascale.spec-ready"] != fingerprint {
		image, err := container.Image(ctx)
		if err != nil {
			return err
		}
		component.Mounts = append(component.Mounts, spec.Mount{Source: "/etc/resolv.conf", Destination: "/etc/resolv.conf", Type: "bind", Options: []string{"rbind", "ro", "nosuid", "nodev"}}, spec.Mount{Source: "/etc/hosts", Destination: "/etc/hosts", Type: "bind", Options: []string{"rbind", "ro", "nosuid", "nodev"}})
		options := []oci.SpecOpts{oci.WithImageConfig(image), oci.WithEnv(component.Env), oci.WithHostNamespace(spec.NetworkNamespace), oci.WithMounts(component.Mounts), oci.WithNoNewPrivileges, oci.WithMemoryLimit(component.Memory), oci.WithMemorySwap(int64(component.Memory)), oci.WithPidsLimit(256)}
		if len(component.Args) > 0 {
			options = append(options, oci.WithProcessArgs(component.Args...))
		}
		if err = check(); err != nil {
			return err
		}
		if err = container.Update(ctx, containerd.UpdateContainerOpts(containerd.WithNewSpec(options...)), containerd.UpdateContainerOpts(containerd.WithContainerLabels(map[string]string{"terrascale.foundation": "netbird-v1", "terrascale.spec": fingerprint, "terrascale.spec-ready": fingerprint}))); err != nil {
			return err
		}
	}
	task, err := container.Task(ctx, nil)
	if err == nil {
		status, statusErr := task.Status(ctx)
		if statusErr != nil {
			return statusErr
		}
		if status.Status == containerd.Running {
			return nil
		}
		if status.Status == containerd.Created {
			if err = check(); err != nil {
				return err
			}
			return task.Start(ctx)
		}
		if status.Status != containerd.Stopped {
			return errors.New("NetBird component is in an unresolved runtime state")
		}
		if err = check(); err != nil {
			return err
		}
		if _, err = task.Delete(ctx); err != nil {
			return err
		}
	} else if !errdefs.IsNotFound(err) {
		return err
	}
	if err = check(); err != nil {
		return err
	}
	if err = os.MkdirAll(r.logRoot, 0700); err != nil {
		return err
	}
	uri, err := cio.LogURIGenerator("binary-v2", r.executable, map[string]string{"--runtime-logger": r.logRoot})
	if err != nil {
		return err
	}
	task, err = container.NewTask(ctx, cio.LogURI(uri))
	if err != nil {
		return err
	}
	if err = check(); err != nil {
		return err
	}
	return task.Start(ctx)
}

func (r *foundationRuntime) stop(ctx context.Context, id string, check func() error) error {
	if check == nil {
		return errors.New("NetBird component authority unavailable")
	}
	if err := check(); err != nil {
		return err
	}
	ctx = foundationContext(ctx)
	container, err := r.client.LoadContainer(ctx, id)
	if errdefs.IsNotFound(err) {
		return nil
	}
	if err != nil {
		return err
	}
	labels, err := container.Labels(ctx)
	if err != nil {
		return err
	}
	if labels["terrascale.foundation"] != "netbird-v1" {
		return errors.New("NetBird component container ownership mismatch")
	}
	task, err := container.Task(ctx, nil)
	if errdefs.IsNotFound(err) {
		return nil
	}
	if err != nil {
		return err
	}
	status, err := task.Status(ctx)
	if err != nil {
		return err
	}
	if status.Status == containerd.Running {
		wait, err := task.Wait(ctx)
		if err != nil {
			return err
		}
		if err = check(); err != nil {
			return err
		}
		if err = task.Kill(ctx, syscall.SIGTERM, containerd.WithKillAll); err != nil && !errdefs.IsNotFound(err) {
			return err
		}
		select {
		case <-ctx.Done():
			return ctx.Err()
		case <-wait:
		case <-time.After(30 * time.Second):
			if err = check(); err != nil {
				return err
			}
			if err = task.Kill(ctx, syscall.SIGKILL, containerd.WithKillAll); err != nil && !errdefs.IsNotFound(err) {
				return err
			}
			select {
			case <-ctx.Done():
				return ctx.Err()
			case <-wait:
			}
		}
	}
	if err = check(); err != nil {
		return err
	}
	_, err = task.Delete(ctx, containerd.WithProcessKill)
	return err
}
func (r *foundationRuntime) healthy(ctx context.Context) bool {
	ctx = foundationContext(ctx)
	for _, id := range []string{"netbird-server", "netbird-dashboard", "netbird-ingress"} {
		container, err := r.client.LoadContainer(ctx, id)
		if err != nil {
			return false
		}
		task, err := container.Task(ctx, nil)
		if err != nil {
			return false
		}
		status, err := task.Status(ctx)
		if err != nil || status.Status != containerd.Running {
			return false
		}
	}
	client, err := newBootstrapClient(localOrigin)
	if err != nil {
		return false
	}
	defer client.http.CloseIdleConnections()
	var instance struct {
		SetupRequired *bool `json:"setup_required"`
	}
	if client.api(ctx, "GET", "/instance", "", nil, &instance) != nil || instance.SetupRequired == nil || *instance.SetupRequired {
		return false
	}
	return true
}

func serviceLock(ctx context.Context) (func(), error) {
	if err := os.MkdirAll(DataDirectory, 0700); err != nil {
		return nil, err
	}
	fd, err := unix.Open(DataDirectory+"/.backup.lock", unix.O_CREAT|unix.O_RDWR|unix.O_CLOEXEC|unix.O_NOFOLLOW, 0600)
	if err != nil {
		return nil, err
	}
	for {
		err = unix.Flock(fd, unix.LOCK_EX|unix.LOCK_NB)
		if err == nil {
			return func() { _ = unix.Flock(fd, unix.LOCK_UN); _ = unix.Close(fd) }, nil
		}
		if !errors.Is(err, unix.EWOULDBLOCK) {
			unix.Close(fd)
			return nil, err
		}
		select {
		case <-ctx.Done():
			unix.Close(fd)
			return nil, ctx.Err()
		case <-time.After(100 * time.Millisecond):
		}
	}
}
