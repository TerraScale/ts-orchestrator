package foundation

import (
	"context"
	"crypto/rand"
	"crypto/sha256"
	"encoding/json/v2"
	"errors"
	"fmt"
	"io"
	"math"
	"net/http"
	"net/url"
	"os"
	"path/filepath"
	"reflect"
	"slices"
	"strconv"
	"strings"
	"sync"
	"sync/atomic"
	"time"

	"github.com/TerraScale/ts-orchestrator/internal/region"
	"github.com/TerraScale/ts-orchestrator/internal/rootoci"
	containerd "github.com/containerd/containerd/v2/client"
	"github.com/containerd/containerd/v2/contrib/seccomp"
	"github.com/containerd/containerd/v2/core/containers"
	"github.com/containerd/containerd/v2/core/mount"
	"github.com/containerd/containerd/v2/core/remotes"
	"github.com/containerd/containerd/v2/core/remotes/docker"
	"github.com/containerd/containerd/v2/core/snapshots"
	"github.com/containerd/containerd/v2/pkg/cio"
	"github.com/containerd/containerd/v2/pkg/namespaces"
	"github.com/containerd/containerd/v2/pkg/oci"
	"github.com/containerd/errdefs"
	"github.com/containerd/platforms"
	"github.com/opencontainers/image-spec/identity"
	imagespec "github.com/opencontainers/image-spec/specs-go/v1"
	spec "github.com/opencontainers/runtime-spec/specs-go"
	"golang.org/x/sys/unix"
	"google.golang.org/grpc"
)

const componentNamespace = "terrascale-netbird"
const componentSocket = "/run/containerd/containerd.sock"
const componentRuntimeSchema = "terrascale.netbird.runtime.v1"

var errComponentCustody = errors.New("NetBird runtime identity or retained physical custody is unresolved")
var errComponentAdmission = errors.New("NetBird current component admission is unresolved")

func componentRoles() [3]string {
	return [3]string{"netbird-server", "netbird-dashboard", "netbird-ingress"}
}

type componentRelease struct {
	Role, Image, Identity, BundleSHA256, MigrationSHA256, ConfigurationSHA256 string
	Sequence                                                                  uint64
}

type componentJournal struct {
	Schema     string
	Binding    storeBinding
	Token      string
	Next       [3]componentRelease
	Components [3]componentRecord
}

type componentRecord struct {
	Release                           componentRelease
	Spec                              *spec.Spec
	Snapshot, Parent, Stage           string
	ContainerCreated, SnapshotCreated time.Time
	SnapshotMounts                    []mount.Mount     `json:",omitempty"`
	Sources                           []componentSource `json:",omitempty"`
	Root                              componentSource
	Process                           *componentProcess
}

type componentInode struct {
	Device, Inode  uint64
	Mode, UID, GID uint32
}

type componentSource struct {
	Path  string
	Nodes []componentInode
}

type componentProcess struct {
	BootID                             string
	PID                                int
	Start                              uint64
	Cgroup                             string
	PIDNamespace, MountNamespace, Root componentInode
	RootMountID                        uint64
	CgroupSource                       componentSource
	Mounts                             []componentInode `json:",omitempty"`
}

// The held descriptors make path replacement observable throughout a lifecycle.
type componentPin struct {
	source componentSource
	files  []*os.File
}

type componentChild struct {
	pidfd   int
	witness *rootoci.ProcessWitness
	files   []*os.File
	cgroup  *componentPin
}

type componentRuntime struct {
	mu         sync.Mutex
	custody    *storeCustody
	client     *containerd.Client
	journal    componentJournal
	pins       map[string]*componentPin
	children   [3]*componentChild
	guard      atomic.Pointer[componentGuard]
	closed     bool
	unresolved bool
}

type componentGuard struct {
	runtime  *componentRuntime
	owner    *owner
	material region.NetBirdComponents
	base     context.Context
}

func openComponentRuntime(custody *storeCustody) (_ *componentRuntime, err error) {
	if custody == nil || custody.rootPath() != "/var/lib/terrascale/netbird" {
		return nil, errComponentCustody
	}
	if err := custody.check(); err != nil {
		return nil, err
	}
	r := &componentRuntime{custody: custody, pins: make(map[string]*componentPin)}
	defer func() {
		if err != nil {
			_ = r.Close()
		}
	}()
	found, err := custody.loadRuntime(&r.journal)
	if err != nil {
		return nil, err
	}
	if found {
		if r.journal.Schema != componentRuntimeSchema || r.journal.Binding != custody.binding() || r.journal.Token == "" {
			return nil, errComponentCustody
		}
		for i, role := range componentRoles() {
			c := &r.journal.Components[i]
			if c.Release.Role != role || c.Snapshot != role+"-"+r.journal.Token || c.Release.Identity == "" {
				return nil, errComponentCustody
			}
			if c.Spec != nil && (c.Spec.Linux == nil || c.Spec.Linux.CgroupsPath != r.cgroupPath(role)) {
				return nil, errComponentCustody
			}
		}
	}
	if _, err := r.pin(componentSocket, nil, true); err != nil {
		return nil, err
	}
	r.guard.Store(&componentGuard{runtime: r})
	r.client, err = containerd.New(componentSocket,
		containerd.WithDefaultNamespace(componentNamespace),
		containerd.WithDefaultRuntime("io.containerd.runc.v2"),
		containerd.WithDefaultPlatform(platforms.OnlyStrict(imagespec.Platform{OS: "linux", Architecture: "arm64"})),
		containerd.WithExtraDialOpts([]grpc.DialOption{
			grpc.WithDisableRetry(), grpc.WithChainUnaryInterceptor(r.unary), grpc.WithChainStreamInterceptor(r.stream),
		}))
	if err != nil {
		return nil, err
	}
	return r, nil
}

func (r *componentRuntime) local() error {
	if r.closed {
		return errComponentCustody
	}
	if err := r.custody.check(); err != nil {
		return errors.Join(errComponentCustody, err)
	}
	for _, pin := range r.pins {
		if err := pin.check(); err != nil {
			return errors.Join(errComponentCustody, err)
		}
	}
	return nil
}

func (g *componentGuard) before(ctx context.Context, method string) error {
	if err := g.runtime.local(); err != nil {
		return err
	}
	if g.owner == nil {
		switch method {
		case "/containerd.services.containers.v1.Containers/Get",
			"/containerd.services.tasks.v1.Tasks/Get", "/containerd.services.tasks.v1.Tasks/Wait",
			"/containerd.services.snapshots.v1.Snapshots/Stat", "/containerd.services.snapshots.v1.Snapshots/Mounts":
			return ctx.Err()
		default:
			return errComponentCustody
		}
	}
	if !g.runtime.custody.prepared() || g.base == nil {
		return errComponentCustody
	}
	if err := g.base.Err(); err != nil {
		return err
	}
	if err := ctx.Err(); err != nil {
		return err
	}
	check, cancel := context.WithCancel(g.base)
	detach := context.AfterFunc(ctx, cancel)
	defer detach()
	defer cancel()
	return g.owner.authorize(check, g.material)
}

func (r *componentRuntime) unary(ctx context.Context, method string, req, reply any, cc *grpc.ClientConn, invoker grpc.UnaryInvoker, opts ...grpc.CallOption) error {
	g := r.guard.Load()
	if g == nil {
		return errComponentCustody
	}
	if err := g.before(ctx, method); err != nil {
		return err
	}
	return invoker(ctx, method, req, reply, cc, opts...)
}

type componentStream struct {
	grpc.ClientStream
	guard  *componentGuard
	method string
}

func (s *componentStream) SendMsg(message any) error {
	if err := s.guard.before(s.Context(), s.method); err != nil {
		return err
	}
	return s.ClientStream.SendMsg(message)
}

func (r *componentRuntime) stream(ctx context.Context, desc *grpc.StreamDesc, cc *grpc.ClientConn, method string, streamer grpc.Streamer, opts ...grpc.CallOption) (grpc.ClientStream, error) {
	g := r.guard.Load()
	if g == nil {
		return nil, errComponentCustody
	}
	if err := g.before(ctx, method); err != nil {
		return nil, err
	}
	s, err := streamer(ctx, desc, cc, method, opts...)
	if err != nil {
		return nil, err
	}
	return &componentStream{ClientStream: s, guard: g, method: method}, nil
}

func (r *componentRuntime) authorized(ctx context.Context, o *owner, material region.NetBirdComponents) (context.Context, context.CancelFunc, error) {
	if ctx == nil || o == nil || o.custody != r.custody || !r.custody.prepared() {
		return nil, nil, errComponentCustody
	}
	ctx, cancel := context.WithDeadline(ctx, material.ExpiresAt())
	if err := r.local(); err != nil {
		cancel()
		return nil, nil, err
	}
	if err := o.authorize(ctx, material); err != nil {
		cancel()
		return nil, nil, err
	}
	r.guard.Store(&componentGuard{runtime: r, owner: o, material: material, base: ctx})
	return namespaces.WithNamespace(ctx, componentNamespace), cancel, nil
}

func (r *componentRuntime) save() error {
	if err := r.local(); err != nil {
		return err
	}
	return r.custody.saveRuntime(r.journal)
}

func componentHash(value any) (string, error) {
	wire, err := json.Marshal(value, json.Deterministic(true))
	if err != nil {
		return "", err
	}
	return fmt.Sprintf("%x", sha256.Sum256(wire)), nil
}

func desiredComponents(ctx context.Context, o *owner, material region.NetBirdComponents) ([3]componentRelease, error) {
	var result [3]componentRelease
	for i, role := range componentRoles() {
		component, err := material.Component(ctx, role)
		if err != nil {
			return result, err
		}
		release := component.Release()
		claim := release.Claim()
		configuration, err := componentHash(o.configurations[i])
		if err != nil {
			return result, err
		}
		if claim.Role != role || claim.Architecture != "arm64" || claim.ReleaseSequence == 0 || release.ReleaseIdentity() == "" {
			return result, errComponentAdmission
		}
		result[i] = componentRelease{Role: role, Image: claim.Image, Identity: release.ReleaseIdentity(),
			BundleSHA256: release.BundleSHA256(), MigrationSHA256: claim.SequenceMigrationSHA256,
			Sequence: claim.ReleaseSequence, ConfigurationSHA256: configuration}
	}
	return result, nil
}

func (r *componentRuntime) matches(desired [3]componentRelease) bool {
	if r.journal.Schema != componentRuntimeSchema {
		return false
	}
	for i := range desired {
		if r.journal.Components[i].Release != desired[i] {
			return false
		}
	}
	return true
}

func (r *componentRuntime) backend(ctx context.Context, o *owner, material region.NetBirdComponents) error {
	r.mu.Lock()
	defer r.mu.Unlock()
	ctx, cancel, err := r.authorized(ctx, o, material)
	if err != nil {
		return err
	}
	defer cancel()
	defer r.guard.Store(&componentGuard{runtime: r})
	desired, err := desiredComponents(ctx, o, material)
	if err != nil {
		return err
	}
	prepared := r.matches(desired)
	for _, c := range r.journal.Components {
		if c.Spec == nil {
			prepared = false
		}
	}
	if !prepared || r.journal.Next != [3]componentRelease{} {
		if r.journal.Schema == "" {
			if err := r.noUnrecordedContainers(ctx); err != nil {
				return err
			}
			r.journal = componentJournal{Schema: componentRuntimeSchema, Binding: r.custody.binding(), Token: rand.Text()}
			for i := range desired {
				r.journal.Components[i] = componentRecord{Release: desired[i], Snapshot: desired[i].Role + "-" + r.journal.Token, Stage: "admitted"}
			}
		}
		r.journal.Next = desired
		if err := r.save(); err != nil {
			return err
		}
		var specs [3]*spec.Spec
		var parents [3]string
		for i := range desired {
			image, err := r.pull(ctx, material, desired[i])
			if err != nil {
				return err
			}
			rootfs, err := image.RootFS(ctx)
			if err != nil {
				return err
			}
			parents[i] = identity.ChainID(rootfs).String()
			specs[i], err = r.specification(ctx, image, o.configurations[i], i)
			if err != nil {
				return err
			}
		}
		active := r.guard.Load()
		if err := r.quiesceLocked(ctx); err != nil {
			return err
		}
		r.guard.Store(active)
		for i := 2; i >= 0; i-- {
			if err := r.remove(ctx, i); err != nil {
				return err
			}
		}
		for i := range r.children {
			r.closeChild(i)
		}
		r.releasePins()
		// The cgroup path depends on physical store identity, not the release token.
		r.journal = componentJournal{Schema: componentRuntimeSchema, Binding: r.custody.binding(), Token: rand.Text()}
		for i := range desired {
			r.journal.Components[i] = componentRecord{Release: desired[i], Spec: specs[i], Parent: parents[i],
				Snapshot: desired[i].Role + "-" + r.journal.Token, Stage: "snapshot-intent"}
			if err := r.bindSources(i); err != nil {
				return err
			}
		}
		if err := r.save(); err != nil {
			return err
		}
	}
	// A partial preparation never becomes a cache hit after an interrupted pull.
	for _, c := range r.journal.Components {
		if c.Spec == nil {
			return errComponentCustody
		}
	}
	for i := range 2 {
		if err := r.ensure(ctx, i); err != nil {
			return err
		}
	}
	return nil
}

func (r *componentRuntime) expose(ctx context.Context, o *owner, material region.NetBirdComponents) error {
	r.mu.Lock()
	defer r.mu.Unlock()
	ctx, cancel, err := r.authorized(ctx, o, material)
	if err != nil {
		return err
	}
	defer cancel()
	defer r.guard.Store(&componentGuard{runtime: r})
	desired, err := desiredComponents(ctx, o, material)
	if err != nil {
		return err
	}
	if !r.matches(desired) || r.journal.Next != [3]componentRelease{} {
		return errComponentCustody
	}
	for i := range 2 {
		ctr, err := r.container(ctx, i)
		if err != nil {
			return err
		}
		task, err := ctr.Task(ctx, nil)
		if err != nil {
			return err
		}
		status, err := task.Status(ctx)
		if err != nil || status.Status != containerd.Running {
			return errors.Join(errComponentCustody, err)
		}
		if err := r.retainChild(i, task, false); err != nil {
			return err
		}
	}
	return r.ensure(ctx, 2)
}

func (r *componentRuntime) noUnrecordedContainers(ctx context.Context) error {
	for _, role := range componentRoles() {
		_, err := r.client.LoadContainer(ctx, role)
		if !errdefs.IsNotFound(err) {
			return errors.Join(errComponentCustody, err)
		}
	}
	return nil
}

func (r *componentRuntime) cgroupPath(role string) string {
	binding, _ := componentHash(r.custody.binding())
	return "/terrascale-netbird/" + binding + "/" + role
}

func (r *componentRuntime) specification(ctx context.Context, image containerd.Image, configuration componentConfiguration, index int) (*spec.Spec, error) {
	if len(configuration.Args) == 0 || !filepath.IsAbs(configuration.Args[0]) || configuration.Memory == 0 || configuration.Memory > math.MaxInt64 {
		return nil, errComponentCustody
	}
	config, err := image.Spec(ctx)
	if err != nil {
		return nil, err
	}
	if config.OS != "linux" || config.Architecture != "arm64" {
		return nil, errComponentAdmission
	}
	cwd := config.Config.WorkingDir
	if cwd == "" {
		cwd = "/"
	}
	var capabilities []string
	if index == 1 {
		capabilities = []string{"CAP_SETUID", "CAP_SETGID", "CAP_CHOWN"}
	}
	if index == 2 {
		capabilities = []string{"CAP_NET_BIND_SERVICE"}
	}
	opts := []oci.SpecOpts{
		oci.WithProcessArgs(configuration.Args...), oci.WithEnv(config.Config.Env), oci.WithEnv(configuration.Env),
		oci.WithProcessCwd(cwd), oci.WithUIDGID(0, 0), oci.WithNoNewPrivileges,
		oci.WithCapabilities(capabilities), seccomp.WithDefaultProfile(), oci.WithPidsLimit(256),
		oci.WithMemoryLimit(configuration.Memory), oci.WithMemorySwap(int64(configuration.Memory)),
		oci.WithCPUCFS(100_000, 100_000), oci.WithHostNamespace(spec.NetworkNamespace),
		oci.WithCgroup(r.cgroupPath(componentRoles()[index])), oci.WithMounts(configuration.Mounts),
	}
	if index != 1 {
		opts = append(opts, oci.WithRootFSReadonly())
	}
	for _, m := range configuration.Mounts {
		if m.Type != "bind" || !strings.HasPrefix(m.Source, r.custody.rootPath()+"/") || filepath.Clean(m.Source) != m.Source ||
			!filepath.IsAbs(m.Destination) || filepath.Clean(m.Destination) != m.Destination || m.Destination == "/" ||
			!slices.Contains(m.Options, "nosuid") || !slices.Contains(m.Options, "nodev") {
			return nil, errComponentCustody
		}
	}
	return oci.GenerateSpec(ctx, r.client, &containers.Container{ID: componentRoles()[index]}, opts...)
}

func (r *componentRuntime) labels(i int) map[string]string {
	c := &r.journal.Components[i]
	return map[string]string{"terrascale.netbird.token": r.journal.Token, "terrascale.netbird.role": c.Release.Role,
		"terrascale.netbird.release": c.Release.Identity, "terrascale.netbird.store": r.journal.Binding.StoreGeneration}
}

func (r *componentRuntime) snapshot(ctx context.Context, i int, create bool) error {
	c := &r.journal.Components[i]
	store := r.client.SnapshotService("native")
	info, err := store.Stat(ctx, c.Snapshot)
	if errdefs.IsNotFound(err) && create {
		c.Stage = "snapshot-intent"
		if err := r.save(); err != nil {
			return err
		}
		if i == 1 {
			_, err = store.Prepare(ctx, c.Snapshot, c.Parent, snapshots.WithLabels(r.labels(i)))
		} else {
			_, err = store.View(ctx, c.Snapshot, c.Parent, snapshots.WithLabels(r.labels(i)))
		}
		if err != nil {
			return err
		}
		info, err = store.Stat(ctx, c.Snapshot)
	}
	if err != nil {
		return err
	}
	kind := snapshots.KindView
	if i == 1 {
		kind = snapshots.KindActive
	}
	if info.Name != c.Snapshot || info.Parent != c.Parent || info.Kind != kind || !reflect.DeepEqual(info.Labels, r.labels(i)) ||
		(!c.SnapshotCreated.IsZero() && !c.SnapshotCreated.Equal(info.Created)) {
		return errComponentCustody
	}
	actual, err := store.Mounts(ctx, c.Snapshot)
	if err != nil {
		return err
	}
	if len(actual) != 1 || actual[0].Type != "bind" || !filepath.IsAbs(actual[0].Source) ||
		(i != 1 && !slices.Contains(actual[0].Options, "ro")) {
		return errComponentCustody
	}
	if c.SnapshotMounts != nil && !reflect.DeepEqual(c.SnapshotMounts, actual) {
		return errComponentCustody
	}
	var expected *componentSource
	if c.Root.Path != "" {
		expected = &c.Root
	}
	pin, err := r.pin(actual[0].Source, expected, false)
	if err != nil {
		return err
	}
	c.Root, c.SnapshotMounts, c.SnapshotCreated = pin.source, actual, info.Created
	return nil
}

func (r *componentRuntime) bindSources(i int) error {
	c := &r.journal.Components[i]
	var sources []componentSource
	for _, m := range c.Spec.Mounts {
		if m.Type != "bind" {
			continue
		}
		var expected *componentSource
		if c.Sources != nil {
			if len(sources) >= len(c.Sources) {
				return errComponentCustody
			}
			expected = &c.Sources[len(sources)]
		}
		pin, err := r.pin(m.Source, expected, false)
		if err != nil {
			return err
		}
		sources = append(sources, pin.source)
	}
	if c.Sources != nil && len(sources) != len(c.Sources) {
		return errComponentCustody
	}
	c.Sources = sources
	return nil
}

func (r *componentRuntime) container(ctx context.Context, i int) (containerd.Container, error) {
	c := &r.journal.Components[i]
	if c.Spec == nil {
		return nil, errComponentCustody
	}
	ctr, err := r.client.LoadContainer(ctx, c.Release.Role)
	if err != nil {
		return nil, err
	}
	info, err := ctr.Info(ctx)
	if err != nil {
		return nil, err
	}
	actual, err := ctr.Spec(ctx)
	if err != nil {
		return nil, err
	}
	if info.ID != c.Release.Role || info.Image != c.Release.Image || info.Snapshotter != "native" || info.SnapshotKey != c.Snapshot ||
		info.Runtime.Name != "io.containerd.runc.v2" ||
		(info.Runtime.Options != nil && (info.Runtime.Options.GetTypeUrl() != "" || len(info.Runtime.Options.GetValue()) != 0)) ||
		info.SandboxID != "" || len(info.Extensions) != 0 ||
		!reflect.DeepEqual(info.Labels, r.labels(i)) || !reflect.DeepEqual(actual, c.Spec) ||
		(!c.ContainerCreated.IsZero() && !c.ContainerCreated.Equal(info.CreatedAt)) {
		return nil, errComponentCustody
	}
	if c.ContainerCreated.IsZero() {
		if c.Stage != "container-intent" {
			return nil, errComponentCustody
		}
		if _, err := ctr.Task(ctx, nil); !errdefs.IsNotFound(err) {
			return nil, errors.Join(errComponentCustody, err)
		}
	}
	if err := r.snapshot(ctx, i, false); err != nil {
		return nil, err
	}
	if err := r.bindSources(i); err != nil {
		return nil, err
	}
	c.ContainerCreated = info.CreatedAt
	return ctr, nil
}

func (r *componentRuntime) ensure(ctx context.Context, i int) error {
	c := &r.journal.Components[i]
	if c.Stage == "task-intent" && c.Process == nil {
		return errComponentCustody
	}
	if err := r.bindSources(i); err != nil {
		return err
	}
	if err := r.save(); err != nil {
		return err
	}
	if err := r.snapshot(ctx, i, true); err != nil {
		return err
	}
	if err := r.save(); err != nil {
		return err
	}
	ctr, err := r.client.LoadContainer(ctx, c.Release.Role)
	if errdefs.IsNotFound(err) {
		if !c.ContainerCreated.IsZero() {
			return errComponentCustody
		}
		c.Stage = "container-intent"
		if err := r.save(); err != nil {
			return err
		}
		ctr, err = r.client.NewContainer(ctx, c.Release.Role, containerd.WithSnapshotter("native"),
			containerd.WithSnapshot(c.Snapshot), containerd.WithSpec(c.Spec),
			containerd.WithRuntime("io.containerd.runc.v2", nil), containerd.WithContainerLabels(r.labels(i)),
			func(_ context.Context, _ *containerd.Client, value *containers.Container) error {
				value.Image = c.Release.Image
				return nil
			})
	}
	if err != nil {
		return err
	}
	ctr, err = r.container(ctx, i)
	if err != nil {
		return err
	}
	if err := r.save(); err != nil {
		return err
	}
	task, err := ctr.Task(ctx, nil)
	if errdefs.IsNotFound(err) {
		if c.Process != nil {
			if err := r.confirmGone(i); err != nil {
				return err
			}
			r.closeChild(i)
			c.Process = nil
		}
		if err := r.makeLogs(ctx, i); err != nil {
			return err
		}
		executable, err := os.Executable()
		if err != nil {
			return err
		}
		executablePin, err := r.pin(executable, nil, false)
		if err != nil {
			return err
		}
		defer func() {
			if pin := r.pins[executable]; pin != nil {
				pin.close()
				delete(r.pins, executable)
			}
		}()
		self, err := componentProcFile("/proc/self/exe", unix.O_PATH)
		if err != nil {
			return errors.Join(errComponentCustody, err)
		}
		node, err := componentNode(self)
		_ = self.Close()
		if err != nil || node != executablePin.source.Nodes[len(executablePin.source.Nodes)-1] || node.Mode&0o111 == 0 {
			return errors.Join(errComponentCustody, err)
		}
		uri, err := cio.LogURIGenerator("binary-v2", executable, map[string]string{"--runtime-logger": r.custody.rootPath() + "/logs"})
		if err != nil {
			return err
		}
		c.Stage = "task-intent"
		if err := r.save(); err != nil {
			return err
		}
		task, err = ctr.NewTask(ctx, cio.LogURI(uri))
		if pin := r.pins[executable]; pin != nil {
			pin.close()
			delete(r.pins, executable)
		}
		if err != nil {
			return err
		}
		if err := r.retainChild(i, task, true); err != nil {
			return err
		}
		c.Stage = "entered"
		if err := r.save(); err != nil {
			return err
		}
	} else if err != nil {
		return err
	}
	if c.Process == nil {
		return errComponentCustody
	}
	if err := componentSameBoot(c.Process); err != nil {
		return err
	}
	status, err := task.Status(ctx)
	if err != nil {
		return err
	}
	if status.Status == containerd.Stopped {
		if err := r.confirmGone(i); err != nil {
			return err
		}
		c.Stage = "delete-task-intent"
		if err := r.save(); err != nil {
			return err
		}
		if _, err := task.Delete(ctx); err != nil {
			return err
		}
		r.closeChild(i)
		c.Process = nil
		c.Stage = "container"
		if err := r.save(); err != nil {
			return err
		}
		return r.ensure(ctx, i)
	}
	if err := r.retainChild(i, task, false); err != nil {
		return err
	}
	switch status.Status {
	case containerd.Running:
		if c.Stage != "starting" && c.Stage != "running" {
			return errComponentCustody
		}
	case containerd.Created:
		c.Stage = "starting"
		if err := r.save(); err != nil {
			return err
		}
		if err := task.Start(ctx); err != nil {
			return err
		}
	default:
		return errComponentCustody
	}
	if err := r.retainChild(i, task, false); err != nil {
		return err
	}
	c.Stage = "running"
	return r.save()
}

func (r *componentRuntime) makeLogs(ctx context.Context, i int) error {
	for _, path := range []string{r.custody.rootPath() + "/logs", r.custody.rootPath() + "/logs/" + componentRoles()[i]} {
		if err := r.guard.Load().before(ctx, "local-create-log-directory"); err != nil {
			return err
		}
		parent, err := r.pin(filepath.Dir(path), nil, false)
		if err != nil {
			return err
		}
		err = unix.Mkdirat(int(parent.files[len(parent.files)-1].Fd()), filepath.Base(path), 0700)
		if err != nil && !errors.Is(err, unix.EEXIST) {
			return err
		}
		if _, err := r.pin(path, nil, false); err != nil {
			return err
		}
	}
	return nil
}

func (r *componentRuntime) quiesce(ctx context.Context) error {
	r.mu.Lock()
	defer r.mu.Unlock()
	return r.quiesceLocked(ctx)
}

func (r *componentRuntime) quiesceLocked(ctx context.Context) (err error) {
	defer func() { r.unresolved = err != nil }()
	if ctx == nil {
		return errComponentCustody
	}
	// Proof expiry cannot cancel cleanup of an entered, directly owned writer.
	cleanup, cancel := context.WithTimeout(context.WithoutCancel(ctx), 45*time.Second)
	defer cancel()
	cleanup = namespaces.WithNamespace(cleanup, componentNamespace)
	r.guard.Store(&componentGuard{runtime: r})
	if err := r.local(); err != nil {
		return err
	}
	if r.journal.Schema == "" {
		return r.noUnrecordedContainers(cleanup)
	}
	for i := 2; i >= 0; i-- {
		if err := r.stop(cleanup, i); err != nil {
			return err
		}
	}
	return nil
}

func (r *componentRuntime) stop(ctx context.Context, i int) error {
	c := &r.journal.Components[i]
	if c.Stage == "task-intent" && c.Process == nil {
		return errComponentCustody
	}
	if r.children[i] != nil && c.Process != nil {
		return r.stopRetained(ctx, i)
	}
	ctr, err := r.client.LoadContainer(ctx, c.Release.Role)
	if errdefs.IsNotFound(err) {
		if c.Process != nil {
			return r.confirmGone(i)
		}
		return nil
	}
	if err != nil {
		return err
	}
	ctr, err = r.container(ctx, i)
	if err != nil {
		return err
	}
	task, err := ctr.Task(ctx, nil)
	if errdefs.IsNotFound(err) {
		if c.Process != nil {
			return r.confirmGone(i)
		}
		return nil
	}
	if err != nil {
		return err
	}
	if c.Process == nil || task.Pid() != uint32(c.Process.PID) {
		return errComponentCustody
	}
	if err := componentSameBoot(c.Process); err != nil {
		return err
	}
	status, err := task.Status(ctx)
	if err != nil {
		return err
	}
	if status.Status == containerd.Stopped {
		if err := r.confirmGone(i); err != nil {
			return err
		}
		c.Stage = "stopped"
		return r.save()
	}
	if status.Status != containerd.Running && status.Status != containerd.Created {
		return errComponentCustody
	}
	if err := r.retainChild(i, task, false); err != nil {
		return err
	}
	return r.stopRetained(ctx, i)
}

func (r *componentRuntime) stopRetained(ctx context.Context, i int) error {
	if err := r.signal(i, unix.SIGTERM); err != nil {
		return err
	}
	if err := r.waitChild(ctx, i, 10*time.Second); err != nil {
		if err := r.signal(i, unix.SIGKILL); err != nil {
			return err
		}
		joined, cancel := context.WithTimeout(context.WithoutCancel(ctx), 5*time.Second)
		defer cancel()
		if err := r.waitChild(joined, i, 5*time.Second); err != nil {
			return err
		}
	}
	if err := r.confirmGone(i); err != nil {
		return err
	}
	r.journal.Components[i].Stage = "stopped"
	return r.save()
}

func componentChildExited(child *componentChild) (bool, error) {
	fds := []unix.PollFd{{Fd: int32(child.pidfd), Events: unix.POLLIN}}
	n, err := unix.Poll(fds, 0)
	if err != nil {
		return false, err
	}
	if fds[0].Revents&(unix.POLLERR|unix.POLLNVAL) != 0 {
		return false, errComponentCustody
	}
	return n == 1 && fds[0].Revents&unix.POLLIN != 0, nil
}

func (r *componentRuntime) waitChild(ctx context.Context, i int, timeout time.Duration) error {
	timer := time.NewTimer(timeout)
	defer timer.Stop()
	tick := time.NewTicker(50 * time.Millisecond)
	defer tick.Stop()
	for {
		if err := r.local(); err != nil {
			return err
		}
		exited, err := componentChildExited(r.children[i])
		if err != nil {
			return errors.Join(errComponentCustody, err)
		}
		if exited && r.confirmGone(i) == nil {
			return nil
		}
		select {
		case <-tick.C:
		case <-ctx.Done():
			return ctx.Err()
		case <-timer.C:
			return errComponentCustody
		}
	}
}

func (r *componentRuntime) remove(ctx context.Context, i int) error {
	c := &r.journal.Components[i]
	ctr, err := r.client.LoadContainer(ctx, c.Release.Role)
	if err != nil && !errdefs.IsNotFound(err) {
		return err
	}
	if err == nil {
		ctr, err = r.container(ctx, i)
		if err != nil {
			return err
		}
		task, err := ctr.Task(ctx, nil)
		if err != nil && !errdefs.IsNotFound(err) {
			return err
		}
		if err == nil {
			if c.Process == nil || task.Pid() != uint32(c.Process.PID) {
				return errComponentCustody
			}
			if err := componentSameBoot(c.Process); err != nil {
				return err
			}
			status, err := task.Status(ctx)
			if err != nil || status.Status != containerd.Stopped {
				return errors.Join(errComponentCustody, err)
			}
			if err := r.confirmGone(i); err != nil {
				return err
			}
			c.Stage = "delete-task-intent"
			if err := r.save(); err != nil {
				return err
			}
			if _, err := task.Delete(ctx); err != nil {
				return err
			}
			r.closeChild(i)
			c.Process = nil
			if err := r.save(); err != nil {
				return err
			}
		}
		c.Stage = "delete-container-intent"
		if err := r.save(); err != nil {
			return err
		}
		if err := ctr.Delete(ctx); err != nil {
			return err
		}
	}
	_, err = r.client.SnapshotService("native").Stat(ctx, c.Snapshot)
	if errdefs.IsNotFound(err) {
		return nil
	}
	if err != nil {
		return err
	}
	if c.Spec == nil {
		return errComponentCustody
	}
	if err := r.snapshot(ctx, i, false); err != nil {
		return err
	}
	c.Stage = "delete-snapshot-intent"
	if err := r.save(); err != nil {
		return err
	}
	// A removed snapshot's path must not remain in the live path-check set.
	if pin := r.pins[c.Root.Path]; pin != nil {
		pin.close()
		delete(r.pins, c.Root.Path)
	}
	if err := r.client.SnapshotService("native").Remove(ctx, c.Snapshot); err != nil {
		return err
	}
	return nil
}

func componentNode(file *os.File) (componentInode, error) {
	var st unix.Stat_t
	if err := unix.Fstat(int(file.Fd()), &st); err != nil {
		return componentInode{}, err
	}
	return componentInode{Device: uint64(st.Dev), Inode: st.Ino, Mode: st.Mode, UID: st.Uid, GID: st.Gid}, nil
}

func openComponentPin(path string, socket bool) (_ *componentPin, err error) {
	if !filepath.IsAbs(path) || filepath.Clean(path) != path {
		return nil, errComponentCustody
	}
	pin := &componentPin{source: componentSource{Path: path}}
	defer func() {
		if err != nil {
			pin.close()
		}
	}()
	fd, err := unix.Open("/", unix.O_PATH|unix.O_DIRECTORY|unix.O_NOFOLLOW|unix.O_CLOEXEC, 0)
	if err != nil {
		return nil, err
	}
	pin.files = append(pin.files, os.NewFile(uintptr(fd), "/"))
	parts := strings.Split(strings.TrimPrefix(path, "/"), "/")
	if path == "/" {
		parts = nil
	}
	for i := 0; i <= len(parts); i++ {
		file := pin.files[len(pin.files)-1]
		node, err := componentNode(file)
		if err != nil {
			return nil, err
		}
		mode := node.Mode & unix.S_IFMT
		if node.UID != 0 || node.GID != 0 || node.Mode&0o002 != 0 ||
			(node.Mode&0o020 != 0 && !(socket && i == len(parts) && mode == unix.S_IFSOCK)) ||
			(i < len(parts) && mode != unix.S_IFDIR) || (i == len(parts) && mode != unix.S_IFDIR && mode != unix.S_IFREG && !(socket && mode == unix.S_IFSOCK)) {
			return nil, errComponentCustody
		}
		pin.source.Nodes = append(pin.source.Nodes, node)
		if i == len(parts) {
			break
		}
		fd, err = unix.Openat(int(file.Fd()), parts[i], unix.O_PATH|unix.O_NOFOLLOW|unix.O_CLOEXEC, 0)
		if err != nil {
			return nil, err
		}
		pin.files = append(pin.files, os.NewFile(uintptr(fd), parts[i]))
	}
	return pin, nil
}

func (pin *componentPin) check() error {
	current, err := openComponentPin(pin.source.Path, pin.source.Path == componentSocket)
	if err != nil {
		return err
	}
	defer current.close()
	if !reflect.DeepEqual(current.source, pin.source) {
		return errComponentCustody
	}
	for i, file := range pin.files {
		node, err := componentNode(file)
		if err != nil || node != pin.source.Nodes[i] {
			return errors.Join(errComponentCustody, err)
		}
	}
	return nil
}

func (pin *componentPin) close() {
	for _, file := range pin.files {
		_ = file.Close()
	}
	clear(pin.files)
}

func (r *componentRuntime) pin(path string, expected *componentSource, socket bool) (*componentPin, error) {
	if pin := r.pins[path]; pin != nil {
		if expected != nil && !reflect.DeepEqual(*expected, pin.source) {
			return nil, errComponentCustody
		}
		if err := pin.check(); err != nil {
			return nil, errors.Join(errComponentCustody, err)
		}
		return pin, nil
	}
	pin, err := openComponentPin(path, socket)
	if err != nil {
		return nil, errors.Join(errComponentCustody, err)
	}
	if expected != nil && !reflect.DeepEqual(*expected, pin.source) {
		pin.close()
		return nil, errComponentCustody
	}
	r.pins[path] = pin
	return pin, nil
}

func (r *componentRuntime) releasePins() {
	for path, pin := range r.pins {
		if path != componentSocket {
			pin.close()
			delete(r.pins, path)
		}
	}
}

func componentBootID() (string, error) {
	wire, err := os.ReadFile("/proc/sys/kernel/random/boot_id")
	id := strings.TrimSpace(string(wire))
	if err != nil || len(id) != 36 {
		return "", errors.Join(errComponentCustody, err)
	}
	return id, nil
}

func componentSameBoot(process *componentProcess) error {
	boot, err := componentBootID()
	if err != nil || boot != process.BootID {
		return errors.Join(errComponentCustody, err)
	}
	return nil
}

func componentProcFile(path string, flags int) (*os.File, error) {
	fd, err := unix.Open(path, flags|unix.O_CLOEXEC, 0)
	if err != nil {
		return nil, err
	}
	return os.NewFile(uintptr(fd), path), nil
}

func componentRootMount(file *os.File) (uint64, error) {
	var st unix.Statx_t
	if err := unix.Statx(int(file.Fd()), "", unix.AT_EMPTY_PATH, unix.STATX_MNT_ID, &st); err != nil {
		return 0, err
	}
	if st.Mask&unix.STATX_MNT_ID == 0 || st.Mnt_id == 0 {
		return 0, errComponentCustody
	}
	return st.Mnt_id, nil
}

func componentMountFile(root *os.File, destination string) (_ *os.File, err error) {
	parts := strings.Split(strings.TrimPrefix(destination, "/"), "/")
	if !filepath.IsAbs(destination) || filepath.Clean(destination) != destination || destination == "/" {
		return nil, errComponentCustody
	}
	fd, err := unix.FcntlInt(root.Fd(), unix.F_DUPFD_CLOEXEC, 0)
	if err != nil {
		return nil, err
	}
	current := os.NewFile(uintptr(fd), "component-root")
	defer func() {
		if current != nil {
			_ = current.Close()
		}
	}()
	for _, name := range parts {
		fd, err := unix.Openat(int(current.Fd()), name, unix.O_PATH|unix.O_NOFOLLOW|unix.O_CLOEXEC, 0)
		if err != nil {
			return nil, err
		}
		next := os.NewFile(uintptr(fd), name)
		_ = current.Close()
		current = next
		node, err := componentNode(current)
		if err != nil || node.Mode&unix.S_IFMT == unix.S_IFLNK {
			return nil, errors.Join(errComponentCustody, err)
		}
	}
	result := current
	current = nil
	return result, nil
}

func (r *componentRuntime) observeChild(i int, pid int) (*componentChild, componentProcess, error) {
	var last error
	for attempt := range 5 {
		child, observed, err := r.observeChildOnce(i, pid)
		if err == nil {
			return child, observed, nil
		}
		last = err
		// runc-init and the dashboard legitimately exec during observation.
		if attempt < 4 {
			time.Sleep(10 * time.Millisecond)
		}
	}
	return nil, componentProcess{}, last
}

func (r *componentRuntime) observeChildOnce(i int, pid int) (_ *componentChild, observed componentProcess, err error) {
	child := &componentChild{pidfd: -1}
	defer func() {
		if err != nil {
			child.close()
			err = errors.Join(errComponentCustody, err)
		}
	}()
	observed.BootID, err = componentBootID()
	if err != nil {
		return nil, observed, err
	}
	child.pidfd, err = unix.PidfdOpen(pid, 0)
	if err != nil {
		return nil, observed, err
	}
	child.witness, err = rootoci.CaptureProcess(pid)
	if err != nil {
		return nil, observed, err
	}
	observed.PID, observed.Start, observed.Cgroup = pid, child.witness.KernelStart(), child.witness.Cgroup()
	if child.witness.Peer().UID != 0 || child.witness.Peer().GID != 0 || strings.TrimSpace(observed.Cgroup) != "0::"+r.cgroupPath(componentRoles()[i]) {
		return nil, observed, errComponentCustody
	}
	status, err := os.ReadFile(fmt.Sprintf("/proc/%d/status", pid))
	if err != nil {
		return nil, observed, err
	}
	privateInit := false
	for line := range strings.SplitSeq(string(status), "\n") {
		fields := strings.Fields(line)
		if len(fields) >= 3 && fields[0] == "NSpid:" && fields[len(fields)-1] == "1" {
			privateInit = true
		}
	}
	if !privateInit {
		return nil, observed, errComponentCustody
	}
	for j, name := range []string{"ns/pid", "ns/mnt", "root"} {
		file, err := componentProcFile(fmt.Sprintf("/proc/%d/%s", pid, name), unix.O_PATH)
		if err != nil {
			return nil, observed, err
		}
		child.files = append(child.files, file)
		node, err := componentNode(file)
		if err != nil {
			return nil, observed, err
		}
		switch j {
		case 0:
			observed.PIDNamespace = node
		case 1:
			observed.MountNamespace = node
		case 2:
			observed.Root = node
			observed.RootMountID, err = componentRootMount(file)
			if err != nil {
				return nil, observed, err
			}
		}
	}
	for j, name := range []string{"pid", "mnt"} {
		file, err := componentProcFile("/proc/self/ns/"+name, unix.O_PATH)
		if err != nil {
			return nil, observed, err
		}
		node, nodeErr := componentNode(file)
		_ = file.Close()
		if nodeErr != nil || (j == 0 && node == observed.PIDNamespace) || (j == 1 && node == observed.MountNamespace) {
			return nil, observed, errors.Join(errComponentCustody, nodeErr)
		}
	}
	c := &r.journal.Components[i]
	if len(c.Root.Nodes) == 0 || observed.Root != c.Root.Nodes[len(c.Root.Nodes)-1] {
		return nil, observed, errComponentCustody
	}
	child.cgroup, err = openComponentPin("/sys/fs/cgroup"+r.cgroupPath(componentRoles()[i]), false)
	if err != nil {
		return nil, observed, err
	}
	observed.CgroupSource = child.cgroup.source
	index := 0
	for _, m := range c.Spec.Mounts {
		if m.Type != "bind" {
			continue
		}
		if index >= len(c.Sources) {
			return nil, observed, errComponentCustody
		}
		file, err := componentMountFile(child.files[2], m.Destination)
		if err != nil {
			return nil, observed, err
		}
		child.files = append(child.files, file)
		node, err := componentNode(file)
		source := c.Sources[index]
		if err != nil || len(source.Nodes) == 0 || node != source.Nodes[len(source.Nodes)-1] {
			return nil, observed, errors.Join(errComponentCustody, err)
		}
		observed.Mounts = append(observed.Mounts, node)
		index++
	}
	if err := child.witness.Verify(); err != nil {
		return nil, observed, err
	}
	if unix.PidfdSendSignal(child.pidfd, 0, nil, 0) != nil {
		return nil, observed, errComponentCustody
	}
	return child, observed, nil
}

func (r *componentRuntime) retainChild(i int, task containerd.Task, entered bool) error {
	c := &r.journal.Components[i]
	if task.Pid() < 2 || (!entered && c.Process == nil) {
		return errComponentCustody
	}
	if c.Process != nil {
		boot, err := componentBootID()
		if err != nil || boot != c.Process.BootID || task.Pid() != uint32(c.Process.PID) {
			return errors.Join(errComponentCustody, err)
		}
	}
	child, observed, err := r.observeChild(i, int(task.Pid()))
	if err != nil {
		return err
	}
	if c.Process != nil && !reflect.DeepEqual(*c.Process, observed) {
		child.close()
		return errComponentCustody
	}
	if retained := r.children[i]; retained != nil {
		defer child.close()
		exited, err := componentChildExited(retained)
		if err != nil || exited || retained.cgroup.check() != nil {
			return errors.Join(errComponentCustody, err)
		}
		return nil
	}
	r.closeChild(i)
	r.children[i] = child
	c.Process = &observed
	return nil
}

func (r *componentRuntime) signal(i int, signal unix.Signal) error {
	if err := r.local(); err != nil {
		return err
	}
	c, child := &r.journal.Components[i], r.children[i]
	if c.Process == nil || child == nil {
		return errComponentCustody
	}
	exited, err := componentChildExited(child)
	if err != nil {
		return errors.Join(errComponentCustody, err)
	}
	if exited {
		return nil
	}
	// Observe the current executable; do not pin runc-init/bash across legitimate exec.
	current, observed, err := r.observeChild(i, c.Process.PID)
	if err != nil {
		return err
	}
	defer current.close()
	if !reflect.DeepEqual(*c.Process, observed) || child.cgroup.check() != nil {
		return errComponentCustody
	}
	if err := current.witness.Verify(); err != nil {
		return errors.Join(errComponentCustody, err)
	}
	if err := unix.PidfdSendSignal(child.pidfd, signal, nil, 0); err != nil && !errors.Is(err, unix.ESRCH) {
		return errors.Join(errComponentCustody, err)
	}
	return nil
}

func componentCgroupEmpty(pin *componentPin) error {
	if err := pin.check(); err != nil {
		if !errors.Is(err, os.ErrNotExist) {
			return err
		}
		parent, parentErr := openComponentPin(filepath.Dir(pin.source.Path), false)
		if parentErr != nil {
			return parentErr
		}
		defer parent.close()
		if !reflect.DeepEqual(parent.source.Nodes, pin.source.Nodes[:len(pin.source.Nodes)-1]) {
			return errComponentCustody
		}
		var st unix.Stat_t
		if err := unix.Fstat(int(pin.files[len(pin.files)-1].Fd()), &st); err != nil {
			return err
		}
		// A populated cgroup cannot be removed; the held directory must be unlinked.
		if st.Nlink == 0 {
			return nil
		}
		return errComponentCustody
	}
	fd, err := unix.Openat(int(pin.files[len(pin.files)-1].Fd()), "cgroup.events", unix.O_RDONLY|unix.O_NOFOLLOW|unix.O_CLOEXEC, 0)
	if err != nil {
		return err
	}
	file := os.NewFile(uintptr(fd), "cgroup.events")
	defer file.Close()
	wire, err := io.ReadAll(io.LimitReader(file, 4097))
	if err != nil || len(wire) > 4096 {
		return errors.Join(errComponentCustody, err)
	}
	for line := range strings.SplitSeq(string(wire), "\n") {
		if line == "populated 0" {
			return nil
		}
	}
	return errComponentCustody
}

func (r *componentRuntime) confirmGone(i int) error {
	if err := r.local(); err != nil {
		return err
	}
	p := r.journal.Components[i].Process
	if p == nil {
		return errComponentCustody
	}
	boot, err := componentBootID()
	if err != nil {
		return err
	}
	if child := r.children[i]; child != nil {
		fds := []unix.PollFd{{Fd: int32(child.pidfd), Events: unix.POLLIN}}
		if n, err := unix.Poll(fds, 0); err != nil || n != 1 || fds[0].Revents&unix.POLLIN == 0 {
			return errors.Join(errComponentCustody, err)
		}
		return componentCgroupEmpty(child.cgroup)
	}
	if boot == p.BootID {
		wire, err := os.ReadFile(fmt.Sprintf("/proc/%d/stat", p.PID))
		if err == nil {
			_, rest, ok := strings.CutLast(string(wire), ") ")
			fields := strings.Fields(rest)
			if !ok || len(fields) < 20 {
				return errComponentCustody
			}
			start, err := strconv.ParseUint(fields[19], 10, 64)
			if err != nil || start == p.Start {
				return errors.Join(errComponentCustody, err)
			}
		} else if !errors.Is(err, os.ErrNotExist) {
			return err
		}
	}
	pin, err := openComponentPin(p.CgroupSource.Path, false)
	if errors.Is(err, os.ErrNotExist) {
		return nil
	}
	if err != nil {
		return err
	}
	defer pin.close()
	if boot != p.BootID || !reflect.DeepEqual(pin.source, p.CgroupSource) {
		return errComponentCustody
	}
	return componentCgroupEmpty(pin)
}

func (child *componentChild) close() {
	if child.witness != nil {
		_ = child.witness.Close()
	}
	if child.pidfd >= 0 {
		_ = unix.Close(child.pidfd)
	}
	for _, file := range child.files {
		_ = file.Close()
	}
	if child.cgroup != nil {
		child.cgroup.close()
	}
}

func (r *componentRuntime) closeChild(i int) {
	if r.children[i] != nil {
		r.children[i].close()
		r.children[i] = nil
	}
}

func (r *componentRuntime) Close() error {
	r.mu.Lock()
	defer r.mu.Unlock()
	if r.closed {
		return nil
	}
	if r.unresolved {
		return errComponentCustody
	}
	for i, c := range r.journal.Components {
		if c.Stage == "task-intent" && c.Process == nil {
			return errComponentCustody
		}
		if c.Process != nil {
			if err := r.confirmGone(i); err != nil {
				return errors.Join(errComponentCustody, err)
			}
		}
	}
	r.closed = true
	for i := range r.children {
		r.closeChild(i)
	}
	for _, pin := range r.pins {
		pin.close()
	}
	clear(r.pins)
	if r.client != nil {
		return r.client.Close()
	}
	return nil
}

type componentRegistryTransport struct {
	guard            *componentGuard
	host, repository string
	credentials      func(string) (string, string, error)
	base             *http.Transport
}

func (t componentRegistryTransport) RoundTrip(request *http.Request) (*http.Response, error) {
	u := request.URL
	if u.Scheme != "https" || u.Host != t.host || u.User != nil || u.Fragment != "" || u.RawPath != "" || u.Opaque != "" ||
		(request.Host != "" && request.Host != t.host) ||
		(request.Method != http.MethodGet && request.Method != http.MethodHead) {
		return nil, errComponentAdmission
	}
	path := "/v2/" + t.repository + "/"
	content := strings.HasPrefix(u.Path, path+"manifests/sha256:") || strings.HasPrefix(u.Path, path+"blobs/sha256:")
	auth := u.Path == "/20180419/docker/token" || u.Path == "/oauth2/token"
	if !content && !auth && u.Path != "/v2/" {
		return nil, errComponentAdmission
	}
	if auth {
		query, err := url.ParseQuery(u.RawQuery)
		if err != nil {
			return nil, errComponentAdmission
		}
		for _, scope := range query["scope"] {
			if scope != "repository:"+t.repository+":pull" {
				return nil, errComponentAdmission
			}
		}
	}
	if err := t.guard.before(request.Context(), "registry-read"); err != nil {
		return nil, err
	}
	if request.Header.Get("Authorization") == "" {
		user, password, err := t.credentials(t.host)
		if err != nil || user == "" || password == "" {
			return nil, errComponentAdmission
		}
		request = request.Clone(request.Context())
		request.SetBasicAuth(user, password)
	}
	return t.base.RoundTrip(request)
}

type componentResolver struct {
	remotes.Resolver
	image string
}

func (r componentResolver) Resolve(ctx context.Context, image string) (string, imagespec.Descriptor, error) {
	if image != r.image {
		return "", imagespec.Descriptor{}, errComponentAdmission
	}
	return r.Resolver.Resolve(ctx, image)
}

func (r componentResolver) Fetcher(ctx context.Context, image string) (remotes.Fetcher, error) {
	if image != r.image {
		return nil, errComponentAdmission
	}
	return r.Resolver.Fetcher(ctx, image)
}

func (componentResolver) Pusher(context.Context, string) (remotes.Pusher, error) {
	return nil, errComponentAdmission
}

func (r *componentRuntime) pull(ctx context.Context, material region.NetBirdComponents, admitted componentRelease) (containerd.Image, error) {
	host, repositoryDigest, ok := strings.Cut(admitted.Image, "/")
	repository, digest, pinned := strings.Cut(repositoryDigest, "@")
	if !ok || !pinned || host == "" || repository == "" || !strings.HasPrefix(digest, "sha256:") || len(digest) != 71 {
		return nil, errComponentAdmission
	}
	guard := r.guard.Load()
	if err := guard.before(ctx, "resolve-pull-credentials"); err != nil {
		return nil, err
	}
	credentials, err := material.ResolvePull(ctx, admitted.Role)
	if err != nil {
		return nil, err
	}
	transport := &http.Transport{DisableKeepAlives: true, TLSHandshakeTimeout: 10 * time.Second}
	defer transport.CloseIdleConnections()
	client := &http.Client{Transport: componentRegistryTransport{guard: guard, host: host, repository: repository, credentials: credentials.ForHost, base: transport},
		Timeout: 30 * time.Second, CheckRedirect: func(*http.Request, []*http.Request) error { return http.ErrUseLastResponse }}
	authorizer := docker.NewDockerAuthorizer(docker.WithAuthClient(client), docker.WithAuthCreds(func(requested string) (string, string, error) {
		if requested != host {
			return "", "", errComponentAdmission
		}
		if err := guard.before(ctx, "dispatch-pull-credentials"); err != nil {
			return "", "", err
		}
		return credentials.ForHost(host)
	}))
	resolver := docker.NewResolver(docker.ResolverOptions{Hosts: func(requested string) ([]docker.RegistryHost, error) {
		if requested != host {
			return nil, errComponentAdmission
		}
		return []docker.RegistryHost{{Client: client, Authorizer: authorizer, Host: host, Scheme: "https", Path: "/v2",
			Capabilities: docker.HostCapabilityPull | docker.HostCapabilityResolve}}, nil
	}})
	image, err := r.client.Pull(ctx, admitted.Image, containerd.WithResolver(componentResolver{Resolver: resolver, image: admitted.Image}))
	if err != nil {
		if errors.Is(err, errComponentCustody) {
			return nil, errComponentCustody
		}
		return nil, errors.New("admitted NetBird image pull is unresolved")
	}
	if image.Target().Digest.String() != digest || (image.Target().MediaType != imagespec.MediaTypeImageManifest && image.Target().MediaType != "application/vnd.docker.distribution.manifest.v2+json") {
		return nil, errComponentAdmission
	}
	config, err := image.Spec(ctx)
	if err != nil {
		return nil, err
	}
	if config.OS != "linux" || config.Architecture != "arm64" {
		return nil, errComponentAdmission
	}
	if err := image.Unpack(ctx, "native"); err != nil {
		return nil, err
	}
	if err := guard.before(ctx, "verify-pull-complete"); err != nil {
		return nil, err
	}
	return image, nil
}
