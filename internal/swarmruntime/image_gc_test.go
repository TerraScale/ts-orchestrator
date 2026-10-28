package swarmruntime

import (
	"path/filepath"
	"strings"
	"testing"

	"github.com/TerraScale/ts-orchestrator/internal/storage/execution"
	containerd "github.com/containerd/containerd/v2/client"
	"github.com/containerd/containerd/v2/core/containers"
	"github.com/containerd/containerd/v2/core/images"
	"github.com/containerd/containerd/v2/core/metadata"
	"github.com/containerd/errdefs"
	"github.com/moby/swarmkit/v2/api"
	"github.com/opencontainers/go-digest"
	imagespec "github.com/opencontainers/image-spec/specs-go/v1"
	bolt "go.etcd.io/bbolt"
	"google.golang.org/protobuf/types/known/anypb"
)

func TestImageGCProtectsContainersDesiredRollbackFloorAndPulls(t *testing.T) {
	ctx := runtimeContext(t.Context())
	db, err := bolt.Open(filepath.Join(t.TempDir(), "metadata.db"), 0600, nil)
	if err != nil {
		t.Fatal(err)
	}
	defer db.Close()
	md := metadata.NewDB(db, nil, nil)
	store, ctrs := metadata.NewImageStore(md), metadata.NewContainerStore(md)
	client, err := containerd.New("", containerd.WithServices(containerd.WithImageStore(store), containerd.WithContainerStore(ctrs)))
	if err != nil {
		t.Fatal(err)
	}
	defer client.Close()
	e := &Executor{client: client, logRoot: t.TempDir()}
	refs := []string{}
	for _, name := range []string{"desired", "current", "rollback", "floor", "container", "obsolete"} {
		target := imagespec.Descriptor{Digest: digest.FromString(name), Size: 1, MediaType: imagespec.MediaTypeImageManifest}
		ref := "ghcr.io/terrascale/web@" + target.Digest.String()
		if _, err := store.Create(ctx, images.Image{Name: ref, Target: target}); err != nil {
			t.Fatal(err)
		}
		refs = append(refs, ref)
	}
	if _, err := ctrs.Create(ctx, containers.Container{ID: "stopped", Spec: &anypb.Any{TypeUrl: "test.container"}, Image: refs[4], Runtime: containers.RuntimeInfo{Name: "runc"}}); err != nil {
		t.Fatal(err)
	}
	spec := func(ref string) api.ServiceSpec {
		runtime, err := ContainerRuntime(&api.ContainerSpec{Image: ref, User: "65532:65532"})
		if err != nil {
			t.Fatal(err)
		}
		return api.ServiceSpec{Annotations: api.Annotations{Name: "web"}, Task: api.TaskSpec{Runtime: runtime}}
	}
	service := &api.Service{Spec: spec(refs[1]), PreviousSpec: new(spec(refs[2]))}
	service.Spec.Task.GetGeneric().Kind = execution.StatefulContainerKind
	service.Spec.Annotations.Labels = map[string]string{LabelDeploymentFloor: `{"repository":"TerraScale/web","runId":"1","revision":"` + strings.Repeat("a", 40) + `","image":"` + refs[3] + `"}`}
	guard, err := e.imageGuard(ctx)
	if err != nil {
		t.Fatal(err)
	}
	// A different executor must see the pending pull/prepare's shared lock.
	other := &Executor{client: client, logRoot: e.logRoot}
	if err := other.CollectImages(ctx, []*api.Service{service}, refs[0]); err != nil {
		t.Fatal(err)
	}
	if _, err := store.Get(ctx, refs[5]); err != nil {
		t.Fatal("collection raced pending prepare", err)
	}
	_ = guard.Close()
	if err := other.CollectImages(ctx, []*api.Service{service}, refs[0]); err != nil {
		t.Fatal(err)
	}
	for _, ref := range refs[:5] {
		if _, err := store.Get(ctx, ref); err != nil {
			t.Fatal("protected image removed", ref, err)
		}
	}
	if _, err := store.Get(ctx, refs[5]); !errdefs.IsNotFound(err) {
		t.Fatalf("obsolete image retained: %v", err)
	}
}
