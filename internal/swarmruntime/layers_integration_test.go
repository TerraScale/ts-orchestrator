package swarmruntime

import (
	"context"
	"fmt"
	"runtime"
	"testing"
	"time"

	"github.com/moby/swarmkit/v2/api"
)

// traefik/whoami v1.11 has three layers; the single-layer integrationImage
// cannot catch a chain-ID mismatch between the disk witness and the snapshot.
var integrationMultiLayerImage = map[string]string{
	"amd64": "docker.io/traefik/whoami@sha256:4f90b33ddca9c4d4f06527070d6e503b16d71016edea036842be2a84e60c91cb",
	"arm64": "docker.io/traefik/whoami@sha256:c2c89736959e8830c3db090e2f54500499ceb0460267f91dce494728d7327770",
}[runtime.GOARCH]

func TestContainerdMultiLayerImageStarts(t *testing.T) {
	if *integrationSocket == "" {
		t.Skip("runs in the containerd workflow, which passes -containerd-socket")
	}
	ctx, cancel := context.WithTimeout(t.Context(), 2*time.Minute)
	defer cancel()
	e, err := newIntegrationExecutor(*integrationSocket, t.TempDir())
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = e.Close() })
	runtime, err := ContainerRuntime(&api.ContainerSpec{Image: integrationMultiLayerImage, User: "65532:65532", Args: []string{"--port", "35003"}})
	if err != nil {
		t.Fatal(err)
	}
	task := &api.Task{ID: fmt.Sprintf("layers%d", time.Now().UnixNano()), ServiceID: "layersintegration",
		Spec: api.TaskSpec{Runtime: runtime, Resources: containerTestResources(250_000_000, 64<<20)}}
	c, err := integrationContainerController(e, task)
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() {
		cleanup, stop := context.WithTimeout(context.Background(), 20*time.Second)
		defer stop()
		_ = c.Remove(cleanup)
	})
	if err := c.Prepare(ctx); err != nil {
		t.Fatal(err)
	}
	if err := c.Start(ctx); err != nil {
		t.Fatal(err)
	}
}
