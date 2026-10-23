package swarmruntime

import (
	"context"
	"encoding/json/v2"

	containerd "github.com/containerd/containerd/v2/client"
	"github.com/containerd/containerd/v2/core/content"
	imagespec "github.com/opencontainers/image-spec/specs-go/v1"
)

// ImageRevision reads the pulled digest's config, without registry access.
// An absent label is reported as empty; signed releases must reject it.
func ImageRevision(ctx context.Context, socket, imageRef string) (string, error) {
	client, err := containerd.New(socket, containerd.WithDefaultNamespace(runtimeNamespace))
	if err != nil {
		return "", err
	}
	defer client.Close()
	image, err := client.GetImage(ctx, imageRef)
	if err != nil {
		return "", err
	}
	config, err := image.Config(ctx)
	if err != nil {
		return "", err
	}
	data, err := content.ReadBlob(ctx, client.ContentStore(), config)
	if err != nil {
		return "", err
	}
	var metadata imagespec.Image
	if err := json.Unmarshal(data, &metadata); err != nil {
		return "", err
	}
	return metadata.Config.Labels["org.opencontainers.image.revision"], nil
}
