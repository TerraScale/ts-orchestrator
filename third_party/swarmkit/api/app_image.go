package api

import (
	"bytes"
	"regexp"
	"strings"
)

var appImageIdentity = regexp.MustCompile(`^[a-z0-9][a-z0-9._-]{0,127}@sha256:[0-9a-f]{64}$`)

func CanonicalAppImage(image string) string {
	identity := strings.TrimPrefix(image, "ghcr.io/terrascale/")
	if appImageIdentity.MatchString(identity) {
		return identity
	}
	return image
}

func CanonicalTaskSpec(spec *TaskSpec) *TaskSpec {
	canonical := spec.Copy()
	runtime := canonical.GetGeneric()
	if runtime == nil || runtime.Kind != "terrascale.container.v1" || runtime.Payload == nil || runtime.Payload.TypeUrl != "terrascale.tech/runtime/container/v1" {
		return canonical
	}
	var container ContainerSpec
	if container.Unmarshal(runtime.Payload.Value) != nil {
		return canonical
	}
	if data, err := container.Marshal(); err != nil || !bytes.Equal(data, runtime.Payload.Value) {
		return canonical
	}
	image := CanonicalAppImage(container.Image)
	if image == container.Image {
		return canonical
	}
	container.Image = image
	if data, err := container.Marshal(); err == nil {
		runtime.Payload.Value = data
	}
	return canonical
}
