package release

import (
	"crypto/sha256"
	"encoding/json/v2"
	"errors"
	"fmt"
	"strings"

	ocispec "github.com/opencontainers/image-spec/specs-go/v1"
)

const MaxContainerIndexBytes = 16 << 10

func verifyContainerIndex(wire []byte, claim ContainerClaim) error {
	_, child, _ := strings.Cut(claim.Image, "@sha256:")
	if claim.QualificationSHA256 == child && len(wire) == 0 {
		return nil
	}
	if len(wire) == 0 || len(wire) > MaxContainerIndexBytes || fmt.Sprintf("%x", sha256.Sum256(wire)) != claim.QualificationSHA256 {
		return errors.New("container qualification requires exact bounded retained OCI index bytes")
	}
	var index ocispec.Index
	if err := json.Unmarshal(wire, &index); err != nil || index.SchemaVersion != 2 || index.MediaType != "" && index.MediaType != ocispec.MediaTypeImageIndex && index.MediaType != "application/vnd.docker.distribution.manifest.list.v2+json" || index.ArtifactType != "" || index.Subject != nil || len(index.Manifests) == 0 || len(index.Manifests) > 512 {
		return errors.New("container qualification root is not a standard OCI platform index")
	}
	matches := 0
	for _, descriptor := range index.Manifests {
		platform := descriptor.Platform
		if platform == nil || platform.OS != "linux" || platform.Architecture != claim.Architecture {
			continue
		}
		matches++
		if descriptor.Digest.String() != "sha256:"+child || descriptor.Digest.Validate() != nil || descriptor.Size <= 0 || descriptor.Size > 8<<20 || descriptor.MediaType != ocispec.MediaTypeImageManifest && descriptor.MediaType != "application/vnd.docker.distribution.manifest.v2+json" || len(descriptor.URLs) != 0 || len(descriptor.Data) != 0 || descriptor.ArtifactType != "" || platform.Variant != "" && !(claim.Architecture == "arm64" && platform.Variant == "v8") || platform.OSVersion != "" || len(platform.OSFeatures) != 0 {
			return errors.New("retained OCI index does not bind the exact native child image")
		}
	}
	if matches != 1 {
		return errors.New("retained OCI index requires one matching Linux architecture child")
	}
	return nil
}
