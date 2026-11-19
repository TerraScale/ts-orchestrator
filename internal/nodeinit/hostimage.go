package nodeinit

import (
	"fmt"
	"maps"
	"regexp"

	json "encoding/json/v2"

	image "github.com/TerraScale/ts-orchestrator/deploy/image"
	"github.com/TerraScale/ts-orchestrator/internal/fleetregion"
)

const (
	ReleaseURLKey    = "terrascale-release-url"
	ReleaseSHA256Key = "terrascale-release-sha256"
	hostImagesSchema = "terrascale.host-images.v1"
)

var (
	imageOCID     = regexp.MustCompile(`^ocid1\.image\.oc1\.([a-z0-9-]+)\.[a-z0-9]+$`)
	debianRelease = regexp.MustCompile(`^[0-9]+$`)
	hostArches    = map[string]bool{"amd64": true, "arm64": true}
	ampere        = regexp.MustCompile(`\.A[0-9]+\.`)
	regionCodes   = map[string]string{"us-ashburn-1": "iad", "us-phoenix-1": "phx"}
)

func ShapeArch(shape string) string {
	if ampere.MatchString(shape) {
		return "arm64"
	}
	return "amd64"
}

func imageInRegion(imageID, region string) bool {
	match := imageOCID.FindStringSubmatch(imageID)
	return match != nil && (match[1] == region || match[1] == regionCodes[region])
}

type HostImage struct {
	Label   string `json:"label"`
	Arch    string `json:"arch"`
	ImageID string `json:"image_ocid"`
	Debian  string `json:"debian"`
	SHA256  string `json:"sha256"`
}

func PinnedHostImage(label, arch string) (HostImage, bool, error) {
	var manifest struct {
		Schema string      `json:"schema"`
		Images []HostImage `json:"images"`
	}
	if err := json.Unmarshal(image.HostImages, &manifest, json.RejectUnknownMembers(true)); err != nil {
		return HostImage{}, false, fmt.Errorf("deploy/image/host-images.json: %w", err)
	}
	if manifest.Schema != hostImagesSchema || manifest.Images == nil {
		return HostImage{}, false, fmt.Errorf("deploy/image/host-images.json needs schema %s and an images list", hostImagesSchema)
	}
	var pinned HostImage
	found := false
	seen := map[[2]string]bool{}
	for index, entry := range manifest.Images {
		key := [2]string{entry.Label, entry.Arch}
		location, err := fleetregion.Lookup(entry.Label)
		if err != nil || !hostArches[entry.Arch] ||
			!imageInRegion(entry.ImageID, location.OCIRegion) || !debianRelease.MatchString(entry.Debian) || !sha256Hex.MatchString(entry.SHA256) || seen[key] {
			return HostImage{}, false, fmt.Errorf("deploy/image/host-images.json image %d needs a fleet label, amd64 or arm64, an image OCID of that label's OCI region, a Debian release and a lowercase sha256, once per label and arch", index)
		}
		seen[key] = true
		if entry.Label == label && entry.Arch == arch {
			pinned, found = entry, true
		}
	}
	return pinned, found, nil
}

func HostMetadata(binaryURL, sum string) (map[string]string, error) {
	if !sha256Hex.MatchString(sum) || !plainURL.MatchString(binaryURL) {
		return nil, fmt.Errorf("release asset needs a plain https URL and a lowercase sha256")
	}
	return map[string]string{ReleaseURLKey: binaryURL, ReleaseSHA256Key: sum}, nil
}

func HostVolumeMetadata(binaryURL, sum, volumeID, expectedUUID, expectedSerial string, mayFormat bool) (map[string]string, error) {
	if err := checkBinding(volumeID, expectedUUID, expectedSerial, mayFormat); err != nil {
		return nil, err
	}
	metadata, err := HostMetadata(binaryURL, sum)
	if err != nil {
		return nil, err
	}
	maps.Copy(metadata, PoolBinding(volumeID, expectedUUID, mayFormat))
	if expectedSerial != "" {
		metadata[SerialKey] = expectedSerial
	}
	return metadata, nil
}
