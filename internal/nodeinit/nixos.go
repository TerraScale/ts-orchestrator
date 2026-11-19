package nodeinit

import (
	"bytes"
	"encoding/json"
	"fmt"
	"maps"
	"regexp"

	image "github.com/TerraScale/ts-orchestrator/deploy/image"
)

const (
	ReleaseURLKey     = "terrascale-release-url"
	ReleaseSHA256Key  = "terrascale-release-sha256"
	nixosImagesSchema = "terrascale.nixos-images.v1"
)

var (
	ociRegion    = regexp.MustCompile(`^[a-z]+-[a-z]+-[0-9]+$`)
	imageOCID    = regexp.MustCompile(`^ocid1\.image\.oc[0-9]+\.[a-z0-9-]+\.[a-z0-9]+$`)
	nixosRelease = regexp.MustCompile(`^[0-9]{2}\.[0-9]{2}`)
	systems      = map[string]string{"amd64": "x86_64-linux", "arm64": "aarch64-linux"}
)

type NixOSImage struct {
	Region  string `json:"region"`
	Arch    string `json:"arch"`
	ImageID string `json:"image_ocid"`
	NixOS   string `json:"nixos"`
	System  string `json:"system"`
	SHA256  string `json:"sha256"`
}

func PinnedNixOSImage(region, arch string) (NixOSImage, bool, error) {
	var manifest struct {
		Schema string       `json:"schema"`
		Images []NixOSImage `json:"images"`
	}
	decoder := json.NewDecoder(bytes.NewReader(image.NixOSImages))
	decoder.DisallowUnknownFields()
	if err := decoder.Decode(&manifest); err != nil {
		return NixOSImage{}, false, fmt.Errorf("deploy/image/nixos-images.json: %w", err)
	}
	if manifest.Schema != nixosImagesSchema || manifest.Images == nil {
		return NixOSImage{}, false, fmt.Errorf("deploy/image/nixos-images.json needs schema %s and an images list", nixosImagesSchema)
	}
	var pinned NixOSImage
	found := false
	seen := map[[2]string]bool{}
	for index, entry := range manifest.Images {
		key := [2]string{entry.Region, entry.Arch}
		if !ociRegion.MatchString(entry.Region) || systems[entry.Arch] == "" || systems[entry.Arch] != entry.System ||
			!imageOCID.MatchString(entry.ImageID) || !nixosRelease.MatchString(entry.NixOS) || !sha256Hex.MatchString(entry.SHA256) || seen[key] {
			return NixOSImage{}, false, fmt.Errorf("deploy/image/nixos-images.json image %d needs an OCI region, amd64 or arm64 with its system, an image OCID, a NixOS release and a lowercase sha256, once per region and arch", index)
		}
		seen[key] = true
		if entry.Region == region && entry.Arch == arch {
			pinned, found = entry, true
		}
	}
	return pinned, found, nil
}

func NixOSMetadata(binaryURL, sum string) (map[string]string, error) {
	if !sha256Hex.MatchString(sum) || !plainURL.MatchString(binaryURL) {
		return nil, fmt.Errorf("release asset needs a plain https URL and a lowercase sha256")
	}
	return map[string]string{ReleaseURLKey: binaryURL, ReleaseSHA256Key: sum}, nil
}

func NixOSHostMetadata(binaryURL, sum, volumeID, expectedUUID, expectedSerial string, mayFormat bool) (map[string]string, error) {
	if err := checkBinding(volumeID, expectedUUID, expectedSerial, mayFormat); err != nil {
		return nil, err
	}
	metadata, err := NixOSMetadata(binaryURL, sum)
	if err != nil {
		return nil, err
	}
	maps.Copy(metadata, PoolBinding(volumeID, expectedUUID, mayFormat))
	if expectedSerial != "" {
		metadata[SerialKey] = expectedSerial
	}
	return metadata, nil
}
