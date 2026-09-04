package vmimage

import (
	"bytes"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"path/filepath"
	"strings"
)

// BuildPlanSchemaVersion is bumped when the reproducible image preparation
// contract changes. A plan contains no timestamps, host paths, or credentials,
// so its canonical bytes can be checked into CI evidence and compared across
// machines.
const BuildPlanSchemaVersion = 1

const maxBuildPlanBytes = 64 << 10

// BuildStep describes one deterministic operation in image preparation. The
// qualification image is a raw Ubuntu/systemd disk pair, never an OCI image.
type BuildStep struct {
	Name   string   `json:"name"`
	Inputs []string `json:"inputs"`
	Output string   `json:"output"`
}

// BuildPlan is the auditable plan used by Cache.Install. It intentionally
// describes verification and immutable publication rather than shell
// commands: no remote installer, package manager, or container runtime is
// hidden behind this API.
type BuildPlan struct {
	SchemaVersion  int                `json:"schemaVersion"`
	UbuntuRelease  string             `json:"ubuntuRelease"`
	Architecture   Architecture       `json:"architecture"`
	Version        string             `json:"version"`
	Manifest       GuestImageManifest `json:"manifest"`
	ManifestDigest string             `json:"manifestDigest"`
	CacheEntry     string             `json:"cacheEntry"`
	Steps          []BuildStep        `json:"steps"`
}

// NewBuildPlan returns the deterministic preparation plan and the exact
// digest-keyed cache destination for a manifest.
func NewBuildPlan(manifest GuestImageManifest, cacheRoot string) (BuildPlan, error) {
	canonical, err := NewManifest(manifest)
	if err != nil {
		return BuildPlan{}, err
	}
	if cacheRoot == "" || !filepath.IsAbs(cacheRoot) || strings.ContainsRune(cacheRoot, 0) {
		return BuildPlan{}, errors.New("vmimage: build plan cache root must be an absolute path")
	}
	digest, err := canonical.Digest()
	if err != nil {
		return BuildPlan{}, err
	}
	entry := filepath.Join(filepath.Clean(cacheRoot), string(canonical.Architecture), canonical.Version, digest)
	steps := expectedBuildSteps(canonical, digest)
	return BuildPlan{SchemaVersion: BuildPlanSchemaVersion, UbuntuRelease: canonical.UbuntuRelease, Architecture: canonical.Architecture, Version: canonical.Version, Manifest: canonical, ManifestDigest: digest, CacheEntry: entry, Steps: steps}, nil
}

// Validate checks the plan's digest and immutable cache destination. It is
// safe to call on data read from a cache entry before using that entry.
func (plan BuildPlan) Validate() error {
	if plan.SchemaVersion != BuildPlanSchemaVersion {
		return fmt.Errorf("vmimage: unsupported build plan schema %d", plan.SchemaVersion)
	}
	canonical, err := NewManifest(plan.Manifest)
	if err != nil {
		return err
	}
	digest, err := canonical.Digest()
	if err != nil {
		return err
	}
	if plan.ManifestDigest != digest || plan.UbuntuRelease != canonical.UbuntuRelease || plan.Architecture != canonical.Architecture || plan.Version != canonical.Version {
		return errors.New("vmimage: build plan manifest digest or identity is inconsistent")
	}
	if plan.CacheEntry == "" || !filepath.IsAbs(plan.CacheEntry) {
		return errors.New("vmimage: build plan cache entry must be absolute")
	}
	expected := expectedBuildSteps(canonical, digest)
	if !buildStepsEqual(plan.Steps, expected) {
		return errors.New("vmimage: build plan steps are incomplete or inconsistent")
	}
	return nil
}

func expectedBuildSteps(manifest GuestImageManifest, digest string) []BuildStep {
	steps := []BuildStep{
		{Name: "verify-kernel", Inputs: []string{manifest.Kernel.Source, manifest.Kernel.SHA256, fmt.Sprintf("%d", manifest.Kernel.Size)}, Output: manifest.Kernel.Name},
	}
	if manifest.RootFS.Transform == nil {
		steps = append(steps, BuildStep{Name: "verify-rootfs", Inputs: []string{manifest.RootFS.Source, manifest.RootFS.SHA256, fmt.Sprintf("%d", manifest.RootFS.Size)}, Output: manifest.RootFS.Name})
	} else {
		transform := manifest.RootFS.Transform
		steps = append(steps,
			BuildStep{Name: "verify-rootfs-input", Inputs: []string{manifest.RootFS.Source, manifest.RootFS.InputSHA256, fmt.Sprintf("%d", manifest.RootFS.InputSize)}, Output: manifest.RootFS.Name + ".input"},
			BuildStep{Name: "convert-qcow2-to-raw", Inputs: []string{manifest.RootFS.Name + ".input", "qcow2"}, Output: manifest.RootFS.Name + ".raw"},
			BuildStep{Name: "extract-root-partition", Inputs: []string{fmt.Sprintf("%d", transform.SectorSize), fmt.Sprintf("%d", transform.StartSector), fmt.Sprintf("%d", transform.SectorCount), manifest.RootFS.SHA256, fmt.Sprintf("%d", manifest.RootFS.Size)}, Output: manifest.RootFS.Name},
		)
	}
	return append(steps, BuildStep{Name: "publish-manifest", Inputs: []string{digest}, Output: "manifest.json"})
}

func buildStepsEqual(left, right []BuildStep) bool {
	if len(left) != len(right) {
		return false
	}
	for index := range left {
		if left[index].Name != right[index].Name || left[index].Output != right[index].Output || len(left[index].Inputs) != len(right[index].Inputs) {
			return false
		}
		for inputIndex := range left[index].Inputs {
			if left[index].Inputs[inputIndex] != right[index].Inputs[inputIndex] {
				return false
			}
		}
	}
	return true
}

// CanonicalJSON returns stable plan bytes suitable for writing to the cache.
func (plan BuildPlan) CanonicalJSON() ([]byte, error) {
	if err := plan.Validate(); err != nil {
		return nil, err
	}
	return json.Marshal(plan)
}

// DecodeBuildPlan strictly decodes one plan document and checks all derived
// fields. Trailing JSON values are rejected to avoid ambiguous cache state.
func DecodeBuildPlan(data []byte) (BuildPlan, error) {
	if len(data) == 0 || len(data) > maxBuildPlanBytes {
		return BuildPlan{}, errors.New("vmimage: build plan size is outside the permitted range")
	}
	decoder := json.NewDecoder(bytes.NewReader(data))
	decoder.DisallowUnknownFields()
	var plan BuildPlan
	if err := decoder.Decode(&plan); err != nil {
		return BuildPlan{}, fmt.Errorf("vmimage: decode build plan: %w", err)
	}
	var extra any
	if err := decoder.Decode(&extra); err != io.EOF {
		return BuildPlan{}, errors.New("vmimage: build plan contains trailing data")
	}
	if err := plan.Validate(); err != nil {
		return BuildPlan{}, err
	}
	return plan, nil
}
