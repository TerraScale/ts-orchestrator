package vmimage

import (
	"errors"
	"fmt"
	"time"
)

// ServiceReadiness records the exact release observed by the guest health
// gate. A service is not ready merely because its process exists.
type ServiceReadiness struct {
	Component string `json:"component"`
	Version   string `json:"version"`
	SHA256    string `json:"sha256"`
	Ready     bool   `json:"ready"`
	Health    string `json:"health"`
	PID1      int    `json:"pid1"`

	Sha256 string `json:"-"`
}

// ReadinessMetadata is the bounded readiness record exchanged by the test
// controller and guest. Ready is derived from every prerequisite by
// NewReadinessMetadata; Validate rejects forged or incomplete records.
type ReadinessMetadata struct {
	SchemaVersion int                         `json:"schemaVersion"`
	SeedDigest    string                      `json:"seedDigest"`
	ImageDigest   string                      `json:"imageDigest"`
	Architecture  Architecture                `json:"architecture"`
	ImageVersion  string                      `json:"imageVersion"`
	KernelSHA256  string                      `json:"kernelSha256"`
	RootFSSHA256  string                      `json:"rootfsSha256"`
	SystemdPID1   bool                        `json:"systemdPid1"`
	CgroupV2      bool                        `json:"cgroupV2"`
	NetworkReady  bool                        `json:"networkReady"`
	DataDiskReady bool                        `json:"dataDiskReady"`
	TimeReady     bool                        `json:"timeReady"`
	TSNodeReady   bool                        `json:"tsNodeReady"`
	Services      map[string]ServiceReadiness `json:"services"`
	Ready         bool                        `json:"ready"`
	CheckedAt     time.Time                   `json:"checkedAt"`
}

// Readiness is the concise alias used by provider code.
type Readiness = ReadinessMetadata

// NewReadinessMetadata builds a readiness record from independent guest
// observations. All three exact production services are required.
func NewReadinessMetadata(manifest GuestImageManifest, seedDigest string, systemdPID1, cgroupV2, networkReady, dataDiskReady, timeReady bool, services []ServiceReadiness, checkedAt time.Time) (ReadinessMetadata, error) {
	canonical, err := NewManifest(manifest)
	if err != nil {
		return ReadinessMetadata{}, err
	}
	imageDigest, err := canonical.Digest()
	if err != nil {
		return ReadinessMetadata{}, err
	}
	if !sha256Pattern.MatchString(seedDigest) {
		return ReadinessMetadata{}, errors.New("vmimage: readiness image digest must be lowercase SHA-256 hex")
	}
	if checkedAt.IsZero() || checkedAt.Unix() < 0 {
		return ReadinessMetadata{}, errors.New("vmimage: readiness check time is required")
	}
	serviceMap, tsNodeReady, err := canonicalServices(services, canonical.Architecture)
	if err != nil {
		return ReadinessMetadata{}, err
	}
	metadata := ReadinessMetadata{
		SchemaVersion: ManifestSchemaVersion,
		SeedDigest:    seedDigest,
		ImageDigest:   imageDigest,
		Architecture:  canonical.Architecture,
		ImageVersion:  canonical.Version,
		KernelSHA256:  canonical.Kernel.digest(),
		RootFSSHA256:  canonical.RootFS.digest(),
		SystemdPID1:   systemdPID1,
		CgroupV2:      cgroupV2,
		NetworkReady:  networkReady,
		DataDiskReady: dataDiskReady,
		TimeReady:     timeReady,
		TSNodeReady:   tsNodeReady,
		Services:      serviceMap,
		CheckedAt:     checkedAt.UTC(),
	}
	metadata.Ready = metadata.isReady()
	return metadata, nil
}

// EvaluateReadiness is a descriptive alias for NewReadinessMetadata.
func EvaluateReadiness(manifest GuestImageManifest, seedDigest string, systemdPID1, cgroupV2, networkReady, dataDiskReady, timeReady bool, services []ServiceReadiness, checkedAt time.Time) (ReadinessMetadata, error) {
	return NewReadinessMetadata(manifest, seedDigest, systemdPID1, cgroupV2, networkReady, dataDiskReady, timeReady, services, checkedAt)
}

func canonicalServices(services []ServiceReadiness, architecture Architecture) (map[string]ServiceReadiness, bool, error) {
	if len(services) != 3 {
		return nil, false, errors.New("vmimage: readiness requires exactly ts-node, orchestrator, and terrabase")
	}
	result := make(map[string]ServiceReadiness, len(services))
	for _, service := range services {
		if service.Component != "ts-node" && service.Component != "orchestrator" && service.Component != "terrabase" {
			return nil, false, fmt.Errorf("vmimage: readiness service %q is not admitted", service.Component)
		}
		if _, exists := result[service.Component]; exists {
			return nil, false, fmt.Errorf("vmimage: duplicate readiness service %q", service.Component)
		}
		if !versionPattern.MatchString(service.Version) || !sha256Pattern.MatchString(service.digest()) || service.PID1 <= 0 || service.Health != "healthy" {
			return nil, false, fmt.Errorf("vmimage: readiness service %q is incomplete", service.Component)
		}
		if service.Component == "ts-node" && architecture != ArchitectureAMD64 && architecture != ArchitectureARM64 {
			return nil, false, errors.New("vmimage: readiness architecture is invalid")
		}
		service.SHA256 = service.digest()
		service.Sha256 = ""
		result[service.Component] = service
	}
	for _, component := range ArtifactComponents() {
		if _, ok := result[component]; !ok {
			return nil, false, fmt.Errorf("vmimage: missing readiness service %q", component)
		}
	}
	return result, result["ts-node"].Ready, nil
}

func (service ServiceReadiness) digest() string {
	if service.SHA256 != "" && service.Sha256 != "" && service.SHA256 != service.Sha256 {
		return ""
	}
	if service.SHA256 != "" {
		return service.SHA256
	}
	return service.Sha256
}

func (metadata ReadinessMetadata) isReady() bool {
	if !metadata.SystemdPID1 || !metadata.CgroupV2 || !metadata.NetworkReady || !metadata.DataDiskReady || !metadata.TimeReady || !metadata.TSNodeReady {
		return false
	}
	if len(metadata.Services) != 3 {
		return false
	}
	for _, component := range ArtifactComponents() {
		service, ok := metadata.Services[component]
		if !ok || !service.Ready || service.Health != "healthy" || service.PID1 <= 0 {
			return false
		}
	}
	return true
}

// IsReady reports whether all readiness dimensions and all required service
// health gates are true.
func (metadata ReadinessMetadata) IsReady() bool { return metadata.Ready && metadata.isReady() }

// Validate checks correlation fields and rejects a caller-provided Ready bit
// that does not match the independently derived state.
func (metadata ReadinessMetadata) Validate(manifest GuestImageManifest, seedDigest string) error {
	canonical, err := NewManifest(manifest)
	if err != nil {
		return err
	}
	imageDigest, err := canonical.Digest()
	if err != nil {
		return err
	}
	if metadata.SchemaVersion != ManifestSchemaVersion || metadata.SeedDigest != seedDigest || metadata.ImageDigest != imageDigest || metadata.ImageVersion != canonical.Version || metadata.Architecture != canonical.Architecture || metadata.KernelSHA256 != canonical.Kernel.digest() || metadata.RootFSSHA256 != canonical.RootFS.digest() {
		return errors.New("vmimage: readiness metadata does not match image")
	}
	if !sha256Pattern.MatchString(seedDigest) {
		return errors.New("vmimage: readiness seed digest is invalid")
	}
	if metadata.Services == nil || len(metadata.Services) != 3 || metadata.TSNodeReady != metadata.Services["ts-node"].Ready {
		return errors.New("vmimage: readiness service set is incomplete")
	}
	for _, component := range ArtifactComponents() {
		if _, ok := metadata.Services[component]; !ok {
			return fmt.Errorf("vmimage: readiness service %q is missing", component)
		}
	}
	for _, service := range metadata.Services {
		if !sha256Pattern.MatchString(service.digest()) || service.Health != "healthy" || service.PID1 <= 0 {
			return errors.New("vmimage: readiness contains an unhealthy service")
		}
	}
	if metadata.Ready != metadata.isReady() {
		return errors.New("vmimage: readiness Ready bit is inconsistent")
	}
	return nil
}
