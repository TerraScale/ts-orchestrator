package hostcontrol

import (
	"bytes"
	"context"
	"crypto/ed25519"
	"encoding/json/jsontext"
	"encoding/json/v2"
	"errors"
	"fmt"
	"strings"

	"terrascale.tech/orchestrator/src/orchestrator/bootstrapcredentials"
	"terrascale.tech/orchestrator/src/orchestrator/hostagent"
	"terrascale.tech/orchestrator/src/orchestrator/hostmanifest"
	runtimeplan "terrascale.tech/orchestrator/src/orchestrator/runtime"
)

const MaximumReleaseCatalogBytes = 4 << 20

// SignedReleaseCatalogEnvelope authenticates the exact decoded payload bytes.
// Payload and Signature use standard base64 JSON strings.
type SignedReleaseCatalogEnvelope struct {
	KeyID     string `json:"keyId"`
	Payload   []byte `json:"payload"`
	Signature []byte `json:"signature"`
}

type ReleaseCatalogPayload struct {
	SchemaVersion int                   `json:"schemaVersion"`
	Releases      []ReleaseCatalogEntry `json:"releases"`
}

// ReleaseCatalogEntry carries the entire desired host manifest, including
// components unaffected by this release. Omission means desired removal.
type ReleaseCatalogEntry struct {
	HostID                 string         `json:"hostId"`
	Architecture           string         `json:"architecture"`
	Service                string         `json:"service"`
	Version                string         `json:"version"`
	ArtifactSHA256         string         `json:"artifactSha256"`
	ExpectedManifestSHA256 string         `json:"expectedManifestSha256"`
	Manifest               jsontext.Value `json:"manifest"`
}

// SignedReleaseCatalog reads a source file for every resolution; it never derives
// desired state or CAS predecessors from host observations.
type SignedReleaseCatalog struct {
	path  string
	trust map[string]ed25519.PublicKey
}

func NewSignedReleaseCatalog(path string, trust map[string]ed25519.PublicKey) (*SignedReleaseCatalog, error) {
	if strings.TrimSpace(path) == "" || len(trust) == 0 {
		return nil, errors.New("hostcontrol: release catalog path and explicit signing trust are required")
	}
	keys := make(map[string]ed25519.PublicKey, len(trust))
	for id, key := range trust {
		if strings.TrimSpace(id) == "" || len(key) != ed25519.PublicKeySize {
			return nil, errors.New("hostcontrol: invalid release catalog signing trust")
		}
		keys[id] = bytes.Clone(key)
	}
	return &SignedReleaseCatalog{path: path, trust: keys}, nil
}

func (c *SignedReleaseCatalog) ResolveRelease(ctx context.Context, host string, plan runtimeplan.HostRuntimePlan) (Release, error) {
	if ctx == nil {
		return Release{}, errors.New("hostcontrol: release context required")
	}
	if err := ctx.Err(); err != nil {
		return Release{}, err
	}
	if strings.TrimSpace(host) == "" || (plan.Architecture != runtimeplan.HostArchitectureX64 && plan.Architecture != runtimeplan.HostArchitectureArm64) || plan.SchemaVersion != 2 || plan.Role != runtimeplan.AdmittedRoleTerraBaseMember || plan.Driver != runtimeplan.RuntimeDriverNativeSystemd || plan.Systemd == nil || plan.AllocationId.Value != "terrabase" || plan.Systemd.UnitName != hostagent.UnitName(plan.AllocationId.Value) {
		return Release{}, errors.New("hostcontrol: invalid release runtime plan")
	}
	entries, err := c.load(ctx)
	if err != nil {
		return Release{}, err
	}
	for _, entry := range entries {
		if entry.identity == [4]string{host, plan.Architecture.String(), plan.AllocationId.Value, plan.ArtifactDigest.Value} {
			return entry.release, nil
		}
	}
	return Release{}, errors.New("hostcontrol: no signed release matches host runtime plan")
}

// Validate authenticates the current source and validates every complete entry.
// Call before admitting listeners; resolution repeats validation for file updates.
func (c *SignedReleaseCatalog) Validate(ctx context.Context) error {
	_, err := c.load(ctx)
	return err
}

type validatedCatalogEntry struct {
	identity [4]string
	release  Release
}

func (c *SignedReleaseCatalog) load(ctx context.Context) ([]validatedCatalogEntry, error) {
	if ctx == nil {
		return nil, errors.New("hostcontrol: release context required")
	}
	if err := ctx.Err(); err != nil {
		return nil, err
	}
	data, err := bootstrapcredentials.ReadFile(c.path, false, MaximumReleaseCatalogBytes)
	if err != nil {
		return nil, fmt.Errorf("hostcontrol: read release catalog: %w", err)
	}
	var envelope SignedReleaseCatalogEnvelope
	if err := json.Unmarshal(data, &envelope, json.RejectUnknownMembers(true)); err != nil {
		return nil, fmt.Errorf("hostcontrol: release envelope: %w", err)
	}
	key, ok := c.trust[envelope.KeyID]
	if !ok || !ed25519.Verify(key, envelope.Payload, envelope.Signature) {
		return nil, errors.New("hostcontrol: release catalog signature rejected")
	}
	var payload ReleaseCatalogPayload
	if err := json.Unmarshal(envelope.Payload, &payload, json.RejectUnknownMembers(true)); err != nil {
		return nil, fmt.Errorf("hostcontrol: release payload: %w", err)
	}
	if payload.SchemaVersion != 1 || len(payload.Releases) == 0 || len(payload.Releases) > 1024 {
		return nil, errors.New("hostcontrol: invalid release catalog schema or entry count")
	}
	var entries []validatedCatalogEntry
	seen := make(map[[4]string]bool)
	for _, entry := range payload.Releases {
		identity := [4]string{entry.HostID, entry.Architecture, entry.Service, entry.ArtifactSHA256}
		if seen[identity] {
			return nil, errors.New("hostcontrol: ambiguous release catalog entry")
		}
		seen[identity] = true
		if strings.TrimSpace(entry.HostID) == "" || (entry.Architecture != "X64" && entry.Architecture != "Arm64") || entry.Service == "" || entry.Version == "" {
			return nil, errors.New("hostcontrol: incomplete release catalog identity")
		}
		manifest, err := hostmanifest.ParseHostManifest(entry.Manifest)
		if err != nil {
			return nil, err
		}
		canonical, err := hostmanifest.CanonicalHostManifestJSON(manifest)
		if err != nil {
			return nil, err
		}
		if !bytes.Equal(canonical, entry.Manifest) {
			return nil, errors.New("hostcontrol: release manifest must use canonical JSON")
		}
		if _, err := hostmanifest.NewApplyManifestCommand("validate", entry.ExpectedManifestSHA256, manifest); err != nil {
			return nil, err
		}
		matched := false
		for _, component := range manifest.Components {
			if component.Name == entry.Service {
				matched = component.Version == entry.Version && component.Sha256 == entry.ArtifactSHA256
			}
		}
		if !matched {
			return nil, errors.New("hostcontrol: release target does not match complete manifest")
		}
		architecture := runtimeplan.HostArchitectureX64
		if entry.Architecture == "Arm64" {
			architecture = runtimeplan.HostArchitectureArm64
		}
		entries = append(entries, validatedCatalogEntry{identity: identity, release: Release{Manifest: manifest, ExpectedManifestSHA: entry.ExpectedManifestSHA256, Architecture: architecture}})
	}
	if err := ctx.Err(); err != nil {
		return nil, err
	}
	return entries, nil
}

// ResolveTarget resolves a health target against admitted host identity and the
// same authenticated complete manifest used for delivery.
func (c *SignedReleaseCatalog) ResolveTarget(ctx context.Context, host Host, digest string) (Release, error) {
	allocation, err := runtimeplan.NewRuntimeAllocationId("terrabase")
	if err != nil {
		return Release{}, err
	}
	artifact, err := runtimeplan.NewArtifactDigest(digest)
	if err != nil {
		return Release{}, err
	}
	plan, err := runtimeplan.NewHostRuntimePlan(runtimeplan.AdmittedRoleTerraBaseMember, runtimeplan.RuntimeDriverNativeSystemd, allocation, artifact, host.Architecture, nil)
	if err != nil {
		return Release{}, err
	}
	return c.ResolveRelease(ctx, host.NodeID.Value, plan)
}
