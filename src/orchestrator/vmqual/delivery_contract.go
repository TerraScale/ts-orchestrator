package vmqual

import (
	"context"
	"crypto/ed25519"
	"encoding/json"
	"errors"
	"fmt"
	"strings"

	"terrascale.tech/orchestrator/src/orchestrator/delivery"
)

// DeliveryArtifactIdentity is one architecture entry in the local release
// manifest used by the VM qualification. The manifest is deliberately small:
// the delivery package remains the authority for request validation, while
// this type makes the amd64/arm64 identity check explicit and inspectable.
type DeliveryArtifactIdentity struct {
	Architecture string `json:"architecture"`
	Digest       string `json:"digest"`
	Size         int64  `json:"size"`
}

// DeliveryArchitectureManifest is the cross-built release identity handed to
// a guest-backed ts-node qualifier. It always contains one amd64 and one arm64
// artifact for the same service and source version.
type DeliveryArchitectureManifest struct {
	SchemaVersion int                        `json:"schemaVersion"`
	Service       string                     `json:"service"`
	Version       string                     `json:"version"`
	Artifacts     []DeliveryArtifactIdentity `json:"artifacts"`
}

// DeliverySignedArtifact carries the exact bytes and detached signature for
// one manifest entry. The private signing key never crosses this boundary.
type DeliverySignedArtifact struct {
	Identity  DeliveryArtifactIdentity
	Body      []byte
	Signature []byte
}

// TSNodeGuestQualification is the complete, bounded input a Firecracker guest
// adapter needs to exercise ts-node. Implementations must perform the attempts
// inside the named guest; returning a synthesized success is not qualification.
type TSNodeGuestQualification struct {
	Manifest            DeliveryArchitectureManifest
	ManifestDigest      string
	PublicKey           ed25519.PublicKey
	Candidates          map[string]DeliverySignedArtifact
	BadSignature        map[string]DeliverySignedArtifact
	BadDigest           map[string]DeliverySignedArtifact
	ExpectedSystemdUnit string
	PersistenceSentinel []byte
}

// TSNodeInstallAttempt is an observed result of one guest-side install.
type TSNodeInstallAttempt struct {
	Name         string
	Architecture string
	Digest       string
	Accepted     bool
}

// TSNodeGuestObservation contains values read back from the guest after the
// qualification attempts and one restart. Unit text and persistent bytes are
// compared exactly by RunDeliveryContract.
type TSNodeGuestObservation struct {
	Host                    string
	NativeArchitecture      string
	InstalledDigest         string
	ActiveDigest            string
	SystemdUnit             string
	PersistentBeforeRestart []byte
	PersistentAfterRestart  []byte
	InstallAttempts         []TSNodeInstallAttempt
}

// DeliveryGuestGateObservation is a gate result read from a participating
// guest, not a success value manufactured by the coordinator.
type DeliveryGuestGateObservation struct {
	Host   string
	Digest string
	Gate   string
	Passed bool
}

// DeliveryGuestObservation is the post-rollback state read from a guest.
type DeliveryGuestObservation struct {
	Host           string
	ActiveDigest   string
	Cordoned       bool
	UnitActive     bool
	PersistentData []byte
}

// DeliveryGuestControl is intentionally required. The existing vmguest
// diagnostic protocol cannot install artifacts or drive ts-node, so the VM
// suite must supply an SSH/vsock/NATS-backed implementation rather than claim
// criterion 6 from an in-process fake.
type DeliveryGuestControl interface {
	delivery.HostControl
	QualifyTSNode(context.Context, string, TSNodeGuestQualification) (TSNodeGuestObservation, error)
	CheckDeliveryGate(context.Context, string, string, string) (DeliveryGuestGateObservation, error)
	ObserveDeliveryGuest(context.Context, string) (DeliveryGuestObservation, error)
}

// ValidateDeliveryArchitectureManifest verifies the exact manifest identity,
// body SHA-256, and Ed25519 signature for both supported release architectures.
// It returns the canonical manifest digest used by delivery requests.
func ValidateDeliveryArchitectureManifest(manifest DeliveryArchitectureManifest, artifacts map[string]DeliverySignedArtifact, publicKey ed25519.PublicKey) (string, error) {
	if manifest.SchemaVersion != DeliveryContractSchemaVersion || manifest.Service != DeliveryContractService || strings.TrimSpace(manifest.Version) == "" {
		return "", errors.New("vmqual: delivery architecture manifest identity is invalid")
	}
	if len(publicKey) != ed25519.PublicKeySize {
		return "", errors.New("vmqual: delivery architecture manifest needs an Ed25519 public key")
	}
	if len(manifest.Artifacts) != 2 || len(artifacts) != 2 {
		return "", errors.New("vmqual: delivery manifest must contain exactly amd64 and arm64")
	}
	wanted := map[string]bool{"linux/amd64": false, "linux/arm64": false}
	for _, identity := range manifest.Artifacts {
		if _, ok := wanted[identity.Architecture]; !ok || wanted[identity.Architecture] {
			return "", fmt.Errorf("vmqual: delivery manifest architecture %q is missing or duplicated", identity.Architecture)
		}
		artifact, ok := artifacts[identity.Architecture]
		if !ok || artifact.Identity != identity || identity.Size <= 0 || int64(len(artifact.Body)) != identity.Size {
			return "", fmt.Errorf("vmqual: %s manifest entry does not match its artifact", identity.Architecture)
		}
		if digest := delivery.SHA256Digest(artifact.Body); !delivery.SameDigest(digest, identity.Digest) {
			return "", fmt.Errorf("vmqual: %s artifact digest does not match its bytes", identity.Architecture)
		}
		if len(artifact.Signature) != ed25519.SignatureSize || !ed25519.Verify(publicKey, artifact.Body, artifact.Signature) {
			return "", fmt.Errorf("vmqual: %s artifact signature is invalid", identity.Architecture)
		}
		wanted[identity.Architecture] = true
	}
	for architecture, present := range wanted {
		if !present {
			return "", fmt.Errorf("vmqual: delivery manifest is missing %s", architecture)
		}
	}
	encoded, err := json.Marshal(manifest)
	if err != nil {
		return "", fmt.Errorf("vmqual: encode delivery architecture manifest: %w", err)
	}
	return delivery.SHA256Digest(encoded), nil
}

const (
	DeliveryContractService       = "terrabase"
	DeliveryContractCanary        = "gru-member-1"
	DeliveryContractFailureHost   = "sfo-member-2"
	DeliveryContractFailureGate   = "replication-backup-catch-up"
	DeliveryContractToken         = "vmqual-local-delivery-token"
	DeliveryContractSchemaVersion = 1
)
