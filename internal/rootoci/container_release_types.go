package rootoci

import (
	"encoding/json/v2"
	"time"

	"github.com/TerraScale/ts-orchestrator/internal/entityid"
	"github.com/TerraScale/ts-orchestrator/internal/release"
	"github.com/TerraScale/ts-orchestrator/internal/releasechannel"
	"github.com/TerraScale/ts-orchestrator/internal/trust"
)

const OperationContainerRelease Operation = "container_release"

type ContainerReleaseRequest struct{ Role, Architecture string }

func (r ContainerReleaseRequest) Valid() bool {
	return validNativeRole(r.Role) && (r.Architecture == "amd64" || r.Architecture == "arm64")
}

type ContainerReleaseObservation struct {
	OriginalProof []byte
	Found         bool
	Bundle        release.ContainerBundle
	BundleSHA256  string
	Fingerprint   string
	ExpiresAt     time.Time
	Floor         *ContainerReleaseFloor
}

// ContainerReleaseFloor only locates retained provenance; it grants no execution authority.
type ContainerReleaseFloor struct {
	Found           bool
	OperationID     string
	Generation      uint64
	ReleaseSequence uint64
	ReleaseIdentity string
	IntentSHA256    string
}

func (f ContainerReleaseFloor) valid() bool {
	if !f.Found {
		return f.OperationID == "" && f.Generation == 0 && f.ReleaseSequence == 0 && f.ReleaseIdentity == "" && f.IntentSHA256 == ""
	}
	return entityid.Valid(f.OperationID) && f.Generation != 0 && f.ReleaseSequence != 0 && validDigest(f.ReleaseIdentity) && validDigest(f.IntentSHA256)
}

// Valid checks transport coherence; only root's current verifier grants admission.
func (o ContainerReleaseObservation) Valid(request ContainerReleaseRequest, now time.Time) bool {
	if !request.Valid() || now.IsZero() || !now.Before(o.ExpiresAt) || len(o.OriginalProof) > MaxOriginalProofBytes {
		return false
	}
	wire, err := json.Marshal(o.Bundle)
	if err != nil || len(wire) > releasechannel.MaxContainerBundleBytes {
		return false
	}
	if !o.Found {
		return len(o.OriginalProof) == 0 && len(o.Bundle.Claim) == 0 && len(o.Bundle.Index) == 0 && len(o.Bundle.Sequence) == 0 && len(o.Bundle.Delegation) == 0 && len(o.Bundle.Migration) == 0 && o.BundleSHA256 == "" && o.Fingerprint == "" && o.Floor == nil
	}
	if o.Floor == nil || !o.Floor.valid() {
		return false
	}
	digest, err := release.ContainerBundleSHA256(o.Bundle)
	if err != nil || digest != o.BundleSHA256 {
		return false
	}
	envelope, err := trust.DecodeEnvelope(o.Bundle.Claim)
	if err != nil || !now.Before(envelope.ExpiresAt) || o.ExpiresAt.After(envelope.ExpiresAt) {
		return false
	}
	fingerprint, err := trust.Fingerprint(envelope)
	if err != nil || fingerprint != o.Fingerprint {
		return false
	}
	var claim release.ContainerClaim
	if json.Unmarshal(envelope.Payload, &claim, json.RejectUnknownMembers(true)) != nil || claim.Validate() != nil {
		return false
	}
	if (claim.WorkloadGenesisSHA256 != "") != (len(o.OriginalProof) != 0) {
		return false
	}
	for _, wire := range [][]byte{o.Bundle.Delegation, claim.Production.Qualification, claim.Production.Delegation} {
		if len(wire) == 0 {
			continue
		}
		proof, err := trust.DecodeEnvelope(wire)
		if err != nil || !now.Before(proof.ExpiresAt) || o.ExpiresAt.After(proof.ExpiresAt) {
			return false
		}
	}
	return claim.Role == request.Role && claim.Architecture == request.Architecture && envelope.Scope == release.ContainerScope(release.ContainerTarget{Cell: claim.Cell, Environment: claim.Environment, Role: claim.Role, Architecture: claim.Architecture})
}
