package bootstrapstart

import (
	"context"
	"errors"
	"time"

	"github.com/TerraScale/ts-orchestrator/internal/bootstrap"
	"github.com/TerraScale/ts-orchestrator/internal/protocol"
	"github.com/TerraScale/ts-orchestrator/internal/trust"
)

// RuntimeIdentity binds a previously admitted controller to current signed
// regional identity. It carries no permission to create or replace OCI hosts.
type RuntimeIdentity struct {
	DeploymentID, ClusterID, Environment, Cell string
	Slot, SeedSlot, InstanceID                 string
	PrivateIP, SeedPrivateIP                   string
}

// RuntimeAuthority is a read-only view of the existing founder authority.
type RuntimeAuthority struct {
	identity RuntimeIdentity
	anchor   bootstrap.VerifiedBootstrapAnchor
	expires  time.Time
}

func (a RuntimeAuthority) Identity() RuntimeIdentity                 { return a.identity }
func (a RuntimeAuthority) Anchor() bootstrap.VerifiedBootstrapAnchor { return a.anchor }
func (a RuntimeAuthority) ExpiresAt() time.Time                      { return a.expires }

// ReadRuntimeAuthority consumes the installation already checked by Gate and
// the existing seed/accepted-peer selection readers. Discovery cannot elect a
// founder, turn a peer into a seed, or extend launch permission through this API.
func (reader *CurrentFounderAuthorityReader) ReadRuntimeAuthority(ctx context.Context,
	accepted AcceptedIdentity, now time.Time,
) (RuntimeAuthority, error) {
	if reader == nil || accepted.Validate() != nil {
		return RuntimeAuthority{}, errors.New("runtime requires an accepted controller identity")
	}
	marker := reader.accepted
	if marker.DeploymentID != accepted.DeploymentID || marker.Cell != accepted.Cell ||
		marker.Slot != accepted.Slot || marker.SeedSlot != accepted.SeedSlot ||
		marker.InstanceOCID != accepted.InstanceOCID || marker.ImageOCID != accepted.ImageOCID ||
		marker.PrimaryVNICOCID != accepted.PrimaryVNICOCID || marker.PrimaryPrivateIP != accepted.PrimaryPrivateIP {
		return RuntimeAuthority{}, errors.New("runtime identity differs from accepted founder installation")
	}
	var plan bootstrap.FounderPlan
	var anchor bootstrap.VerifiedBootstrapAnchor
	var expires time.Time
	var manifests map[string][]byte
	if marker.Slot == marker.SeedSlot {
		selected, err := reader.ReadCurrent(ctx, now)
		if err != nil {
			return RuntimeAuthority{}, err
		}
		plan, anchor, expires, manifests = selected.Plan.Plan(), selected.Anchor, selected.SelectionExpiresAt, selected.ManifestWires
	} else {
		selected, err := reader.readCurrentCompletedPeer(ctx, now, true)
		if err != nil {
			return RuntimeAuthority{}, err
		}
		// The completed-peer reader verified these exact signed bytes. Decoding
		// exposes identity only, never a launch-capable VerifiedFounderPlan.
		envelope, err := trust.DecodeEnvelope(selected.PlanWire)
		if err != nil || protocol.DecodeStrict(envelope.Payload, &plan, bootstrap.MaxFounderPlanBytes) != nil {
			return RuntimeAuthority{}, ErrFounderSelection
		}
		anchor, expires, manifests = selected.Anchor, selected.SelectionExpiresAt, selected.ManifestWires
	}
	if !anchor.IsVerified() || anchor.Digest() != marker.AnchorSHA256 ||
		anchor.Anchor().ClusterID != accepted.ClusterID || anchor.Anchor().Environment != accepted.Environment ||
		plan.SeedSlot != accepted.SeedSlot || digestWire(manifests[accepted.Slot]) != marker.ManifestSHA256 ||
		!now.Before(expires) {
		return RuntimeAuthority{}, errors.New("runtime scope differs from current signed controller authority")
	}
	privateIP := plan.SeedPrivateIP
	if accepted.Slot != plan.SeedSlot {
		privateIP = ""
		for _, row := range plan.Peers {
			if row.Slot == accepted.Slot && row.ImageOCID == accepted.ImageOCID {
				privateIP = row.PrivateIP
			}
		}
	}
	if privateIP == "" || privateIP != accepted.PrimaryPrivateIP {
		return RuntimeAuthority{}, errors.New("runtime host address differs from signed slot and accepted instance")
	}
	return RuntimeAuthority{identity: RuntimeIdentity{
		DeploymentID: accepted.DeploymentID, ClusterID: accepted.ClusterID,
		Environment: accepted.Environment, Cell: accepted.Cell,
		Slot: accepted.Slot, SeedSlot: accepted.SeedSlot, InstanceID: accepted.InstanceOCID,
		PrivateIP: privateIP, SeedPrivateIP: plan.SeedPrivateIP,
	}, anchor: anchor, expires: expires}, nil
}
