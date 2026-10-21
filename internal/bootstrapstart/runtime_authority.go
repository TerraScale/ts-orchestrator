package bootstrapstart

import (
	"context"
	"errors"
	"time"

	"github.com/TerraScale/ts-orchestrator/internal/bootstrap"
	"github.com/TerraScale/ts-orchestrator/internal/oci"
	"github.com/TerraScale/ts-orchestrator/internal/ociclient"
	"github.com/TerraScale/ts-orchestrator/internal/ociregion/catalog"
	"github.com/TerraScale/ts-orchestrator/internal/protocol"
	"github.com/TerraScale/ts-orchestrator/internal/trust"
	"github.com/oracle/oci-go-sdk/v65/core"
)

// RuntimeIdentity binds a previously admitted controller to current signed
// regional identity. It carries no permission to create or replace OCI hosts.
type RuntimeIdentity struct {
	DeploymentID, ClusterID, Environment, Cell string
	OCIRegion                                  string
	Slot, SeedSlot, InstanceID                 string
	PrivateIP, SeedPrivateIP                   string
}

// RuntimeAuthority is a read-only view of the existing founder authority.
type RuntimeAuthority struct {
	identity                    RuntimeIdentity
	anchor                      bootstrap.VerifiedBootstrapAnchor
	expires                     time.Time
	plan                        bootstrap.FounderPlan
	planDigest, selectionDigest string
	manifests                   map[string][]byte
	derived                     *bootstrap.DerivedFounderPlan
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
	var planDigest, selectionDigest string
	var derived *bootstrap.DerivedFounderPlan
	if marker.Slot == marker.SeedSlot {
		selected, err := reader.ReadCurrent(ctx, now)
		if err != nil {
			return RuntimeAuthority{}, err
		}
		plan, anchor, expires, manifests = selected.Plan.Plan(), selected.Anchor, selected.SelectionExpiresAt, selected.ManifestWires
		planDigest, selectionDigest, derived = selected.Plan.Digest(), selected.SelectionSHA256, selected.Derived
	} else {
		selected, err := reader.readCurrentCompletedPeer(ctx, now, true)
		if err != nil {
			return RuntimeAuthority{}, err
		}
		if selected.derived != nil {
			plan = selected.derived.Plan()
		} else {
			// Legacy continuation retains the exact verified root-signed wire.
			envelope, err := trust.DecodeEnvelope(selected.PlanWire)
			if err != nil || protocol.DecodeStrict(envelope.Payload, &plan, bootstrap.MaxFounderPlanBytes) != nil {
				return RuntimeAuthority{}, ErrFounderSelection
			}
		}
		anchor, expires, manifests = selected.Anchor, selected.SelectionExpiresAt, selected.ManifestWires
		planDigest, selectionDigest, derived = selected.Plan.Digest(), selected.SelectionSHA256, selected.derived
	}
	identity := anchor.Anchor()
	if derived != nil {
		var err error
		identity, _, err = externalSeedIdentity(derived.SeedAuthority(), anchor)
		if err != nil {
			return RuntimeAuthority{}, err
		}
	}
	if !anchor.IsVerified() || anchor.Digest() != marker.AnchorSHA256 ||
		identity.DeploymentID != accepted.DeploymentID || string(identity.Cell) != accepted.Cell ||
		identity.ClusterID != accepted.ClusterID || identity.Environment != accepted.Environment ||
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
		OCIRegion: identity.OCIRegion,
		Slot:      accepted.Slot, SeedSlot: accepted.SeedSlot, InstanceID: accepted.InstanceOCID,
		PrivateIP: privateIP, SeedPrivateIP: plan.SeedPrivateIP,
	}, anchor: anchor, expires: expires, plan: plan, planDigest: planDigest,
		selectionDigest: selectionDigest, manifests: manifests, derived: derived}, nil
}

// RuntimeInstanceObserver shares the admission transport and accepted root scope.
func (reader *CurrentFounderAuthorityReader) RuntimeInstanceObserver(ctx context.Context, accepted AcceptedIdentity) (*OCIInstanceObserver, error) {
	authority, err := reader.ReadRuntimeAuthority(ctx, accepted, time.Now().UTC())
	if err != nil {
		return nil, err
	}
	if authority.derived != nil {
		if _, err := authority.derived.SeedAuthority().OriginalLaunch(); err == nil {
			factory, err := ociclient.InstancePrincipalContext(ctx, authority.Identity().OCIRegion)
			if err != nil {
				return nil, err
			}
			return NewOCIInstanceObserverWithFactory(oci.Region(authority.Identity().Cell), factory)
		}
	}
	config, err := currentLedgerConfig(authority.Anchor(), reader.baked.Roots)
	if err != nil {
		return nil, err
	}
	provider, err := newOCIAdmissionProvider(config)
	if err != nil {
		return nil, err
	}
	return NewOCIInstanceObserver(config.Cell, provider)
}

// ObserveWorkerArchitecture checks the exact observed OCI shape and image in its AD.
func (observer *OCIInstanceObserver) ObserveWorkerArchitecture(ctx context.Context, observed InstanceObservation) (string, error) {
	reader, ok := observer.compute.(interface {
		ListShapes(context.Context, core.ListShapesRequest) (core.ListShapesResponse, error)
	})
	if !ok {
		return "", errors.New("OCI observer cannot verify worker processor architecture")
	}
	var page *string
	for range 20 {
		response, err := reader.ListShapes(ctx, core.ListShapesRequest{CompartmentId: new(observed.CompartmentOCID), AvailabilityDomain: new(observed.AvailabilityDomain), ImageId: new(observed.ImageOCID), Page: page})
		if err != nil {
			return "", err
		}
		for _, shape := range response.Items {
			if shape.Shape != nil && *shape.Shape == observed.Shape && shape.ProcessorDescription != nil {
				return catalog.ShapeArchitecture(*shape.ProcessorDescription)
			}
		}
		if response.OpcNextPage == nil || *response.OpcNextPage == "" {
			break
		}
		page = response.OpcNextPage
	}
	return "", errors.New("worker shape is not compatible with its observed image and placement")
}
