package mesh

import (
	"context"
	"errors"
	"slices"
	"time"

	"github.com/TerraScale/ts-orchestrator/internal/appregistry"
	"github.com/TerraScale/ts-orchestrator/internal/protocol"
	"github.com/TerraScale/ts-orchestrator/internal/releasepush"
	"github.com/TerraScale/ts-orchestrator/internal/swarmruntime"
	"github.com/nats-io/nats.go"
)

const appReleaseView = "app-release"

type stateRequest struct {
	Nonce   string `json:"nonce"`
	View    string `json:"view"`
	Region  string `json:"region"`
	Service string `json:"service"`
}

func ReadAppRelease(ctx context.Context, conn *nats.Conn, region, service, nonce string) (releasepush.AppReleaseObservation, error) {
	payload, err := protocol.EncodeJSON(stateRequest{Nonce: nonce, View: appReleaseView, Region: region, Service: service})
	if err != nil {
		return releasepush.AppReleaseObservation{}, err
	}
	var proof releasepush.AppReleaseObservation
	err = collect(ctx, conn, StateSubject, payload, len(Regions(region)), 12*time.Second, func(data []byte) bool {
		var reply releasepush.AppReleaseObservation
		if protocol.DecodeTolerant(data, &reply, maxWire) != nil || reply.Nonce != nonce || reply.Service != service || reply.Region != region {
			return true
		}
		proof = reply
		return false
	})
	if err != nil {
		return proof, err
	}
	if proof.Nonce == "" {
		return proof, errors.New("regional manager did not return a signed app observation")
	}
	return proof, nil
}

func (n *Node) observeAppRelease(request stateRequest) releasepush.AppReleaseObservation {
	proof := releasepush.AppReleaseObservation{Nonce: request.Nonce, Region: n.cfg.region, Service: request.Service}
	proof.Configured = append(n.AdmittedRegions(), Regions(n.cfg.region)...)
	slices.Sort(proof.Configured)
	proof.Configured = slices.Compact(proof.Configured)
	state := (*n.stateDesired.Load())[request.Service]
	entry := state.entry()
	if entry.Spec == nil || entry.Generation <= 0 {
		return proof
	}
	proof.Declared = entry.Spec.RunsIn(n.cfg.region)
	proof.Placement = &releasepush.Placement{Generation: entry.Generation, RollbackOf: entry.RollbackOf, Regions: entry.Spec.Regions}
	if entry.Deployment == nil || state.Floor == nil || *entry.Deployment != *state.Floor || entry.RollbackOf != 0 ||
		entry.Deployment.Validate() != nil || !appregistry.SameDigest(entry.Deployment.Image, entry.Spec.Image) {
		return proof
	}
	proof.Release = entry.Deployment
	if !proof.Declared {
		return proof
	}
	key := n.bakePath(request.Service, entry.Generation)
	identity, err := bakeIdentity(state)
	if err != nil {
		return proof
	}
	record, err := n.readBake(request.Service, entry.Generation)
	if err != nil || record.Identity != identity || record.Generation != entry.Generation || record.Release == nil || *record.Release != *entry.Deployment ||
		!appregistry.SameDigest(record.Image, entry.Spec.Image) || record.Rollout.Revision != entry.Deployment.Revision ||
		record.Bake.Finished.IsZero() || record.Bake.Reason != "" || record.Bake.Unsaved {
		return proof
	}
	if pending := n.stateUnsaved.Load(); pending != nil {
		if _, unsaved := (*pending)[key]; unsaved {
			return proof
		}
	}
	proof.BakeGeneration, proof.PassedAt = entry.Generation, record.Bake.Finished
	a, ok := n.cfg.applier.(swarmApplier)
	if !ok || entry.Spec.ReadyPath == "" {
		return proof
	}
	ctx, cancel := context.WithTimeout(n.ctx, 10*time.Second)
	defer cancel()
	client, close, err := a.control()
	if err != nil {
		return proof
	}
	defer close()
	spec, _, settled := n.regionalServiceSpec(state)
	if !settled {
		return proof
	}
	if _, err := swarmruntime.ProbeServiceSpecExact(ctx, client, spec); err != nil {
		return proof
	}
	current, err := bakeIdentity((*n.stateDesired.Load())[request.Service])
	if err == nil && current == identity {
		proof.ServingGeneration = entry.Generation
	}
	return proof
}
