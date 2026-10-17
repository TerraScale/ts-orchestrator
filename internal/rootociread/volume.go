package rootociread

import (
	"context"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json/v2"
	"errors"
	"time"

	"github.com/TerraScale/ts-orchestrator/internal/bootstrapstart"
	"github.com/TerraScale/ts-orchestrator/internal/oci"
	"github.com/TerraScale/ts-orchestrator/internal/rootoci"
	"github.com/TerraScale/ts-orchestrator/internal/rootvolumeclient"
)

var _ rootoci.VolumeReader = (*Backend)(nil)

type volumeScope struct {
	intent oci.RegionIntent
	config oci.RegionConfig
	source string
}

func (b *Backend) currentVolumeScope(cell string) (volumeScope, error) {
	accepted, intent, config, err := bootstrapstart.LoadAcceptedOCIConfig()
	if err != nil || string(config.Region) != cell {
		return volumeScope{}, errors.Join(ErrPending, err)
	}
	// Include accepted source, material generation and exact derived scope;
	// a successor acceptance cannot refresh an older observation's authority.
	wire, err := json.Marshal(struct {
		Accepted bootstrapstart.AcceptedIdentity
		Intent   oci.RegionIntent
		Config   oci.RegionConfig
	}{accepted, intent, config}, json.Deterministic(true))
	if err != nil {
		return volumeScope{}, err
	}
	digest := sha256.Sum256(wire)
	return volumeScope{intent: intent, config: config, source: hex.EncodeToString(digest[:])}, nil
}

func (b *Backend) volumeObserver(ctx context.Context, call rootoci.Call, scope scope, original *rootvolumeclient.Authority) (*oci.VolumeMountObserver, rootvolumeclient.Authority, error) {
	current, err := b.currentVolumeScope(scope.cell)
	if err != nil {
		return nil, rootvolumeclient.Authority{}, err
	}
	authority := rootvolumeclient.Authority{SourceSHA256: current.source, GrantSHA256: scope.grant,
		SessionSHA256: call.SessionBindingSHA256(), Deadline: call.Deadline()}
	if original != nil {
		if !original.Valid(time.Now()) || original.SourceSHA256 != authority.SourceSHA256 ||
			original.GrantSHA256 != authority.GrantSHA256 || original.SessionSHA256 != authority.SessionSHA256 ||
			original.Deadline.After(authority.Deadline) {
			return nil, rootvolumeclient.Authority{}, rootoci.ErrUnauthorized
		}
		authority = *original
	}
	if !authority.Valid(time.Now()) {
		return nil, rootvolumeclient.Authority{}, rootoci.ErrUnauthorized
	}
	b.mu.RLock()
	journal := b.journal
	b.mu.RUnlock()
	observer, err := oci.NewVolumeMountObserverWithReader(b.factory, current.config, current.intent, journal)
	return observer, authority, err
}

func (b *Backend) finishVolume(ctx context.Context, call rootoci.Call, scope scope, authority rootvolumeclient.Authority) error {
	current, err := b.currentVolumeScope(scope.cell)
	if err != nil {
		return err
	}
	if current.source != authority.SourceSHA256 || call.SessionBindingSHA256() != authority.SessionSHA256 || !authority.Valid(time.Now()) {
		return rootoci.ErrUnauthorized
	}
	return b.finish(ctx, call, scope)
}

func (b *Backend) InspectVolumeMount(ctx context.Context, call rootoci.Call, request rootvolumeclient.InspectRequest) (rootvolumeclient.MountObservation, error) {
	if !request.Valid() {
		return rootvolumeclient.MountObservation{}, rootoci.ErrInvalid
	}
	ctx, cancel, scope, err := b.begin(ctx, call, rootoci.OperationInspectVolumeMount)
	defer cancel()
	if err != nil {
		return rootvolumeclient.MountObservation{}, err
	}
	observer, authority, err := b.volumeObserver(ctx, call, scope, request.Original)
	if err != nil {
		return rootvolumeclient.MountObservation{}, err
	}
	ctx, stop := context.WithDeadline(ctx, authority.Deadline)
	defer stop()
	proof, err := observer.InspectVolumeMount(ctx, oci.VolumeInitializationPins(request.Pins), request.PredecessorID)
	if err != nil {
		return rootvolumeclient.MountObservation{}, err
	}
	if !proof.IsVerified() || proof.Pins() != oci.VolumeInitializationPins(request.Pins) || proof.PredecessorID() != request.PredecessorID {
		return rootvolumeclient.MountObservation{}, rootoci.ErrUnauthorized
	}
	if err := b.finishVolume(ctx, call, scope, authority); err != nil {
		return rootvolumeclient.MountObservation{}, err
	}
	return rootvolumeclient.MountObservation{Pins: request.Pins, BootDescriptorSHA256: proof.BootDescriptorSHA256(),
		PredecessorID: proof.PredecessorID(), ObservedAt: proof.ObservedAt(), Authority: authority}, nil
}

func (b *Backend) ObserveTerminatedInstance(ctx context.Context, call rootoci.Call, request rootvolumeclient.TerminatedRequest) (rootvolumeclient.TerminatedObservation, error) {
	if !request.Valid() {
		return rootvolumeclient.TerminatedObservation{}, rootoci.ErrInvalid
	}
	ctx, cancel, scope, err := b.begin(ctx, call, rootoci.OperationObserveTerminatedInstance)
	defer cancel()
	if err != nil {
		return rootvolumeclient.TerminatedObservation{}, err
	}
	observer, authority, err := b.volumeObserver(ctx, call, scope, request.Original)
	if err != nil {
		return rootvolumeclient.TerminatedObservation{}, err
	}
	ctx, stop := context.WithDeadline(ctx, authority.Deadline)
	defer stop()
	proof, err := observer.ObserveTerminatedInstance(ctx, request.InstanceID)
	if err != nil {
		return rootvolumeclient.TerminatedObservation{}, err
	}
	if !proof.IsVerified() || proof.InstanceID() != request.InstanceID {
		return rootvolumeclient.TerminatedObservation{}, rootoci.ErrUnauthorized
	}
	if err := b.finishVolume(ctx, call, scope, authority); err != nil {
		return rootvolumeclient.TerminatedObservation{}, err
	}
	return rootvolumeclient.TerminatedObservation{InstanceID: proof.InstanceID(), Region: string(proof.Region()),
		Generation: proof.Generation(), Owner: proof.Owner(), ObservedAt: proof.ObservedAt(), Authority: authority}, nil
}
