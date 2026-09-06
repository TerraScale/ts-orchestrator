package hostagent

import (
	"context"
	"errors"
	"os"
	"path/filepath"
	"time"

	"terrascale.tech/orchestrator/src/orchestrator/bootstrapcredentials"
	"terrascale.tech/orchestrator/src/orchestrator/controltransition"
	"terrascale.tech/orchestrator/src/orchestrator/hostmanifest"
	"terrascale.tech/orchestrator/src/orchestrator/initialgrant"
	"terrascale.tech/orchestrator/src/orchestrator/nodeauthority"
	"terrascale.tech/orchestrator/src/orchestrator/transitiongrant"
)

var ErrStorageTransitionPreparationMissing = controltransition.ErrPreparationMissing

func (a *BootstrapAuthority) storageTransitionDelivery() (controltransition.Delivery, bool, error) {
	var delivery controltransition.Delivery
	source := false
	for _, spec := range a.grant.Manifest.Components {
		c, initial, err := initialgrant.ComponentConfig(spec)
		if err != nil {
			return delivery, false, err
		}
		candidate, prepared, err := transitiongrant.ComponentConfig(spec)
		if err != nil {
			return delivery, false, err
		}
		var next controltransition.Delivery
		if initial {
			next = c.StorageTransition
		}
		if prepared {
			next = candidate.StorageTransition
		}
		if next == (controltransition.Delivery{}) {
			continue
		}
		if delivery != (controltransition.Delivery{}) {
			return delivery, false, errors.New("hostagent: duplicate storage transition delivery")
		}
		delivery, source = next, initial
	}
	for _, spec := range a.grant.Manifest.Components {
		if err := delivery.Validate(spec.DataVolume); err != nil {
			return delivery, false, err
		}
	}
	return delivery, source, nil
}

func (a *BootstrapAuthority) readStorageTransition(ctx context.Context, required bool) (controltransition.VerifiedPlan, []byte, bool, error) {
	var zero controltransition.VerifiedPlan
	if ctx == nil || os.Geteuid() != 0 {
		return zero, nil, false, errors.New("hostagent: trusted storage transition receiver required")
	}
	if err := ctx.Err(); err != nil {
		return zero, nil, false, err
	}
	d, source, err := a.storageTransitionDelivery()
	if err != nil {
		return zero, nil, false, err
	}
	if d == (controltransition.Delivery{}) {
		return zero, nil, false, nil
	}
	if _, err := os.Lstat(d.PlanFile); os.IsNotExist(err) && !required {
		return zero, nil, false, nil
	}
	raw, err := bootstrapcredentials.ReadFile(d.PlanFile, true, controltransition.MaximumBytes)
	if err != nil {
		return zero, nil, false, err
	}
	v, err := controltransition.VerifyPlan(a.ownerPublic, raw)
	if err != nil {
		return zero, nil, false, err
	}
	if err = v.Check(time.Now()); err != nil {
		return zero, nil, false, err
	}
	p, err := v.Plan()
	if err != nil {
		return zero, nil, false, err
	}
	if p.TransitionID != d.TransitionID {
		return zero, nil, false, errors.New("hostagent: delivered storage transition identity differs")
	}
	var grant, manifest string
	var paths []string
	if source {
		if p.Source.NodeID != a.grant.NodeID {
			return zero, nil, false, errors.New("hostagent: delivered source host differs")
		}
		grant, manifest = p.Source.BootstrapGrantSHA256, p.Source.InitialManifestSHA256
		paths = append(paths, p.Source.StoreDir, p.Source.CaptureDir, p.Source.ArchiveDir)
	}
	for _, destination := range p.Destinations {
		if destination.NodeID != a.grant.NodeID {
			continue
		}
		paths = append(paths, destination.PreliminaryStoreDir, destination.StoreDir, destination.StagingDir)
		if !source {
			grant, manifest = destination.BootstrapGrantSHA256, destination.PreparedManifestSHA256
		}
	}
	if grant != a.digest || manifest != a.manifestDigest || d.Validate(paths...) != nil {
		return zero, nil, false, errors.New("hostagent: delivered plan differs from original host admission")
	}
	return v, raw, true, nil
}

func pinStorageTransition(ctx context.Context, epochs *nodeauthority.EpochStore, a *BootstrapAuthority, v controltransition.VerifiedPlan, raw []byte, command *nodeauthority.CommandAuthorization) error {
	if _, err := epochs.ResumeStorageTransitionPlan(ctx, v.Digest()); err == nil {
		return nil
	} else if !os.IsNotExist(err) {
		return err
	}
	_, err := epochs.AdmitStorageTransitionPlan(ctx, a.ownerPublic, raw, command)
	return err
}

// Destination startup calls this only after its ordinary initial manifest has
// been admitted. Missing delivery leaves preliminary work available; it is not
// a successful pin and cannot satisfy any preparation barrier.
func (t *NatsTransport) pinDestinationStorageTransition(ctx context.Context) error {
	a, ok := t.authorizer.(*BootstrapAuthority)
	if !ok {
		return nil
	}
	d, source, err := a.storageTransitionDelivery()
	if err != nil {
		return err
	}
	if source || d == (controltransition.Delivery{}) {
		return nil
	}
	if runtime, err := t.epochs.AdmittedManifest(a.manifestDigest); err == nil && runtime {
		return nil
	}
	v, raw, found, err := a.readStorageTransition(ctx, false)
	if err != nil || !found {
		return err
	}
	return pinStorageTransition(ctx, t.epochs, a, v, raw, nil)
}

// The live source command may pin its exact capture replacement, but a pin
// cannot retire R1. Keep the existing retirement call behind the complete
// preparation barrier, which has not been implemented yet.
func (t *NatsTransport) requireStorageTransitionPreparation(ctx context.Context, command nodeauthority.CommandAuthorization, nextDigest string) error {
	a, ok := t.authorizer.(*BootstrapAuthority)
	if !ok {
		return nil
	}
	d, source, err := a.storageTransitionDelivery()
	if err != nil {
		return err
	}
	if d == (controltransition.Delivery{}) {
		return nil
	}
	v, raw, _, err := a.readStorageTransition(ctx, true)
	if err != nil {
		return err
	}
	p, err := v.Plan()
	if err != nil {
		return err
	}
	expected := ""
	if source {
		expected = p.Source.CaptureManifestSHA256
	} else {
		for _, d := range p.Destinations {
			if d.NodeID == a.grant.NodeID {
				expected = d.ActivationManifestSHA256
			}
		}
	}
	if nextDigest != expected {
		return errors.New("hostagent: replacement differs from delivered storage transition")
	}
	var authorization *nodeauthority.CommandAuthorization
	if source {
		authorization = &command
	}
	if err := pinStorageTransition(ctx, t.epochs, a, v, raw, authorization); err != nil {
		return err
	}
	return ErrStorageTransitionPreparationMissing
}

// ResumeLocalStorageTransitionPlan verifies an existing agreement before NATS
// dialing and before bootstrap's retired-host return. It executes no phase,
// renews no lease, and never calls AdmitBootstrap. First delivery is pinned by
// destination admission or the source's live ApplyManifest handler.
func ResumeLocalStorageTransitionPlan(ctx context.Context, lifecycle *Lifecycle, node string, public, signed []byte) error {
	if ctx == nil || lifecycle == nil {
		return errors.New("hostagent: transition recovery lifecycle required")
	}
	a, err := parseBootstrapAuthority(node, public, signed)
	if err != nil {
		return err
	}
	d, _, err := a.storageTransitionDelivery()
	if err != nil || d == (controltransition.Delivery{}) {
		return err
	}
	v, _, found, err := a.readStorageTransition(ctx, false)
	if err != nil || !found {
		return err
	}
	directory := filepath.Join(lifecycle.dataRoot, hostmanifest.TsNodeComponentName, "command-journal")
	// An absent journal belongs to first bootstrap. Do not create another
	// admission path merely because the owner has delivered a plan early.
	if _, err := os.Lstat(directory); os.IsNotExist(err) {
		return nil
	}
	epochs, err := nodeauthority.NewEpochStore(directory, node)
	if err != nil {
		return err
	}
	defer epochs.Close()
	if _, err := epochs.ResumeStorageTransitionPlan(ctx, v.Digest()); os.IsNotExist(err) {
		return nil
	} else {
		return err
	}
}
