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
	"terrascale.tech/orchestrator/src/orchestrator/ociinstance"
	"terrascale.tech/orchestrator/src/orchestrator/provider"
	"terrascale.tech/orchestrator/src/orchestrator/security"
	"terrascale.tech/orchestrator/src/orchestrator/transitiongrant"
	"terrascale.tech/orchestrator/src/orchestrator/transitionreceipts"
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
	if _, err := os.Lstat(d.PlanFile); os.IsNotExist(err) {
		if d.PlanObject == nil {
			if !required {
				return zero, nil, false, nil
			}
		} else {
			raw, found, err := fetchStorageTransitionPlan(ctx, d)
			if err != nil {
				return zero, nil, false, err
			}
			if !found {
				if required {
					return zero, nil, false, errors.New("hostagent: required remote plan is absent")
				}
				return zero, nil, false, nil
			}
			v, err := a.validateStorageTransition(ctx, d, source, raw)
			if err != nil {
				return zero, nil, false, err
			}
			if err := retainStorageTransitionPlan(ctx, d.PlanFile, raw, func() error { return v.Check(time.Now()) }); err != nil {
				return zero, nil, false, err
			}
		}
	}
	raw, err := bootstrapcredentials.ReadFile(d.PlanFile, true, controltransition.MaximumBytes)
	if err != nil {
		return zero, nil, false, err
	}
	v, err := a.validateStorageTransition(ctx, d, source, raw)
	if err != nil {
		return zero, nil, false, err
	}
	return v, raw, true, nil
}

func (a *BootstrapAuthority) validateStorageTransition(ctx context.Context, d controltransition.Delivery, source bool, raw []byte) (controltransition.VerifiedPlan, error) {
	var zero controltransition.VerifiedPlan
	if err := ctx.Err(); err != nil {
		return zero, err
	}
	v, err := controltransition.VerifyPlan(a.ownerPublic, raw)
	if err != nil {
		return zero, err
	}
	if err = v.Check(time.Now()); err != nil {
		return zero, err
	}
	p, err := v.Plan()
	if err != nil {
		return zero, err
	}
	if p.TransitionID != d.TransitionID {
		return zero, errors.New("hostagent: delivered storage transition identity differs")
	}
	var grant, manifest string
	var paths []string
	if source {
		if p.Source.NodeID != a.grant.NodeID {
			return zero, errors.New("hostagent: delivered source host differs")
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
	if remote := d.PlanObject; remote != nil {
		matched := false
		for _, destination := range p.Destinations {
			if source && destination.Region == "gru" || !source && destination.NodeID == a.grant.NodeID {
				matched = remote.Region == destination.Region && remote.Objects == destination.Objects
			}
		}
		if !matched {
			return zero, errors.New("hostagent: plan object differs from original host delivery scope")
		}
	}
	if grant != a.digest || manifest != a.manifestDigest || d.Validate(paths...) != nil {
		return zero, errors.New("hostagent: delivered plan differs from original host admission")
	}
	return v, nil
}

func pinStorageTransition(ctx context.Context, epochs *nodeauthority.EpochStore, a *BootstrapAuthority, v controltransition.VerifiedPlan, raw []byte, command *nodeauthority.CommandAuthorization) error {
	if _, err := epochs.ResumeStorageTransitionPlan(ctx, v.Digest()); err != nil {
		if !os.IsNotExist(err) {
			return err
		}
		if _, err = epochs.AdmitStorageTransitionPlan(ctx, a.ownerPublic, raw, command); err != nil {
			return err
		}
	}
	return acknowledgeStorageTransition(ctx, epochs, a, v)
}

func acknowledgeStorageTransition(ctx context.Context, epochs *nodeauthority.EpochStore, a *BootstrapAuthority, v controltransition.VerifiedPlan) error {
	raw, err := recoverStorageTransitionAcknowledgement(ctx, epochs, a, v)
	if err != nil {
		return err
	}
	// The local receipt is durable before acquiring credentials or sending any
	// remote request. All retries, including after restart, recover these bytes.
	d, _, err := a.storageTransitionDelivery()
	if err != nil {
		return err
	}
	region, _, err := transitionreceipts.PinObjectKey(v, a.grant.NodeID)
	if err != nil {
		return err
	}
	p, err := v.Plan()
	if err != nil {
		return err
	}
	ociRegion := ""
	for _, destination := range p.Destinations {
		if destination.Region == region {
			ociRegion = destination.Objects.OCIRegion
		}
	}
	bounded, cancel := context.WithTimeout(ctx, time.Minute)
	defer cancel()
	if err := v.Check(time.Now()); err != nil {
		return err
	}
	identity, err := ociinstance.NewFromConfig(bounded, ociinstance.Config{Region: ociRegion, Qualification: d.OCIQualification}, func(path string) ([]byte, error) {
		return bootstrapcredentials.ReadFile(path, true, 64<<10)
	})
	if err != nil {
		return err
	}
	defer identity.Close()
	transport, err := identity.NewTransport(provider.OCIServiceObjectStorage, controltransition.PinReceiptMaximumBytes)
	if err != nil {
		return err
	}
	return transitionreceipts.PublishPlanPin(bounded, v, a.grant.NodeID, raw, transport)
}

func recoverStorageTransitionAcknowledgement(ctx context.Context, epochs *nodeauthority.EpochStore, a *BootstrapAuthority, v controltransition.VerifiedPlan) ([]byte, error) {
	// A valid retained acknowledgement is returned without accessing a key.
	// Only the explicit missing-signer result permits first-signature work.
	raw, err := epochs.AcknowledgeStorageTransitionPlan(ctx, v.Digest(), nil)
	if !errors.Is(err, nodeauthority.ErrStorageTransitionReceiptSignerRequired) {
		return raw, err
	}
	d, _, err := a.storageTransitionDelivery()
	if err != nil {
		return nil, err
	}
	private, err := bootstrapcredentials.ReadFile(d.ReceiptPrivateKeyFile, true, 32<<10)
	if err != nil {
		return nil, err
	}
	signer, err := security.ParseCommandSignatureSignerPEM(private)
	clear(private)
	if err != nil {
		return nil, errors.New("hostagent: invalid protected transition receipt signer")
	}
	defer signer.Close()
	return epochs.AcknowledgeStorageTransitionPlan(ctx, v.Digest(), signer)
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

// ResumeLocalStorageTransitionPlan verifies and acknowledges an existing plan
// and publishes its retained receipt before NATS dialing and bootstrap's
// retired-host return. It executes no broker storage effects, renews no lease,
// and never calls AdmitBootstrap. First delivery is pinned by
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
	} else if err != nil {
		return err
	}
	return acknowledgeStorageTransition(ctx, epochs, a, v)
}
