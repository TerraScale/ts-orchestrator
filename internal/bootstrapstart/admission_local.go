package bootstrapstart

import (
	"bytes"
	"context"
	"errors"
	"fmt"
	"os"

	"github.com/TerraScale/ts-orchestrator/internal/trust"
)

// AdmitRestartLocal verifies root-owned accepted state and installed identity
// before joining internal broker routes. Ordinary runtime also needs full OCI
// and clock admission plus the shared reset gate.
func (gate Gate) AdmitRestartLocal(ctx context.Context) (AcceptedIdentity, error) {
	return gate.admitRestartLocal(ctx, gate.verifyRestartBinary)
}

// AdmitIdentityRekeyCompletion admits only the read-only shared-completion probe.
// An owned transition may use its authenticated predecessor without admitting runtime.
func (gate Gate) AdmitIdentityRekeyCompletion(ctx context.Context) (AcceptedIdentity, error) {
	return gate.admitRestartLocal(ctx, func(accepted AcceptedIdentity, roots trust.Keyring) error {
		if err := gate.verifyRestartBinary(accepted, roots); err == nil {
			return nil
		}
		_, err := verifyRecoveryPredecessor("/proc/self/exe", gate.SelfUpdate, roots, accepted)
		return err
	})
}

func (gate Gate) admitRestartLocal(ctx context.Context, verifyBinary func(AcceptedIdentity, trust.Keyring) error) (AcceptedIdentity, error) {
	if gate.Descriptor == nil || gate.Material == nil || gate.Credentials == nil || gate.ObserveIdentity == nil ||
		gate.Markers.directory == "" || !markerDigestRE.MatchString(gate.LoadedControllerConfigSHA256) {
		return AcceptedIdentity{}, fmt.Errorf("%w: required local verifier is absent", ErrAdmission)
	}
	accepted, err := gate.Markers.ReadIdentity()
	if err != nil {
		return AcceptedIdentity{}, fmt.Errorf("read root-owned accepted installation: %w", err)
	}
	inputs, err := gate.acceptedTrustInputs(accepted)
	if err != nil {
		return AcceptedIdentity{}, err
	}
	if err := gate.checkRestartJournal(accepted, inputs); err != nil {
		return AcceptedIdentity{}, err
	}
	descriptor, err := gate.Descriptor.FetchDescriptor(ctx)
	if err != nil {
		return AcceptedIdentity{}, fmt.Errorf("read accepted local slot: %w", err)
	}
	instance, err := gate.Descriptor.FetchInstanceID(ctx)
	if err != nil {
		return AcceptedIdentity{}, fmt.Errorf("read accepted local instance ID: %w", err)
	}
	if descriptor.SchemaVersion != 1 || descriptor.Slot != accepted.Slot || instance != accepted.InstanceOCID {
		return AcceptedIdentity{}, fmt.Errorf("%w: IMDS slot or instance differs from accepted installation", ErrAdmission)
	}
	if err := verifyBinary(accepted, inputs.Roots.Historical); err != nil {
		return AcceptedIdentity{}, err
	}
	if err := VerifyAcceptedLocalIdentity(accepted, gate.ObserveIdentity); err != nil {
		return AcceptedIdentity{}, fmt.Errorf("verify accepted broker/store identity: %w", err)
	}
	pins, err := gate.Material.RestartPins(accepted, inputs.Roots.Historical)
	if err != nil {
		return AcceptedIdentity{}, fmt.Errorf("read accepted material generation: %w", err)
	}
	if err := gate.restartConfig(&pins, accepted); err != nil {
		return AcceptedIdentity{}, err
	}
	if err := gate.Material.VerifyRestart(ctx, accepted, pins); err != nil {
		return AcceptedIdentity{}, fmt.Errorf("verify installed controller material: %w", err)
	}
	if err := gate.Credentials.VerifyLiveCredentials(ctx, pins, accepted); err != nil {
		return AcceptedIdentity{}, fmt.Errorf("verify live controller credentials: %w", err)
	}
	if err := ctx.Err(); err != nil {
		return AcceptedIdentity{}, err
	}
	if err := gate.checkAcceptedUnchanged(accepted); err != nil {
		return AcceptedIdentity{}, err
	}
	if err := verifyBinary(accepted, inputs.Roots.Historical); err != nil {
		return AcceptedIdentity{}, err
	}
	return accepted, nil
}

func (gate Gate) acceptedTrustInputs(accepted AcceptedIdentity) (TrustInputs, error) {
	if gate.trustStore != nil {
		return gate.trustStore.loadTrustInputs(accepted)
	}
	return LoadTrustInputs(accepted)
}

func (gate Gate) checkRestartJournal(accepted AcceptedIdentity, inputs TrustInputs) error {
	_, err := gate.Markers.verifiedIdentityRekey(accepted, inputs)
	if errors.Is(err, os.ErrNotExist) {
		return nil
	}
	return err
}

func (gate Gate) checkAcceptedUnchanged(accepted AcceptedIdentity) error {
	current, err := gate.Markers.ReadIdentity()
	if err != nil {
		return err
	}
	before, err := EncodeAcceptedIdentity(accepted)
	if err != nil {
		return err
	}
	after, err := EncodeAcceptedIdentity(current)
	if err != nil || !bytes.Equal(before, after) {
		return fmt.Errorf("%w: root-owned accepted installation changed during admission", ErrAdmission)
	}
	inputs, err := gate.acceptedTrustInputs(current)
	if err != nil {
		return err
	}
	return gate.checkRestartJournal(current, inputs)
}
