package imagequalification

import (
	"bytes"
	"context"
	"errors"
	"fmt"
	"io"
	"os"
	"time"

	"github.com/TerraScale/ts-orchestrator/internal/app"
	"github.com/TerraScale/ts-orchestrator/internal/containermaterial"
	"github.com/TerraScale/ts-orchestrator/internal/delivery"
	"github.com/TerraScale/ts-orchestrator/internal/natscell"
	"github.com/TerraScale/ts-orchestrator/internal/trust"
	"github.com/TerraScale/ts-orchestrator/tests/imagequalification/native"
)

// controllerDelivery uses installed operator credentials and the real controller
// spec and delivery APIs. SSH never supplies workload mutation authority.
type controllerDelivery struct {
	prepared Prepared
	config   string
	roots    trust.Keyring
	verifier delivery.Ed25519Codec
}

func (driver *controllerDelivery) Apply(ctx context.Context, fixture native.MaterialFixture) error {
	p := driver.prepared
	if err := p.approval.validate(); err != nil {
		return err
	}
	if p.approvalSHA256 == "" || hashBytes(p.approvalWire) != p.approvalSHA256 || !time.Now().Before(p.expires) {
		return errors.New("native delivery requires current sealed finite approval")
	}
	ctx, cancel := context.WithDeadline(ctx, p.expires)
	defer cancel()
	var approved MaterialApproval
	for _, material := range p.approval.MaterialFixtures {
		if material.Scenario == fixture.Scenario {
			approved = material
		}
	}
	if approved.Scenario == "" || approved.SignedProfileSHA256 != fixture.SignedProfileSHA256 || approved.ContainerIntentSHA256 != fixture.ContainerIntentSHA256 {
		return errors.New("native delivery differs from the independently approved scenario")
	}
	profile, err := nativeProofFile(fixture.SignedProfilePath, approved.SignedProfileSHA256, 64<<10)
	if err != nil {
		return err
	}
	wire, err := nativeProofFile(fixture.ContainerIntentPath, approved.ContainerIntentSHA256, delivery.MaxIntentBytes+8192)
	if err != nil {
		return err
	}
	envelope, err := driver.verifier.Verify(ctx, wire)
	if err != nil {
		return fmt.Errorf("verify retained native delivery authority: %w", err)
	}
	intent, err := delivery.DecodeIntent(envelope.Payload)
	if err != nil {
		return err
	}
	proof, err := containermaterial.VerifyProfile(profile, driver.roots, p.approval.ProfileIdentity, intent)
	if err != nil || !proof.NoSecrets() {
		return errors.New("native delivery requires its approved root-signed no-secret profile")
	}
	expected, err := containermaterial.ServiceIntent(proof, p.approval.Candidate.Architecture)
	if err != nil || expected.Container.Image != p.approval.WorkloadImage {
		return errors.New("native delivery differs from the approved immutable workload")
	}
	cfg, err := app.LoadConfig(driver.config)
	if err != nil {
		return err
	}
	if cfg.NATS.Embedded != nil || cfg.NATS.ClientRole != "operator" || cfg.NATS.Cell != p.approval.ProfileIdentity.Cell {
		return errors.New("native delivery requires the existing regional operator credentials")
	}
	// Adopt the verified bytes rather than reopening the caller's mutable path.
	file, err := os.CreateTemp("", "ts-native-profile-*")
	if err != nil {
		return err
	}
	defer os.Remove(file.Name())
	_, writeErr := file.Write(profile)
	if err := errors.Join(writeErr, file.Close()); err != nil {
		return err
	}
	if err := app.Run(ctx, []string{"operator", "apply", "--config", driver.config, "-f", file.Name()}, io.Discard); err != nil {
		return fmt.Errorf("adopt native signed profile: %w", err)
	}
	runtime, err := natscell.Start(ctx, cfg.NATS)
	if err != nil {
		return err
	}
	defer runtime.Close()
	fingerprint, err := intent.Fingerprint()
	if err != nil {
		return err
	}
	client, err := delivery.ConnectClient(ctx, delivery.Config{Conn: runtime.Conn(), JS: runtime.JetStream(), Cell: intent.Cell,
		Signer: retainedIntentSigner{wire: wire, fingerprint: fingerprint}})
	if err != nil {
		return err
	}
	if err := client.Submit(ctx, intent); err != nil {
		return err
	}
	for {
		receipt, err := client.StatusFor(ctx, intent)
		if err == nil {
			if receipt.Status != "accepted" {
				return fmt.Errorf("native controller delivery %s: %s", receipt.Status, receipt.Error)
			}
			return nil
		}
		if !errors.Is(err, delivery.ErrPending) {
			return err
		}
		select {
		case <-ctx.Done():
			return ctx.Err()
		case <-time.After(250 * time.Millisecond):
		}
	}
}

// The client may request only the intent already covered by the approved wire;
// this adapter neither owns a signing key nor generates a replacement envelope.
type retainedIntentSigner struct {
	wire        []byte
	fingerprint string
}

func (signer retainedIntentSigner) Sign(ctx context.Context, payload []byte) ([]byte, error) {
	if err := ctx.Err(); err != nil {
		return nil, err
	}
	intent, err := delivery.DecodeIntent(payload)
	if err != nil {
		return nil, err
	}
	fingerprint, err := intent.Fingerprint()
	if err != nil || fingerprint != signer.fingerprint {
		return nil, errors.New("delivery attempted to replace independently signed native intent")
	}
	return bytes.Clone(signer.wire), nil
}

func nativeProofFile(path, expected string, limit int64) ([]byte, error) {
	info, err := os.Lstat(path)
	if err != nil || !info.Mode().IsRegular() || info.Size() <= 0 || info.Size() > limit {
		return nil, errors.New("native authority must be a bounded regular proof file")
	}
	file, err := os.Open(path)
	if err != nil {
		return nil, err
	}
	defer file.Close()
	opened, err := file.Stat()
	if err != nil || !os.SameFile(info, opened) {
		return nil, errors.New("native proof file changed during open")
	}
	wire, err := io.ReadAll(io.LimitReader(file, limit+1))
	if err != nil {
		return nil, err
	}
	if int64(len(wire)) > limit || hashBytes(wire) != expected {
		return nil, errors.New("native authority differs from independently approved bytes")
	}
	return wire, nil
}
