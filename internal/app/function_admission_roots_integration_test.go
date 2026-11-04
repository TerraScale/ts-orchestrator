package app

import (
	"context"
	"errors"
	"io"
	"strings"
	"testing"
	"time"

	"github.com/TerraScale/ts-orchestrator/internal/authority"
	"github.com/TerraScale/ts-orchestrator/internal/delivery"
	"github.com/TerraScale/ts-orchestrator/internal/entityid"
	"github.com/TerraScale/ts-orchestrator/internal/functionmaterial"
	"github.com/TerraScale/ts-orchestrator/internal/protocol"
	"github.com/TerraScale/ts-orchestrator/internal/release"
	"github.com/TerraScale/ts-orchestrator/internal/releasechannel"
	"github.com/TerraScale/ts-orchestrator/internal/trust"

	"github.com/nats-io/nats.go/jetstream"
)

type functionAdmissionArtifactWait struct {
	jetstream.ObjectStore
	stored chan struct{}
	resume chan struct{}
}

func (store functionAdmissionArtifactWait) Put(ctx context.Context, meta jetstream.ObjectMeta, body io.Reader) (*jetstream.ObjectInfo, error) {
	info, err := store.ObjectStore.Put(ctx, meta, body)
	if err != nil {
		return nil, err
	}
	close(store.stored)
	select {
	case <-store.resume:
		return info, nil
	case <-ctx.Done():
		return nil, ctx.Err()
	}
}

type functionRootAdmissionFixture struct {
	controller functionController
	location   releasechannel.Location
	signer     functionPublicationSigner
	rotation   []byte
}

func newFunctionRootAdmissionFixture(t *testing.T) functionRootAdmissionFixture {
	t.Helper()
	js := testRolloutJetStream(t)
	deployment := entityid.New()
	control, err := authority.Start(t.Context(), js, authority.Config{DeploymentID: deployment, Scope: "gru", CandidateID: entityid.New(), Replicas: 1})
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = control.Close() })
	artifacts, err := js.CreateObjectStore(t.Context(), jetstream.ObjectStoreConfig{Bucket: delivery.ArtifactBucket})
	if err != nil {
		t.Fatal(err)
	}
	signer := newFunctionPublicationSigner(t)
	roots, err := newRootRegistry(signer.roots, trust.ChainIdentity{DeploymentID: deployment, Cell: "gru", Environment: "canary"}, trust.RootChain{Version: 1}, "")
	if err != nil {
		t.Fatal(err)
	}
	roots.fencer = control
	if err := roots.open(t.Context(), js, 1); err != nil {
		t.Fatal(err)
	}
	nextRoot := newRootKey(t)
	rotation, err := protocol.EncodeJSON(signTestRotation(t, roots.identity, roots.verified, rootKeys(nextRoot), signer.root, nextRoot))
	if err != nil {
		t.Fatal(err)
	}
	return functionRootAdmissionFixture{controller: functionController{config: functionControllerConfig{Authority: control, JS: js, Roots: roots,
		Cell: "gru", Environment: "canary", Material: functionmaterial.Controller{Reader: functionmaterial.Reader{Authority: control, Artifacts: artifacts, Roots: roots.current}}}},
		location: releasechannel.Location{Client: newChannelBucket(), Namespace: "ns", Bucket: "gru-1-head"}, signer: signer, rotation: rotation}
}

func TestFunctionPublicationFencesRootsAcrossArtifactWait(t *testing.T) {
	for _, fault := range []string{"current", "rotated"} {
		t.Run(fault, func(t *testing.T) {
			ctx, cancel := context.WithTimeout(t.Context(), 20*time.Second)
			defer cancel()
			fixture := newFunctionRootAdmissionFixture(t)
			control, roots := fixture.controller.config.Authority, fixture.controller.config.Roots
			proof := fixture.signer.proof(t, 42, "first")
			if fault == "expired" {
				now := time.Now().UTC().Truncate(time.Second)
				envelope, err := release.SignFunctionClaim(proof.Claim(), proof.Module(), fixture.signer.delegation, fixture.signer.roots, fixture.signer.leaf, now, 5*time.Second)
				if err != nil {
					t.Fatal(err)
				}
				wire, _ := trust.EncodeEnvelope(envelope)
				proof, err = release.VerifyFunctionCurrent(wire, proof.Delegation(), proof.Module(), fixture.signer.roots, release.FunctionExpectation{
					Environment: "canary", Cell: "GRU", TenantID: proof.Claim().TenantID, FunctionID: "echo", Revision: "first", Digest: proof.Claim().Digest, MinimumSequence: 42}, now)
				if err != nil {
					t.Fatal(err)
				}
			}
			if err := releasechannel.PublishFunction(ctx, fixture.location, proof); err != nil {
				t.Fatal(err)
			}
			paused := functionAdmissionArtifactWait{ObjectStore: fixture.controller.config.Material.Reader.Artifacts, stored: make(chan struct{}), resume: make(chan struct{})}
			fixture.controller.config.Material.Reader.Artifacts = paused
			done := make(chan error, 1)
			epoch := control.Current().Epoch
			go func() {
				done <- fixture.controller.ingestRelease(ctx, epoch, fixture.location, releasechannel.FunctionRelease{Envelope: proof.Envelope(), Delegation: proof.Delegation()})
			}()
			select {
			case <-paused.stored:
			case err := <-done:
				t.Fatalf("publication did not reach the real artifact Put: %v", err)
			case <-ctx.Done():
				t.Fatal(ctx.Err())
			}
			switch fault {
			case "rotated":
				if _, err := roots.apply(ctx, fixture.rotation, epoch, control); err != nil {
					t.Fatal(err)
				}
			case "expired", "released leader":
				roots.adopting.Lock()
				close(paused.resume)
				if fault == "expired" {
					select {
					case <-time.After(time.Until(proof.ExpiresAt()) + time.Millisecond):
					case <-ctx.Done():
						roots.adopting.Unlock()
						t.Fatal(ctx.Err())
					}
				} else if err := control.Close(); err != nil {
					roots.adopting.Unlock()
					t.Fatal(err)
				}
				roots.adopting.Unlock()
			}
			if fault == "current" || fault == "rotated" {
				close(paused.resume)
			}
			var err error
			select {
			case err = <-done:
			case <-ctx.Done():
				t.Fatal(ctx.Err())
			}
			entry, readErr := control.ReadFunctionIntent(ctx, proof.Claim().TenantID, proof.Claim().FunctionID)
			if fault == "current" {
				if err != nil || readErr != nil {
					t.Fatalf("current signed publication refused: %v, %v", err, readErr)
				}
				intent, decodeErr := authority.DecodeFunctionIntent(entry)
				if decodeErr != nil || intent.EnvelopeSHA256 != proof.EnvelopeSHA256() {
					t.Fatalf("committed function differs from signed authority: %v", decodeErr)
				}
				return
			}
			if err == nil || !errors.Is(readErr, authority.ErrNotFound) {
				t.Fatalf("%s left durable authorizing state: %v, %v", fault, err, readErr)
			}
			if fault == "rotated" && !strings.Contains(err.Error(), "function roots changed") || fault == "expired" && !errors.Is(err, trust.ErrExpired) || fault == "released leader" && !errors.Is(err, authority.ErrNotLeader) && !errors.Is(err, authority.ErrFenced) {
				t.Fatalf("%s failed at a different boundary: %v", fault, err)
			}
		})
	}
}
