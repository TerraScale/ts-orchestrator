package functions

import (
	"context"
	"crypto/ed25519"
	"crypto/rand"
	"encoding/json/v2"
	"errors"
	"testing"
	"time"

	"github.com/TerraScale/ts-orchestrator/internal/release"
	"github.com/TerraScale/ts-orchestrator/internal/trust"
)

func TestSignedReleaseWorkerLifecycle(t *testing.T) {
	if _, err := NewWorker(t.Context(), release.VerifiedFunction{}); !errors.Is(err, ErrScope) {
		t.Fatalf("unsigned worker: %v", err)
	}
	artifact := integrationArtifact(t, "echo")
	admitted, _, _ := signedFunctionFixture(t, artifact)
	claim := admitted.Claim()
	worker, err := NewWorker(t.Context(), admitted)
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = worker.Close(context.Background()) })
	// Mutating publisher-owned bytes cannot change the admitted worker's code.
	artifact.Module[0] ^= 1
	in := Invocation{TenantID: claim.TenantID, FunctionID: claim.FunctionID, Revision: claim.Revision, ID: "signed-1", Trigger: "http", Payload: []byte("signed worker")}
	result, err := worker.Invoke(t.Context(), in)
	if err != nil {
		t.Fatal(err)
	}
	var observed Invocation
	if err := json.Unmarshal(result.Output, &observed); err != nil || string(observed.Payload) != "signed worker" {
		t.Fatalf("guest result: %s, %v", result.Output, err)
	}
	if err := worker.Close(t.Context()); err != nil {
		t.Fatal(err)
	}
	if _, err := worker.Invoke(t.Context(), in); !errors.Is(err, ErrClosed) {
		t.Fatalf("closed admitted worker: %v", err)
	}
}

func signedFunctionFixture(t *testing.T, artifact Artifact) (release.VerifiedFunction, ProcessDeployment, map[string][]byte) {
	t.Helper()
	root, rootPrivate, err := ed25519.GenerateKey(rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	leafPublic, leafPrivate, err := ed25519.GenerateKey(rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	roots, err := trust.ParseKeyring(root)
	if err != nil {
		t.Fatal(err)
	}
	keyID, err := trust.KeyID(leafPublic)
	if err != nil {
		t.Fatal(err)
	}
	encoded, err := trust.EncodeDelegatedPublicKey(leafPublic)
	if err != nil {
		t.Fatal(err)
	}
	claim := release.FunctionClaim{
		Schema: release.FunctionSchema, ABI: artifact.Manifest.ABI,
		TenantID: artifact.Manifest.TenantID, FunctionID: artifact.Manifest.FunctionID,
		Revision: artifact.Manifest.Revision, Digest: artifact.Manifest.Digest,
		Bytes: int64(len(artifact.Module)), Capabilities: []string{}, Environment: "canary", Cell: "GRU", Sequence: 1,
	}
	scope := release.FunctionScope(claim)
	now := time.Now().UTC().Truncate(time.Second)
	delegation, err := trust.SignDelegation(trust.Delegation{
		SchemaVersion: trust.SchemaVersion, SubjectKeyID: keyID, SubjectPublicKey: encoded,
		Capabilities: []trust.Capability{{Domain: scope.Domain, DeploymentID: scope.DeploymentID, Cell: scope.Cell, Environment: scope.Environment, Role: scope.Role, Slots: []string{scope.Slot}, Actions: []string{"sign"}}},
	}, now.Add(-time.Minute), now.Add(time.Hour), rootPrivate)
	if err != nil {
		t.Fatal(err)
	}
	signed, err := release.SignFunctionClaim(claim, artifact.Module, delegation, roots, leafPrivate, now, time.Minute)
	if err != nil {
		t.Fatal(err)
	}
	signedWire, err := trust.EncodeEnvelope(signed)
	if err != nil {
		t.Fatal(err)
	}
	delegationWire, err := trust.EncodeEnvelope(delegation)
	if err != nil {
		t.Fatal(err)
	}
	admitted, err := release.VerifyFunctionCurrent(signedWire, delegationWire, artifact.Module, roots, release.FunctionExpectation{
		Environment: claim.Environment, Cell: claim.Cell, TenantID: claim.TenantID, FunctionID: claim.FunctionID,
		Revision: claim.Revision, Digest: claim.Digest, MinimumSequence: 1,
	}, now)
	if err != nil {
		t.Fatal(err)
	}

	deployment := ProcessDeployment{Environment: claim.Environment, Cell: claim.Cell, TenantID: claim.TenantID, FunctionID: claim.FunctionID, Revision: claim.Revision, Digest: claim.Digest, MinimumSequence: 1, ExpiresAt: admitted.ExpiresAt()}
	return admitted, deployment, map[string][]byte{"root.pub": root, "receipt.json": signedWire, "delegation.json": delegationWire, "module.wasm": artifact.Module}
}
