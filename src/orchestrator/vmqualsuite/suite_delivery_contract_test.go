package vmqualsuite

import (
	"context"
	"crypto/ed25519"
	"encoding/json"
	"errors"
	"strings"
	"sync"
	"testing"

	"terrascale.tech/orchestrator/src/orchestrator/delivery"
	"terrascale.tech/orchestrator/src/orchestrator/sandboxproviders/edge"
	"terrascale.tech/orchestrator/src/orchestrator/vmqual"
)

type deliveryContractTestGuest struct {
	mu         sync.Mutex
	native     string
	active     map[string]string
	cordoned   map[string]bool
	persistent map[string][]byte
}

func newDeliveryContractTestGuest(native string) *deliveryContractTestGuest {
	return &deliveryContractTestGuest{native: native, active: make(map[string]string), cordoned: make(map[string]bool), persistent: make(map[string][]byte)}
}

func (g *deliveryContractTestGuest) QualifyTSNode(ctx context.Context, host string, qualification vmqual.TSNodeGuestQualification) (vmqual.TSNodeGuestObservation, error) {
	if err := ctx.Err(); err != nil {
		return vmqual.TSNodeGuestObservation{}, err
	}
	if _, err := vmqual.ValidateDeliveryArchitectureManifest(qualification.Manifest, qualification.Candidates, qualification.PublicKey); err != nil {
		return vmqual.TSNodeGuestObservation{}, err
	}
	candidate := qualification.Candidates[g.native]
	badSignature := qualification.BadSignature[g.native]
	badDigest := qualification.BadDigest[g.native]
	if !ed25519.Verify(qualification.PublicKey, candidate.Body, candidate.Signature) || delivery.SHA256Digest(candidate.Body) != candidate.Identity.Digest {
		return vmqual.TSNodeGuestObservation{}, errors.New("candidate fixture is invalid")
	}
	if ed25519.Verify(qualification.PublicKey, badSignature.Body, badSignature.Signature) {
		return vmqual.TSNodeGuestObservation{}, errors.New("bad signature fixture verified")
	}
	if delivery.SHA256Digest(badDigest.Body) == badDigest.Identity.Digest {
		return vmqual.TSNodeGuestObservation{}, errors.New("bad digest fixture matched")
	}
	g.mu.Lock()
	g.active[host] = candidate.Identity.Digest
	g.persistent[host] = append([]byte(nil), qualification.PersistenceSentinel...)
	g.mu.Unlock()
	return vmqual.TSNodeGuestObservation{
		Host: host, NativeArchitecture: g.native,
		InstalledDigest: candidate.Identity.Digest, ActiveDigest: candidate.Identity.Digest,
		SystemdUnit:             qualification.ExpectedSystemdUnit,
		PersistentBeforeRestart: append([]byte(nil), qualification.PersistenceSentinel...),
		PersistentAfterRestart:  append([]byte(nil), qualification.PersistenceSentinel...),
		InstallAttempts: []vmqual.TSNodeInstallAttempt{
			{Name: "candidate", Architecture: g.native, Digest: candidate.Identity.Digest, Accepted: true},
			{Name: "bad-signature", Architecture: g.native, Digest: badSignature.Identity.Digest, Accepted: false},
			{Name: "bad-digest", Architecture: g.native, Digest: badDigest.Identity.Digest, Accepted: false},
		},
	}, nil
}

func (g *deliveryContractTestGuest) Cordon(ctx context.Context, host string, cordoned bool) error {
	if err := ctx.Err(); err != nil {
		return err
	}
	g.mu.Lock()
	g.cordoned[host] = cordoned
	g.mu.Unlock()
	return nil
}

func (g *deliveryContractTestGuest) DrainStatus(ctx context.Context, host string) (delivery.DrainReport, error) {
	if err := ctx.Err(); err != nil {
		return delivery.DrainReport{}, err
	}
	g.mu.Lock()
	defer g.mu.Unlock()
	return delivery.DrainReport{Cordoned: g.cordoned[host], Drained: g.cordoned[host]}, nil
}

func (g *deliveryContractTestGuest) Converge(ctx context.Context, host string, plan []byte) error {
	if err := ctx.Err(); err != nil {
		return err
	}
	digest, err := digestFromDeliveryPlan(plan)
	if err != nil {
		return err
	}
	g.mu.Lock()
	g.active[host] = digest
	g.mu.Unlock()
	return nil
}

func (g *deliveryContractTestGuest) CheckDeliveryGate(ctx context.Context, host, digest, gate string) (vmqual.DeliveryGuestGateObservation, error) {
	if err := ctx.Err(); err != nil {
		return vmqual.DeliveryGuestGateObservation{}, err
	}
	g.mu.Lock()
	active := g.active[host]
	g.mu.Unlock()
	return vmqual.DeliveryGuestGateObservation{Host: host, Digest: digest, Gate: gate, Passed: delivery.SameDigest(active, digest)}, nil
}

func (g *deliveryContractTestGuest) ObserveDeliveryGuest(ctx context.Context, host string) (vmqual.DeliveryGuestObservation, error) {
	if err := ctx.Err(); err != nil {
		return vmqual.DeliveryGuestObservation{}, err
	}
	g.mu.Lock()
	defer g.mu.Unlock()
	return vmqual.DeliveryGuestObservation{
		Host: host, ActiveDigest: g.active[host], Cordoned: g.cordoned[host], UnitActive: g.active[host] != "",
		PersistentData: append([]byte(nil), g.persistent[host]...),
	}, nil
}

func TestRunDeliveryContractExercisesProductionContracts(t *testing.T) {
	stateRoot := t.TempDir()
	key := []byte("delivery-contract-capability-key")
	endpoints, err := NewLocalProviderEndpoints(LocalProviderConfig{
		StateRoot: stateRoot,
		Edge:      edge.Options{Key: key},
	})
	if err != nil {
		t.Fatalf("start local providers: %v", err)
	}
	t.Cleanup(func() { _ = endpoints.Close() })

	result, err := RunDeliveryContract(context.Background(), DeliveryContractConfig{
		StateRoot: stateRoot,
		Endpoints: endpoints,
		Guest:     newDeliveryContractTestGuest("linux/amd64"),
	})
	if err != nil {
		t.Fatalf("run delivery contract: %v", err)
	}
	if result.NativeArchitecture != "linux/amd64" || len(result.ArchitectureDigests) != 2 || result.ArchitectureDigests["linux/arm64"] == "" {
		t.Fatalf("architecture proof = %q %#v", result.NativeArchitecture, result.ArchitectureDigests)
	}
	if !result.BadSignatureRejected || !result.BadDigestRejected {
		t.Fatal("bad artifact proof did not fail closed")
	}
	if result.CanaryHost != vmqual.DeliveryContractCanary || len(result.ForwardHosts) != 4 || len(result.RollbackHosts) != 4 {
		t.Fatalf("rollout trace = canary %q forward %v rollback %v", result.CanaryHost, result.ForwardHosts, result.RollbackHosts)
	}
	if len(result.PersistentMirrors) != 12 {
		t.Fatalf("persistent mirrors = %d, want 12", len(result.PersistentMirrors))
	}
	if result.Edge.WorkerDigest == "" || result.Edge.SnippetDigest == "" || result.Edge.SnippetDigest != result.Edge.SnippetRuleDigest || !result.Edge.ReactiveWorkerFree || result.Edge.ReactiveResponses != 2 || result.Edge.ReactiveCacheHits < 1 {
		t.Fatalf("edge proof = %+v", result.Edge)
	}
	for _, receipt := range []*delivery.Receipt{result.SuccessfulReceipt, result.RollbackReceipt, result.WorkerReceipt, result.SnippetReceipt} {
		if receipt == nil || receipt.Provenance == nil || !receipt.Provenance.Verified {
			t.Fatalf("receipt lacks verified provenance: %+v", receipt)
		}
	}
}

func TestRunDeliveryContractRequiresGuestBackedTSNode(t *testing.T) {
	_, err := RunDeliveryContract(context.Background(), DeliveryContractConfig{})
	if err == nil || !strings.Contains(err.Error(), "guest-backed ts-node") {
		t.Fatalf("error = %v", err)
	}
}

func TestValidateDeliveryArchitectureManifestRejectsIdentityDrift(t *testing.T) {
	release, err := newDeliveryContractRelease()
	if err != nil {
		t.Fatal(err)
	}
	manifest := release.candidateManifest
	encoded, err := json.Marshal(manifest)
	if err != nil || delivery.SHA256Digest(encoded) != release.candidateManifestDigest {
		t.Fatalf("canonical manifest digest = %q, err = %v", release.candidateManifestDigest, err)
	}
	manifest.Artifacts[0].Digest = delivery.SHA256Digest([]byte("drift"))
	if _, err := vmqual.ValidateDeliveryArchitectureManifest(manifest, release.candidates, release.publicKey); err == nil {
		t.Fatal("manifest identity drift was accepted")
	}
}
