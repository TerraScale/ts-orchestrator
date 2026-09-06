package vmqualsuite

import (
	"context"
	"crypto/sha256"
	"encoding/hex"
	"errors"
	"fmt"
	"path/filepath"
	"testing"
	"time"

	"terrascale.tech/orchestrator/src/orchestrator/bootstrap"
	"terrascale.tech/orchestrator/src/orchestrator/vmqual"
)

type explicitControlRuntimeFixture struct {
	execute func(context.Context, bootstrap.ControlActionRequest) (bootstrap.ControlRuntimeEvidence, error)
	observe func(context.Context) (map[string]bool, error)
}

func (fixture explicitControlRuntimeFixture) Execute(ctx context.Context, r bootstrap.ControlActionRequest) (bootstrap.ControlRuntimeEvidence, error) {
	if fixture.execute == nil {
		return bootstrap.ControlRuntimeEvidence{}, bootstrap.ErrControlRuntimeUnavailable
	}
	return fixture.execute(ctx, r)
}
func (fixture explicitControlRuntimeFixture) Observe(ctx context.Context) (map[string]bool, error) {
	if fixture.observe == nil {
		return nil, bootstrap.ErrControlRuntimeUnavailable
	}
	return fixture.observe(ctx)
}

type runtimeBoundScenarioFactory struct {
	*scenarioTestFactory
	runtime    bootstrap.ControlRuntime
	resolveErr error
	resolves   int
}

func (factory *runtimeBoundScenarioFactory) QualificationControlRuntime(context.Context) (bootstrap.ControlRuntime, []bootstrap.ControlRegionBinding, error) {
	factory.resolves++
	bindings := []bootstrap.ControlRegionBinding{}
	for _, region := range []string{"gru", "sfo", "fra", "iad"} {
		bindings = append(bindings, bootstrap.ControlRegionBinding{Code: region, MemberIDs: []string{region + "-admitted-1", region + "-admitted-2"}})
	}
	return factory.runtime, bindings, factory.resolveErr
}
func fixtureRuntimeEvidence(request bootstrap.ControlActionRequest) bootstrap.ControlRuntimeEvidence {
	digest := sha256.Sum256([]byte("explicit-unit-record:" + string(request.Action.Kind) + request.Action.Region))
	hexDigest := hex.EncodeToString(digest[:])
	return bootstrap.ControlRuntimeEvidence{IdentityDigest: hexDigest, StorageDigest: hexDigest, HealthDigest: hexDigest, ObservedAt: time.Now()}
}
func TestRuntimeControlBindingIsLazyAndMissingInputNeverSelectsModeledProof(t *testing.T) {
	factory := &runtimeBoundScenarioFactory{scenarioTestFactory: newScenarioTestFactory(), resolveErr: bootstrap.ErrControlRuntimeUnavailable}
	stack, err := vmqual.NewStack(vmqual.StackConfig{StateRoot: t.TempDir(), VMFactory: factory, Network: &scenarioTestNetwork{}})
	if err != nil {
		t.Fatal(err)
	}
	driver := &LocalScenarioDriver{}
	if err := driver.AttachStack(stack); err != nil {
		t.Fatal(err)
	}
	if factory.resolves != 0 {
		t.Fatal("binding blocked baseline before runtime inputs could exist")
	}
	if _, ok := driver.control.(*runtimeControlProof); !ok {
		t.Fatal("selected modeled control fallback")
	}
	if _, err := driver.control.Bootstrap(context.Background()); !errors.Is(err, bootstrap.ErrControlRuntimeUnavailable) {
		t.Fatalf("missing actual runtime passed: %v", err)
	}
	if factory.resolves != 1 {
		t.Fatal("missing lazy runtime resolution")
	}
}
func TestRuntimeControlRejectsFactoryWithoutActualBinding(t *testing.T) {
	stack, err := vmqual.NewStack(vmqual.StackConfig{StateRoot: t.TempDir(), VMFactory: newScenarioTestFactory(), Network: &scenarioTestNetwork{}})
	if err != nil {
		t.Fatal(err)
	}
	proof := &runtimeControlProof{stack: stack, journalRoot: filepath.Join(stack.Config().StateRoot, "control-contract")}
	if _, err := proof.Bootstrap(context.Background()); !errors.Is(err, bootstrap.ErrControlRuntimeUnavailable) {
		t.Fatalf("model-only factory passed runtime qualification: %v", err)
	}
}
func TestRuntimeControlBootstrapRequiresFreshProofForBothActions(t *testing.T) {
	calls := []bootstrap.ControlActionKind{}
	fixture := explicitControlRuntimeFixture{execute: func(_ context.Context, request bootstrap.ControlActionRequest) (bootstrap.ControlRuntimeEvidence, error) {
		switch request.Action.Kind {
		case bootstrap.ControlActionStartTemporaryR1, bootstrap.ControlActionFenceR1:
		default:
			return bootstrap.ControlRuntimeEvidence{}, fmt.Errorf("unadmitted fixture action: %s", request.Action.Kind)
		}
		calls = append(calls, request.Action.Kind)
		return fixtureRuntimeEvidence(request), nil
	}}
	factory := &runtimeBoundScenarioFactory{scenarioTestFactory: newScenarioTestFactory(), runtime: fixture}
	stack, err := vmqual.NewStack(vmqual.StackConfig{StateRoot: t.TempDir(), VMFactory: factory, Network: &scenarioTestNetwork{}})
	if err != nil {
		t.Fatal(err)
	}
	proof := &runtimeControlProof{stack: stack, journalRoot: filepath.Join(stack.Config().StateRoot, "control-contract")}
	observed, err := proof.Bootstrap(context.Background())
	if err != nil {
		t.Fatal(err)
	}
	if len(calls) != 2 || calls[0] != bootstrap.ControlActionStartTemporaryR1 || calls[1] != bootstrap.ControlActionFenceR1 || !observed.Fenced || len(observed.Calls) != 2 {
		t.Fatalf("proof skipped real runtime boundary: %+v / %v", observed, calls)
	}
}
func TestRuntimeControlCandidateNeverSynthesizesReadinessOnFailureOrStaleEvidence(t *testing.T) {
	for _, mode := range []string{"unavailable", "missing-digest", "stale"} {
		t.Run(mode, func(t *testing.T) {
			fixture := explicitControlRuntimeFixture{execute: func(_ context.Context, request bootstrap.ControlActionRequest) (bootstrap.ControlRuntimeEvidence, error) {
				if mode == "unavailable" {
					return bootstrap.ControlRuntimeEvidence{}, bootstrap.ErrControlRuntimeUnavailable
				}
				evidence := fixtureRuntimeEvidence(request)
				if mode == "missing-digest" {
					evidence.StorageDigest = ""
				} else {
					evidence.ObservedAt = time.Now().Add(-time.Minute)
				}
				return evidence, nil
			}}
			provider := &runtimeControlProvider{runtime: fixture}
			candidate, err := provider.VerifyCandidate(context.Background(), bootstrap.ControlActionRequest{Action: bootstrap.ControlAction{Kind: bootstrap.ControlActionVerifyCandidate, Region: "sfo"}})
			if !errors.Is(err, bootstrap.ErrControlRuntimeUnavailable) || candidate.Ready() || len(provider.calls) != 0 {
				t.Fatalf("invalid proof became ready: %+v, %v", candidate, err)
			}
		})
	}
}

func TestRuntimeControlCandidateRequiresExplicitRuntimeGates(t *testing.T) {
	digest := sha256.Sum256([]byte("candidate-proof"))
	runtime := explicitControlRuntimeFixture{execute: func(_ context.Context, request bootstrap.ControlActionRequest) (bootstrap.ControlRuntimeEvidence, error) {
		return bootstrap.ControlRuntimeEvidence{
			IdentityDigest: hex.EncodeToString(digest[:]), StorageDigest: hex.EncodeToString(digest[:]), HealthDigest: hex.EncodeToString(digest[:]), ObservedAt: time.Now(),
			Candidate: &bootstrap.CandidateRuntimeEvidence{CaughtUp: true, IdentityReady: true, StorageReady: true, HealthReady: true},
		}, nil
	}}
	provider := &runtimeControlProvider{runtime: runtime}
	candidate, err := provider.VerifyCandidate(t.Context(), bootstrap.ControlActionRequest{Action: bootstrap.ControlAction{Kind: bootstrap.ControlActionVerifyCandidate, Region: "sfo"}})
	if err != nil || !candidate.Ready() {
		t.Fatalf("explicit candidate proof was rejected: %+v, %v", candidate, err)
	}
}

type quorumAvailabilityFixture struct {
	explicitControlRuntimeFixture
	verify func(context.Context, uint64) error
}

func (fixture quorumAvailabilityFixture) VerifyQuorumAvailability(ctx context.Context, epoch uint64) error {
	return fixture.verify(ctx, epoch)
}

func TestRuntimeControlQuorumFailureRestoresStoppedGuest(t *testing.T) {
	factory := newScenarioTestFactory()
	stack, err := vmqual.NewStack(vmqual.StackConfig{StateRoot: t.TempDir(), VMFactory: factory, Network: &scenarioTestNetwork{}})
	if err != nil {
		t.Fatal(err)
	}
	if err := stack.Start(context.Background()); err != nil {
		t.Fatal(err)
	}
	defer stack.Cleanup(context.Background())
	observedStopped := false
	checkedQuorum := false
	fixture := quorumAvailabilityFixture{
		explicitControlRuntimeFixture: explicitControlRuntimeFixture{
			execute: func(context.Context, bootstrap.ControlActionRequest) (bootstrap.ControlRuntimeEvidence, error) {
				return bootstrap.ControlRuntimeEvidence{}, bootstrap.ErrControlEpochRegression
			},
			observe: func(context.Context) (map[string]bool, error) {
				factory.mu.Lock()
				defer factory.mu.Unlock()
				observedStopped = !factory.vms["fra-member-1"].running
				return map[string]bool{"gru-admitted-1": true, "sfo-admitted-1": true, "fra-admitted-1": !observedStopped}, nil
			},
		},
		verify: func(_ context.Context, epoch uint64) error {
			checkedQuorum = epoch == 2 && observedStopped
			return bootstrap.ErrControlQuorumNotVerified
		},
	}
	proof := &runtimeControlProof{
		stack: stack, runtime: fixture, provider: &runtimeControlProvider{runtime: fixture},
		state: bootstrap.ControlPlaneState{Topology: bootstrap.ControlTopologyGlobalR3, Phase: bootstrap.ControlPhaseR3, Epoch: 2, MemberHosts: 2, ControlRegions: []string{"gru", "sfo", "fra"}},
		bindings: map[string]bootstrap.ControlRegionBinding{
			"gru": {Code: "gru", MemberIDs: []string{"gru-admitted-1", "gru-admitted-2"}},
			"sfo": {Code: "sfo", MemberIDs: []string{"sfo-admitted-1", "sfo-admitted-2"}},
			"fra": {Code: "fra", MemberIDs: []string{"fra-admitted-1", "fra-admitted-2"}},
		},
	}
	_, err = proof.VerifyPermanentR3(context.Background())
	if !errors.Is(err, bootstrap.ErrControlQuorumNotVerified) || !observedStopped || !checkedQuorum {
		t.Fatalf("failed majority proof was bypassed: stopped=%v checked=%v error=%v", observedStopped, checkedQuorum, err)
	}
	factory.mu.Lock()
	defer factory.mu.Unlock()
	if !factory.vms["fra-member-1"].running {
		t.Fatal("failed quorum observation stranded stopped replica")
	}
}
