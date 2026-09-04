package vmqual

import (
	"context"
	"errors"
	"os"
	"reflect"
	"testing"

	"terrascale.tech/orchestrator/src/orchestrator/bootstrap"
)

func TestControlContractProvesLaunchR3AndRemoteRegion(t *testing.T) {
	contract, err := NewControlContract(t.TempDir())
	if err != nil {
		t.Fatal(err)
	}
	ctx := context.Background()

	bootstrapProof, err := contract.Bootstrap(ctx)
	if err != nil {
		t.Fatal(err)
	}
	if !bootstrapProof.Fenced || !bootstrapProof.BootstrapAuthorized || bootstrapProof.AcceptedEpoch != 1 || bootstrapProof.MemberHosts != 2 {
		t.Fatalf("unexpected bootstrap proof: %+v", bootstrapProof)
	}
	assertControlCalls(t, bootstrapProof.Calls,
		bootstrap.ControlActionStartTemporaryR1,
		bootstrap.ControlActionFenceR1,
	)
	assertPrivateJournal(t, bootstrapProof.JournalPath)

	sfo, err := contract.AddLaunchCandidate(ctx, "SFO")
	if err != nil {
		t.Fatal(err)
	}
	if !sfo.Candidate.Ready() || !sfo.SynchronizedBeforePromotion || sfo.Promoted || sfo.State.Epoch != 1 {
		t.Fatalf("unexpected SFO proof: %+v", sfo)
	}

	fra, err := contract.AddLaunchCandidate(ctx, "fra")
	if err != nil {
		t.Fatal(err)
	}
	if !fra.Candidate.Ready() || !fra.SynchronizedBeforePromotion || !fra.Promoted || fra.PromotionEpoch != 2 {
		t.Fatalf("unexpected FRA proof: %+v", fra)
	}
	if fra.State.Topology != bootstrap.ControlTopologyGlobalR3 || fra.State.Phase != bootstrap.ControlPhaseR3 || fra.State.BootstrapAuthorized {
		t.Fatalf("unexpected promoted state: %+v", fra.State)
	}
	assertCallOrder(t, fra.Calls, bootstrap.ControlActionVerifyCandidate, bootstrap.ControlActionPromoteR3)
	assertCallOrder(t, fra.Calls, bootstrap.ControlActionPromoteR3, bootstrap.ControlActionVerifyQuorum)
	assertCallOrder(t, fra.Calls, bootstrap.ControlActionVerifyQuorum, bootstrap.ControlActionRevokeBootstrap)

	r3, err := contract.VerifyPermanentR3(ctx)
	if err != nil {
		t.Fatal(err)
	}
	if !r3.QuorumAvailableAfterLoss || !r3.BootstrapAuthorityRetired || !r3.BootstrapAuthorityReuseDenied ||
		!r3.EpochRegressionDenied || !r3.DowngradeToR1Denied {
		t.Fatalf("unexpected permanent R3 proof: %+v", r3)
	}
	if want := []string{"gru", "sfo"}; !reflect.DeepEqual(r3.ActiveReplicasAfterLoss, want) {
		t.Fatalf("active replicas = %v, want %v", r3.ActiveReplicasAfterLoss, want)
	}

	remote, err := contract.VerifyRemoteRegion(ctx, "iad")
	if err != nil {
		t.Fatal(err)
	}
	if !remote.RemoteManaged || remote.HasGlobalReplica || remote.MemberHosts != 2 || !remote.RegionalR3BelowFloorRejected {
		t.Fatalf("unexpected remote Region proof: %+v", remote)
	}
	if remote.GlobalState.Topology != bootstrap.ControlTopologyGlobalR3 || remote.RegionState.Topology != bootstrap.ControlTopologyRemote {
		t.Fatalf("global and Region control states were conflated: global=%+v region=%+v", remote.GlobalState, remote.RegionState)
	}
	if want := []string{"fra", "gru", "sfo"}; !reflect.DeepEqual(remote.GlobalReplicas, want) {
		t.Fatalf("global replicas = %v, want %v", remote.GlobalReplicas, want)
	}
	assertControlCalls(t, remote.Calls, bootstrap.ControlActionRemoteManage)

	if got := len(contract.JournalPaths()); got != 6 {
		t.Fatalf("journal count = %d, want 6", got)
	}
	for _, path := range contract.JournalPaths() {
		assertPrivateJournal(t, path)
	}
}

func TestControlContractRejectsOutOfOrderTransitions(t *testing.T) {
	contract, err := NewControlContract(t.TempDir())
	if err != nil {
		t.Fatal(err)
	}
	if _, err := contract.AddLaunchCandidate(context.Background(), "sfo"); !errors.Is(err, ErrControlContractOrder) {
		t.Fatalf("add before bootstrap error = %v", err)
	}
	if _, err := contract.VerifyPermanentR3(context.Background()); !errors.Is(err, ErrControlContractOrder) {
		t.Fatalf("R3 verification before promotion error = %v", err)
	}
	if _, err := contract.VerifyRemoteRegion(context.Background(), "iad"); !errors.Is(err, ErrControlContractOrder) {
		t.Fatalf("remote Region before R3 verification error = %v", err)
	}
}

func TestControlContractProviderEvidenceDependsOnPriorActions(t *testing.T) {
	provider := newControlContractProvider()
	empty := bootstrap.ControlPlaneState{}
	request := bootstrap.ControlActionRequest{
		Action: bootstrap.ControlAction{
			ID:             "fence-r1-gru-2",
			Kind:           bootstrap.ControlActionFenceR1,
			Region:         "gru",
			ExpectedEpoch:  0,
			TargetEpoch:    1,
			IdempotencyKey: "control-test-fence",
		},
		State:           empty,
		PlanFingerprint: "test-plan",
	}
	if _, err := provider.FenceTemporaryR1(context.Background(), request); !errors.Is(err, ErrControlContractInvalid) {
		t.Fatalf("fence before start error = %v", err)
	}

	verify := request
	verify.Action = bootstrap.ControlAction{
		ID:             "verify-candidate-sfo-3",
		Kind:           bootstrap.ControlActionVerifyCandidate,
		Region:         "sfo",
		ExpectedEpoch:  0,
		TargetEpoch:    0,
		IdempotencyKey: "control-test-verify",
	}
	if evidence, err := provider.VerifyCandidate(context.Background(), verify); !errors.Is(err, ErrControlContractInvalid) || evidence.Ready() {
		t.Fatalf("unstarted candidate evidence=%+v error=%v", evidence, err)
	}
	if calls := provider.callsFrom(0); len(calls) != 0 {
		t.Fatalf("rejected provider calls were recorded as successful state: %+v", calls)
	}
}

func TestNewControlContractRejectsUnsafeJournalRoot(t *testing.T) {
	for _, root := range []string{"", "\n", string(os.PathSeparator)} {
		if contract, err := NewControlContract(root); !errors.Is(err, ErrControlContractInvalid) || contract != nil {
			t.Fatalf("root %q: contract=%v error=%v", root, contract, err)
		}
	}
}

func assertControlCalls(t *testing.T, calls []ControlContractCall, want ...bootstrap.ControlActionKind) {
	t.Helper()
	if len(calls) != len(want) {
		t.Fatalf("call count = %d, want %d: %+v", len(calls), len(want), calls)
	}
	for index := range want {
		if calls[index].Kind != want[index] || !calls[index].Applied {
			t.Fatalf("call %d = %+v, want applied %s", index, calls[index], want[index])
		}
	}
}

func assertCallOrder(t *testing.T, calls []ControlContractCall, before, after bootstrap.ControlActionKind) {
	t.Helper()
	beforeSequence := uint64(0)
	afterSequence := uint64(0)
	for _, call := range calls {
		if call.Kind == before {
			beforeSequence = call.Sequence
		}
		if call.Kind == after {
			afterSequence = call.Sequence
		}
	}
	if beforeSequence == 0 || afterSequence == 0 || beforeSequence >= afterSequence {
		t.Fatalf("calls do not order %s before %s: %+v", before, after, calls)
	}
}

func assertPrivateJournal(t *testing.T, path string) {
	t.Helper()
	info, err := os.Stat(path)
	if err != nil {
		t.Fatal(err)
	}
	if info.Mode().Perm() != 0o600 {
		t.Fatalf("journal %s mode = %o, want 600", path, info.Mode().Perm())
	}
	if info.Size() == 0 {
		t.Fatalf("journal %s is empty", path)
	}
}
