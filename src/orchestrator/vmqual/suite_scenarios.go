package vmqual

import (
	"context"
	"errors"
	"fmt"
	"strings"
	"time"

	"terrascale.tech/orchestrator/src/orchestrator/delivery"
	"terrascale.tech/orchestrator/src/orchestrator/vmnet"
)

type scenarioState struct {
	operations *LocalOperationsContract
	delivery   *DeliveryContractResult
	recovery   *RecoveryFaultResult
}

func (d *LocalScenarioDriver) attachedContracts() (*Stack, *ControlContract, error) {
	d.mu.Lock()
	defer d.mu.Unlock()
	if d.stack == nil || d.control == nil {
		return nil, nil, errors.New("vmqual: local scenario driver is not attached to a stack")
	}
	return d.stack, d.control, nil
}

func observeLiveRegions(ctx context.Context, stack *Stack) (map[vmnet.RegionCode]int, error) {
	if ctx == nil || stack == nil {
		return nil, errors.New("vmqual: live Region observation requires a stack and context")
	}
	stack.mu.Lock()
	vms := make(map[string]VM, len(stack.vms))
	guests := append([]Guest(nil), stack.guests...)
	for id, vm := range stack.vms {
		vms[id] = vm
	}
	stack.mu.Unlock()

	counts := make(map[vmnet.RegionCode]int, 3)
	for _, guest := range guests {
		vm := vms[guest.ID]
		if vm == nil {
			continue
		}
		observation, err := vm.Inspect(ctx)
		if err != nil {
			return nil, fmt.Errorf("vmqual: inspect scenario guest %s: %w", guest.ID, err)
		}
		if !observation.Running || !observation.Ready || observation.ID != guest.ID || observation.Region != guest.Region {
			return nil, fmt.Errorf("vmqual: scenario guest %s did not return matching live identity", guest.ID)
		}
		counts[guest.Region]++
	}
	return counts, nil
}

func (d *LocalScenarioDriver) scenarioBootstrap(ctx context.Context) error {
	stack, control, err := d.attachedContracts()
	if err != nil {
		return err
	}
	regions, err := observeLiveRegions(ctx, stack)
	if err != nil {
		return err
	}
	if err := d.prove(ScenarioBootstrap, "gru-members-live", regions[vmnet.GRU] == 2 && regions[vmnet.SFO] == 0 && regions[vmnet.FRA] == 0, fmt.Sprintf("gru=%d sfo=%d fra=%d", regions[vmnet.GRU], regions[vmnet.SFO], regions[vmnet.FRA])); err != nil {
		return err
	}
	proof, err := control.Bootstrap(ctx)
	if err != nil {
		return err
	}
	return d.prove(ScenarioBootstrap, "empty-to-fenced-r1", proof.AcceptedEpoch == 1 && proof.MemberHosts == 2 && proof.Fenced && proof.BootstrapAuthorized && proof.JournalPath != "" && len(proof.Calls) != 0, fmt.Sprintf("epoch=%d members=%d journaled=%t", proof.AcceptedEpoch, proof.MemberHosts, proof.JournalPath != ""))
}

func (d *LocalScenarioDriver) scenarioAddRegions(ctx context.Context) error {
	stack, control, err := d.attachedContracts()
	if err != nil {
		return err
	}
	regions, err := observeLiveRegions(ctx, stack)
	if err != nil {
		return err
	}
	if err := d.prove(ScenarioAddRegion, "two-live-members-per-launch-region", regions[vmnet.GRU] == 2 && regions[vmnet.SFO] == 2 && regions[vmnet.FRA] == 2, fmt.Sprintf("gru=%d sfo=%d fra=%d", regions[vmnet.GRU], regions[vmnet.SFO], regions[vmnet.FRA])); err != nil {
		return err
	}
	sfo, err := control.AddLaunchCandidate(ctx, "sfo")
	if err != nil {
		return err
	}
	if err := d.prove(ScenarioAddRegion, "sfo-synchronized-before-promotion", sfo.SynchronizedBeforePromotion && !sfo.Promoted && len(sfo.JournalPaths) == 2, fmt.Sprintf("synchronized=%t promoted=%t", sfo.SynchronizedBeforePromotion, sfo.Promoted)); err != nil {
		return err
	}
	fra, err := control.AddLaunchCandidate(ctx, "fra")
	if err != nil {
		return err
	}
	return d.prove(ScenarioAddRegion, "fra-synchronized-atomic-promotion", fra.SynchronizedBeforePromotion && fra.Promoted && fra.PromotionEpoch == 2 && len(fra.JournalPaths) == 2, fmt.Sprintf("synchronized=%t promoted=%t epoch=%d", fra.SynchronizedBeforePromotion, fra.Promoted, fra.PromotionEpoch))
}

func (d *LocalScenarioDriver) scenarioR3(ctx context.Context) error {
	_, control, err := d.attachedContracts()
	if err != nil {
		return err
	}
	proof, err := control.VerifyPermanentR3(ctx)
	if err != nil {
		return err
	}
	if err := d.prove(ScenarioR3, "permanent-r3-authority-fences", len(proof.GlobalReplicas) == 3 && proof.BootstrapAuthorityRetired && proof.BootstrapAuthorityReuseDenied && proof.EpochRegressionDenied && proof.DowngradeToR1Denied, fmt.Sprintf("replicas=%d epoch=%d", len(proof.GlobalReplicas), proof.AcceptedEpoch)); err != nil {
		return err
	}
	return d.prove(ScenarioR3, "r3-survives-one-replica-loss", proof.QuorumAvailableAfterLoss && len(proof.ActiveReplicasAfterLoss) == 2 && proof.LostReplica != "", fmt.Sprintf("active=%d lost=%s", len(proof.ActiveReplicasAfterLoss), proof.LostReplica))
}

func (d *LocalScenarioDriver) scenarioFourthRegion(ctx context.Context) error {
	_, control, err := d.attachedContracts()
	if err != nil {
		return err
	}
	proof, err := control.VerifyRemoteRegion(ctx, "iad")
	if err != nil {
		return err
	}
	return d.prove(ScenarioFourthRegion, "remote-region-without-global-replica", proof.MemberHosts == 2 && proof.RemoteManaged && !proof.HasGlobalReplica && proof.RegionalR3BelowFloorRejected && len(proof.GlobalReplicas) == 3 && proof.JournalPath != "", fmt.Sprintf("region=%s members=%d globalReplicas=%d", proof.Region, proof.MemberHosts, len(proof.GlobalReplicas)))
}

func (d *LocalScenarioDriver) scenarioReconcile(ctx context.Context) error {
	result, err := RunReconcileContract(ctx, d.Endpoints, d.Client)
	if err != nil {
		return err
	}
	if err := d.prove(ScenarioReconcile, "missing-and-mutable-drift-converged", result.InitialPlan.Creates == 1 && result.MutableDriftPlan.Updates == 1 && result.FinalPlan.Creates == 0 && result.FinalPlan.Updates == 0, fmt.Sprintf("creates=%d updates=%d", result.ProviderCalls.Creates, result.ProviderCalls.Updates)); err != nil {
		return err
	}
	return d.prove(ScenarioReconcile, "eventual-retry-and-unowned-delete-refusal", result.ProviderCalls.RetryableFailures == 1 && result.ProviderCalls.Deletes == 0 && result.HTTPCalls.Deletes == 0 && result.SkippedUnownedDelete > 0, fmt.Sprintf("retries=%d refusedDeletes=%d", result.ProviderCalls.RetryableFailures, result.SkippedUnownedDelete))
}

func (d *LocalScenarioDriver) deliveryProof(ctx context.Context) (*DeliveryContractResult, error) {
	d.mu.Lock()
	if d.state.delivery != nil {
		result := d.state.delivery
		d.mu.Unlock()
		return result, nil
	}
	stack := d.stack
	d.mu.Unlock()
	if stack == nil {
		return nil, errors.New("vmqual: delivery scenario has no attached stack")
	}
	guest, ok := stack.config.VMFactory.(DeliveryGuestControl)
	if !ok {
		return nil, errors.New("vmqual: VM factory does not implement guest-backed delivery control")
	}
	result, err := RunDeliveryContract(ctx, DeliveryContractConfig{
		StateRoot: stack.config.StateRoot,
		Endpoints: d.Endpoints,
		Guest:     guest,
		Client:    d.Client,
	})
	if err != nil {
		return nil, err
	}
	d.mu.Lock()
	d.state.delivery = &result
	d.mu.Unlock()
	return &result, nil
}

func (d *LocalScenarioDriver) scenarioSignedDelivery(ctx context.Context) error {
	result, err := d.deliveryProof(ctx)
	if err != nil {
		return err
	}
	if err := d.prove(ScenarioSignedDelivery, "native-signed-install-and-hardened-unit", result.NativeArchitecture != "" && result.GuestQualification.NativeArchitecture == result.NativeArchitecture && result.GuestQualification.SystemdUnit != "" && delivery.SameDigest(result.GuestQualification.ActiveDigest, result.GuestQualification.InstalledDigest), fmt.Sprintf("architecture=%s attempts=%d", result.NativeArchitecture, len(result.GuestQualification.InstallAttempts))); err != nil {
		return err
	}
	if err := d.prove(ScenarioSignedDelivery, "cross-architecture-manifest-and-rejections", len(result.ArchitectureDigests) == 2 && result.ArchitectureDigests["linux/amd64"] != "" && result.ArchitectureDigests["linux/arm64"] != "" && result.BadSignatureRejected && result.BadDigestRejected, fmt.Sprintf("architectures=%d badSignatureRejected=%t badDigestRejected=%t", len(result.ArchitectureDigests), result.BadSignatureRejected, result.BadDigestRejected)); err != nil {
		return err
	}
	return d.prove(ScenarioSignedDelivery, "persistent-regional-artifact-mirrors", len(result.PersistentMirrors) != 0, fmt.Sprintf("mirrors=%d", len(result.PersistentMirrors)))
}

func (d *LocalScenarioDriver) scenarioRollback(ctx context.Context) error {
	result, err := d.deliveryProof(ctx)
	if err != nil {
		return err
	}
	if err := d.prove(ScenarioRollback, "gru-canary-serial-rollout-with-rf2", result.CanaryHost == "gru-member-1" && len(result.ForwardHosts) == 4 && result.RollbackReceipt != nil, fmt.Sprintf("canary=%s forward=%d", result.CanaryHost, len(result.ForwardHosts))); err != nil {
		return err
	}
	return d.prove(ScenarioRollback, "exact-prior-release-restored-on-touched-hosts", len(result.RollbackHosts) == 4 && len(result.GuestsAfterRollback) == 6 && allDeliveryGuestsHealthy(result.GuestsAfterRollback), fmt.Sprintf("rollbackHosts=%d observedGuests=%d", len(result.RollbackHosts), len(result.GuestsAfterRollback)))
}

func allDeliveryGuestsHealthy(guests []DeliveryGuestObservation) bool {
	if len(guests) == 0 {
		return false
	}
	for _, guest := range guests {
		if strings.TrimSpace(guest.Host) == "" || strings.TrimSpace(guest.ActiveDigest) == "" || guest.Cordoned || !guest.UnitActive {
			return false
		}
	}
	return true
}

func (d *LocalScenarioDriver) scenarioEdge(ctx context.Context) error {
	result, err := d.deliveryProof(ctx)
	if err != nil {
		return err
	}
	return d.prove(ScenarioEdge, "worker-and-snippet-promote-rollback-off-hot-path", result.WorkerReceipt != nil && result.SnippetReceipt != nil && len(result.Edge.WorkerEvents) >= 2 && len(result.Edge.SnippetEvents) >= 2 && result.Edge.ReactiveResponses == 2 && result.Edge.ReactiveCacheHits > 0 && result.Edge.ReactiveWorkerFree, fmt.Sprintf("workerEvents=%d snippetEvents=%d cacheHits=%d", len(result.Edge.WorkerEvents), len(result.Edge.SnippetEvents), result.Edge.ReactiveCacheHits))
}

func (d *LocalScenarioDriver) operationsContract() (*LocalOperationsContract, error) {
	d.mu.Lock()
	if d.state.operations != nil {
		contract := d.state.operations
		d.mu.Unlock()
		return contract, nil
	}
	d.mu.Unlock()
	contract, err := NewLocalOperationsContract(d.Endpoints)
	if err != nil {
		return nil, err
	}
	d.mu.Lock()
	d.state.operations = contract
	d.mu.Unlock()
	return contract, nil
}

func (d *LocalScenarioDriver) scenarioKV(ctx context.Context) error {
	contract, err := d.operationsContract()
	if err != nil {
		return err
	}
	result, err := contract.QualifyKV(ctx)
	if err != nil {
		return err
	}
	if err := d.prove(ScenarioKV, "ten-second-health-refresh-and-write-budget", result.Interval == 10*time.Second && result.TotalWrites > 0 && len(result.BudgetObservations) != 0, fmt.Sprintf("writes=%d budgetObservations=%d", result.TotalWrites, len(result.BudgetObservations))); err != nil {
		return err
	}
	return d.prove(ScenarioKV, "safe-placement-order-and-stale-removal", result.StaleHealthRemoved && result.StalePlacementRemoved && len(result.TransitionOrder) == result.TransitionWrites && result.PlacementGeneration == 2, fmt.Sprintf("transitionWrites=%d generation=%d", result.TransitionWrites, result.PlacementGeneration))
}

func (d *LocalScenarioDriver) scenarioEstate(ctx context.Context) error {
	contract, err := d.operationsContract()
	if err != nil {
		return err
	}
	result, err := contract.QualifyEstate(ctx)
	if err != nil {
		return err
	}
	return d.prove(ScenarioEstate, "change-and-ten-second-publication-with-redaction", result.Interval == 10*time.Second && result.InitialWrites > 0 && result.UnchangedWrites == 0 && result.OnChangeWrites == 1 && result.PersistentReadback && result.SecretRejected && result.UnboundedLabelRejected, fmt.Sprintf("documents=%d changedWrites=%d", len(result.Documents), result.OnChangeWrites))
}

func (d *LocalScenarioDriver) recoveryProof(ctx context.Context) (*RecoveryFaultResult, error) {
	d.mu.Lock()
	if d.state.recovery != nil {
		result := d.state.recovery
		d.mu.Unlock()
		return result, nil
	}
	stack := d.stack
	d.mu.Unlock()
	result, err := QualifyRecoveryFaults(ctx, stack)
	if err != nil {
		return nil, err
	}
	d.mu.Lock()
	d.state.recovery = &result
	d.mu.Unlock()
	return &result, nil
}

func (d *LocalScenarioDriver) scenarioSelfHeal(ctx context.Context) error {
	result, err := d.recoveryProof(ctx)
	if err != nil {
		return err
	}
	return d.prove(ScenarioSelfHeal, "dead-host-replaced-and-caught-up", result.Host.FailedVMStopped && result.Host.ReplacementRunning && result.Host.ReplacementReady && result.Host.ReplacementCaughtUp && result.Host.ReplacementCommit >= result.Host.CatchUpTarget, fmt.Sprintf("target=%d commit=%d", result.Host.CatchUpTarget, result.Host.ReplacementCommit))
}

func (d *LocalScenarioDriver) scenarioKeyRotation(ctx context.Context) error {
	result, err := d.recoveryProof(ctx)
	if err != nil {
		return err
	}
	proof := result.Certificate
	return d.prove(ScenarioKeyRotation, "expired-certificate-rotated", proof.ExpiredSerial != proof.RotatedSerial && proof.ExpiredRejected && proof.RotatedAccepted && proof.ServiceHealthy, fmt.Sprintf("expiredRejected=%t rotatedAccepted=%t", proof.ExpiredRejected, proof.RotatedAccepted))
}

func (d *LocalScenarioDriver) scenarioFaultMatrix(ctx context.Context) error {
	result, err := d.recoveryProof(ctx)
	if err != nil {
		return err
	}
	if err := d.prove(ScenarioFaultMatrix, "guest-visible-storage-fault-matrix", len(result.Disk) == len(RequiredDiskFaultModes()), fmt.Sprintf("diskModes=%d", len(result.Disk))); err != nil {
		return err
	}
	return d.prove(ScenarioFaultMatrix, "shape-fallback-and-clock-write-fence", result.Shape.A1CapacityExhausted && result.Shape.SelectedShape == "VM.Standard.E5.Flex" && result.Shape.ReplacementReady && result.Clock.WritesFenced && result.Clock.TimeSynchronized && result.Clock.WritesAdmittedAfter && !result.Clock.SuspectHLCMinted, fmt.Sprintf("shape=%s skew=%s", result.Shape.SelectedShape, result.Clock.InjectedOffset))
}

func (d *LocalScenarioDriver) scenarioRestore(ctx context.Context) error {
	contract, err := d.operationsContract()
	if err != nil {
		return err
	}
	result, err := contract.QualifyRestoreAndMirrors(ctx)
	if err != nil {
		return err
	}
	return d.prove(ScenarioRestore, "daily-restore-snapshot-and-regional-mirrors", result.DailyInterval == 24*time.Hour && result.RunID != "" && len(result.RestoredDatabases) == 2 && result.ScratchBranchesClean && len(result.SnapshotRegions) == 3 && len(result.ArtifactRegions) == 3 && result.PersistentReadback, fmt.Sprintf("databases=%d snapshotRegions=%d artifactRegions=%d", len(result.RestoredDatabases), len(result.SnapshotRegions), len(result.ArtifactRegions)))
}

func (d *LocalScenarioDriver) scenarioDegraded(ctx context.Context) error {
	d.mu.Lock()
	stack := d.stack
	d.mu.Unlock()
	result, err := QualifyControlOutage(ctx, stack)
	if err != nil {
		return err
	}
	return d.prove(ScenarioDegraded, "admitted-data-serves-through-full-control-outage", result.Before.ControlAvailable && !result.During.ControlAvailable && result.During.AvailableReplicas == 0 && result.Probe.Served && !result.Probe.ContactedControl && result.After.ControlAvailable && result.After.AcceptedEpoch >= result.Before.AcceptedEpoch, fmt.Sprintf("beforeEpoch=%d afterEpoch=%d", result.Before.AcceptedEpoch, result.After.AcceptedEpoch))
}

func (d *LocalScenarioDriver) scenarioPartition(ctx context.Context) error {
	d.mu.Lock()
	stack := d.stack
	d.mu.Unlock()
	result, err := QualifyCrossRegionPartitions(ctx, stack)
	if err != nil {
		return err
	}
	return d.prove(ScenarioPartition, "all-region-pairs-isolate-serve-and-converge", len(result.Pairs) == len(RequiredCrossRegionPairs()), fmt.Sprintf("pairs=%d", len(result.Pairs)))
}

func (d *LocalScenarioDriver) scenarioPlacement(ctx context.Context) error {
	contract, err := d.operationsContract()
	if err != nil {
		return err
	}
	result, err := contract.QualifyPlacementLocks(ctx)
	if err != nil {
		return err
	}
	return d.prove(ScenarioPlacement, "placement-lock-survives-all-byte-transitions", result.Persistent && result.WideningRejected && len(result.Transitions) == 7 && len(result.Regions) == 2, fmt.Sprintf("transitions=%d regions=%d generation=%d", len(result.Transitions), len(result.Regions), result.Generation))
}

func (d *LocalScenarioDriver) scenarioCleanup(ctx context.Context) error {
	d.mu.Lock()
	stack := d.stack
	d.mu.Unlock()
	result, err := QualifyCleanupFaults(ctx, stack)
	if err != nil {
		return err
	}
	if err := d.prove(ScenarioCleanup, "cancellation-and-assertion-cleanup-inspected", len(result.Exercises) == 2 && len(result.Observations) == 2, fmt.Sprintf("exercises=%d observations=%d", len(result.Exercises), len(result.Observations))); err != nil {
		return err
	}
	return d.Endpoints.Close()
}
