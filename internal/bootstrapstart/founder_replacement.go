package bootstrapstart

import (
	"context"
	"errors"
	"fmt"
	"time"

	"git.terrascale.tech/TerraScale/ts-orchestrator/internal/bootstrap"
	"github.com/oracle/oci-go-sdk/v65/core"
)

var ErrFounderReplacement = errors.New("controller slot replacement is not authorized")

// FounderReplacer relaunches one completed managed peer slot as its next
// ledger attempt. It exists only on the admitted seed, which alone holds the
// delegated ledger signer. Every replacement needs root-signed retirement
// evidence for the exact prior instance: the delegated signer cannot retire.
// The successor keeps the founder plan row, private IP, slot and NATS server
// name, so the new empty-store controller rejoins raft under its old identity.
type FounderReplacer struct {
	caller founderCaller
}

// NewAdmittedFounderReplacer opens the seed's current founder authority and
// OCI adapter. It never launches anything by itself.
func NewAdmittedFounderReplacer(ctx context.Context, baked BakedInputs, accepted AcceptedInstall,
	serviceUID, serviceGID uint32,
) (*FounderReplacer, error) {
	if err := ctx.Err(); err != nil {
		return nil, err
	}
	if accepted.validate() != nil || accepted.Slot != accepted.SeedSlot ||
		accepted.DeploymentID != baked.Identity.DeploymentID || accepted.Cell != string(baked.Identity.Cell) ||
		serviceUID == 0 || serviceGID == 0 {
		return nil, ErrFounderReplacement
	}
	floor, err := NewServiceFounderSelectionFloorStore(serviceUID)
	if err != nil {
		return nil, err
	}
	if err := verifyExistingFounderFloor(floor); err != nil {
		return nil, err
	}
	reader, err := NewOCICurrentFounderAuthorityReader(baked, accepted, floor)
	if err != nil {
		return nil, fmt.Errorf("%w: open selected founder authority: %v", ErrFounderReplacement, err)
	}
	selected, err := reader.ReadCurrent(ctx, time.Now().UTC())
	if err != nil || selected.Plan.Plan().SeedSlot != accepted.Slot {
		return nil, fmt.Errorf("%w: read selected seed authority: %v", ErrFounderReplacement, err)
	}
	config, err := currentLedgerConfig(selected.Anchor, baked.Roots)
	if err != nil {
		return nil, err
	}
	provider, err := newOCIAdmissionProvider(config)
	if err != nil {
		return nil, err
	}
	material, err := LoadLaunchMaterial()
	if err != nil {
		return nil, err
	}
	adapter, err := NewFounderOCI(config.Cell, provider, material)
	if err != nil {
		return nil, err
	}
	signers, err := NewFounderSignerStore(serviceUID, serviceGID)
	if err != nil {
		return nil, err
	}
	return &FounderReplacer{caller: founderCaller{reader: reader, roots: baked.Roots,
		accepted: accepted, signers: signers, adapter: adapter}}, nil
}

// Replace advances slot to its next attempt with retirementWire and then runs
// the ordinary founder transaction for it. A replay with the same evidence
// resumes the already admitted successor attempt without another advance.
func (replacer *FounderReplacer) Replace(ctx context.Context, slot string, retirementWire []byte) error {
	if replacer == nil {
		return ErrFounderReplacement
	}
	return replacer.caller.replacePeer(ctx, slot, retirementWire)
}

// ObserveInstanceLifecycle reads the exact pinned instance's lifecycle state.
// It is read-only and never infers an instance from tags or display names.
func (replacer *FounderReplacer) ObserveInstanceLifecycle(ctx context.Context, instanceID string) (string, error) {
	if replacer == nil || replacer.caller.adapter == nil {
		return "", ErrFounderReplacement
	}
	return replacer.caller.adapter.ObserveInstanceLifecycle(ctx, instanceID)
}

// ObserveInstanceLifecycle returns the OCI lifecycle state of one exact
// instance OCID. A missing instance is reported as an error, not TERMINATED.
func (adapter *FounderOCI) ObserveInstanceLifecycle(ctx context.Context, instanceID string) (string, error) {
	if adapter == nil || adapter.compute == nil || !instanceIDRE.MatchString(instanceID) {
		return "", ErrFounderOCI
	}
	readCtx, cancel := context.WithTimeout(ctx, 20*time.Second)
	defer cancel()
	response, err := adapter.compute.GetInstance(readCtx, core.GetInstanceRequest{
		InstanceId: new(instanceID), RequestMetadata: noFounderSDKRetry()})
	if err != nil {
		return "", fmt.Errorf("GetInstance controller slot: %w", err)
	}
	if value(response.Id) != instanceID || response.LifecycleState == "" {
		return "", ErrFounderOCI
	}
	return string(response.LifecycleState), nil
}

// ControllerSlotSummary is the historically verified current HEAD of one
// controller slot. It grants nothing.
type ControllerSlotSummary struct {
	Slot         string
	Attempt      uint64
	Generation   uint64
	InstanceOCID string
	Complete     bool
	Retirement   string
}

// SummarizeControllerSlots reads every anchored controller slot's current
// HEAD. Missing or pending slots are reported incomplete; malformed records
// fail the whole read so a caller never acts on a partial view.
func SummarizeControllerSlots(ctx context.Context, ledger SlotReader, deploymentID, cell string,
	slots []string,
) (map[string]ControllerSlotSummary, error) {
	if ledger == nil || deploymentID == "" || cell == "" || len(slots) == 0 {
		return nil, ErrFounderReplacement
	}
	summaries := make(map[string]ControllerSlotSummary, len(slots))
	for _, slot := range slots {
		state, err := ledger.ReadSlot(ctx, bootstrap.BootstrapScope{DeploymentID: deploymentID, Cell: cell, Slot: slot})
		if err != nil {
			if errors.Is(err, bootstrap.ErrRecordMissing) || errors.Is(err, bootstrap.ErrRetryWindowExpired) ||
				errors.Is(err, bootstrap.ErrManagedPeerProofQuarantined) {
				summaries[slot] = ControllerSlotSummary{Slot: slot}
				continue
			}
			return nil, err
		}
		if state.Intent.Slot != slot || state.Intent.DeploymentID != deploymentID || state.Intent.Cell != cell ||
			state.Head.Attempt != state.Intent.Attempt {
			return nil, ErrFounderReplacement
		}
		summary := ControllerSlotSummary{Slot: slot, Attempt: state.Head.Attempt,
			Generation: state.Head.Generation, Retirement: state.Head.RetirementDigest}
		if state.Head.ResultDigest != "" && state.Result != nil && state.ResultRecord != nil &&
			state.ResultRecord.SHA256 == state.Head.ResultDigest && state.Result.Attempt == state.Head.Attempt {
			summary.Complete, summary.InstanceOCID = true, state.Result.InstanceOCID
		}
		summaries[slot] = summary
	}
	return summaries, nil
}

// RenderSlotRetirementCandidate returns the unsigned evidence an operator
// reviews and root-signs with `ts-orch bootstrap sign-slot-retirement`.
func RenderSlotRetirementCandidate(ctx context.Context, ledger SlotReader, deploymentID, cell, slot,
	observedEvidenceDigest, fencingAuthority string, observedAt time.Time,
) (bootstrap.RetirementEvidence, error) {
	if ledger == nil {
		return bootstrap.RetirementEvidence{}, ErrFounderReplacement
	}
	state, err := ledger.ReadSlot(ctx, bootstrap.BootstrapScope{DeploymentID: deploymentID, Cell: cell, Slot: slot})
	if err != nil {
		return bootstrap.RetirementEvidence{}, err
	}
	return bootstrap.SlotRetirementCandidate(state, observedEvidenceDigest, fencingAuthority, observedAt)
}

func (caller founderCaller) replacePeer(ctx context.Context, slot string, retirementWire []byte) error {
	evidence, err := bootstrap.DecodeSlotRetirementCandidate(retirementWire)
	if err != nil || evidence.Slot != slot || slot == caller.accepted.SeedSlot ||
		evidence.DeploymentID != caller.accepted.DeploymentID || evidence.Cell != caller.accepted.Cell {
		return fmt.Errorf("%w: retirement evidence does not name this managed peer slot", ErrFounderReplacement)
	}
	snapshot, err := caller.fresh(ctx, slot)
	if err != nil {
		return err
	}
	state := snapshot.recovery.State()
	switch {
	case state.Head.Attempt == evidence.PreviousAttempt+1 && state.Head.RetirementDigest == digest(retirementWire):
		// The successor is already admitted; resume its founder transaction.
		return caller.runPeer(ctx, slot)
	case state.Head.Attempt != evidence.PreviousAttempt ||
		snapshot.recovery.Phase() != bootstrap.ManagedPeerRecoveryComplete ||
		state.Result == nil || state.Result.InstanceOCID != evidence.PriorInstanceOCID:
		return fmt.Errorf("%w: retirement evidence is stale for the current slot attempt", ErrFounderReplacement)
	}
	if err := caller.advancePeer(ctx, snapshot, slot, retirementWire); err != nil {
		return fmt.Errorf("advance retired peer slot: %w", err)
	}
	return caller.runPeer(ctx, slot)
}

// advancePeer signs the successor intent and HEAD with the delegated ledger
// key and lets the ledger verify the root-signed retirement before the HEAD
// CAS. A concurrent advance loses on the stale HEAD ETag.
func (caller founderCaller) advancePeer(ctx context.Context, snapshot founderSnapshot, slot string,
	retirementWire []byte,
) error {
	clock := caller.now
	if clock == nil {
		clock = time.Now
	}
	now := clock().UTC().Truncate(time.Second)
	selected := snapshot.selected
	state := snapshot.recovery.State()
	keys, err := caller.signers.Load(selected, caller.accepted, caller.roots, now)
	if err != nil {
		return err
	}
	defer keys.Close()
	intent, err := selected.Plan.ReplacementManagedPeerIntent(slot, state, retirementWire, now)
	if err != nil {
		return err
	}
	expiresAt := earliestFounderTime(selected.Plan.Plan().LaunchDeadline, selected.SelectionExpiresAt,
		selected.Anchor.ExpiresAt())
	if !expiresAt.After(now) {
		return bootstrap.ErrFounderPlanExpired
	}
	intentWire, err := keys.signLedgerRecord(intent, "bootstrap-intent", intent.DeploymentID, intent.Cell,
		intent.Environment, intent.Role, slot, now, expiresAt)
	if err != nil {
		return err
	}
	head, err := bootstrap.ReplacementSlotHead(state, intent, intentWire, retirementWire)
	if err != nil {
		return err
	}
	headWire, err := keys.signHead(head, now, expiresAt)
	if err != nil {
		return err
	}
	scope := bootstrap.BootstrapScope{DeploymentID: caller.accepted.DeploymentID, Cell: caller.accepted.Cell, Slot: slot}
	_, err = snapshot.ledger.AdvanceSlot(ctx, scope, state.HeadRecord.ETag, retirementWire, intentWire, headWire)
	return err
}
