package bootstrapstart

import (
	"bytes"
	"context"
	"crypto/ed25519"
	"errors"
	"fmt"
	"log/slog"
	"slices"
	"time"

	"git.terrascale.tech/TerraScale/ts-orchestrator/internal/bootstrap"
	"git.terrascale.tech/TerraScale/ts-orchestrator/internal/trust"
	"golang.org/x/sys/unix"
)

var ErrFounderSigner = errors.New("installed seed founder signing material is unavailable or unauthorized")
var ErrFounderRuntime = errors.New("admitted seed founder runtime is held")
var errFounderObservationStale = errors.New("exact founder OCI observation must be repeated")

// RunAdmittedFounder is entered after the local controller has passed its
// separate admission process and started embedded NATS. A peer returns before
// touching the seed's durable selection floor or any founder OCI client.
func RunAdmittedFounder(ctx context.Context, baked BakedInputs, accepted AcceptedInstall,
	serviceUID, serviceGID uint32,
) error {
	return runAdmittedFounder(ctx, baked, accepted, serviceUID, serviceGID, nil, completedAdmittedFounder,
		NewIMDSClient().FetchPlacement)
}

func runAdmittedFounder(ctx context.Context, baked BakedInputs, accepted AcceptedInstall,
	serviceUID, serviceGID uint32, floor *FounderSelectionFloorStore,
	completed func(context.Context, BakedInputs, AcceptedInstall) (bool, error),
	placement func(context.Context) (bootstrap.ControllerPlacement, error),
) error {
	if err := ctx.Err(); err != nil {
		return err
	}
	if accepted.validate() != nil || accepted.DeploymentID != baked.Identity.DeploymentID ||
		accepted.Cell != string(baked.Identity.Cell) || serviceUID == 0 || serviceGID == 0 {
		return ErrFounderRuntime
	}
	if accepted.Slot != accepted.SeedSlot {
		return nil
	}
	if floor == nil {
		var err error
		floor, err = NewServiceFounderSelectionFloorStore(serviceUID)
		if err != nil {
			return err
		}
	}
	if err := verifyExistingFounderFloor(floor); err != nil {
		return err
	}
	if completed == nil {
		return ErrFounderRuntime
	}
	// A durable local completion fact lets a seed restart without OCI.
	if floor.PeersComplete(accepted) {
		return nil
	}
	complete, err := completed(ctx, baked, accepted)
	if err != nil {
		return fmt.Errorf("%w: read historical peer completion: %v", ErrFounderRuntime, err)
	}
	if complete {
		markFounderPeersComplete(floor, accepted)
		return nil
	}
	reader, err := NewOCICurrentFounderAuthorityReader(baked, accepted, floor)
	if err != nil {
		return fmt.Errorf("%w: open selected founder authority: %v", ErrFounderRuntime, err)
	}
	if err := ctx.Err(); err != nil {
		return err
	}
	selected, err := reader.ReadCurrent(ctx, time.Now().UTC())
	if err != nil || selected.Plan.Plan().SeedSlot != accepted.Slot {
		return fmt.Errorf("%w: read selected seed authority: %v", ErrFounderRuntime, err)
	}
	config, err := currentLedgerConfig(selected.Anchor, baked.Roots)
	if err != nil {
		return err
	}
	provider, err := newOCIAdmissionProvider(config)
	if err != nil {
		return err
	}
	if err := ctx.Err(); err != nil {
		return err
	}
	material, err := LoadLaunchMaterial()
	if err != nil {
		return err
	}
	adapter, err := NewFounderOCI(config.Cell, provider, material)
	if err != nil {
		return err
	}
	if err := ctx.Err(); err != nil {
		return err
	}
	signers, err := NewFounderSignerStore(serviceUID, serviceGID)
	if err != nil {
		return err
	}
	if err := runFounderPeers(ctx, reader, baked.Roots, accepted, signers, adapter, selected, placement); err != nil {
		return err
	}
	markFounderPeersComplete(floor, accepted)
	return nil
}

// markFounderPeersComplete is best effort: without the fact the next seed
// restart repeats the read-only historical ledger check.
func markFounderPeersComplete(floor *FounderSelectionFloorStore, accepted AcceptedInstall) {
	if err := floor.MarkPeersComplete(accepted); err != nil {
		slog.Warn("record local founder peer completion", "error", err)
	}
}

func verifyExistingFounderFloor(floor *FounderSelectionFloorStore) error {
	dir, err := floor.openDirectory()
	if err != nil {
		return err
	}
	defer unix.Close(dir)
	fd, err := unix.Openat(dir, founderSelectionLockName, unix.O_RDWR|unix.O_CLOEXEC|unix.O_NOFOLLOW, 0)
	if err != nil {
		return fmt.Errorf("%w: open existing selection lock: %v", ErrFounderSelectionFloor, err)
	}
	defer unix.Close(fd)
	var stat unix.Stat_t
	if err := unix.Fstat(fd, &stat); err != nil || stat.Mode&unix.S_IFMT != unix.S_IFREG ||
		stat.Mode&0o777 != 0o600 || stat.Uid != floor.ownerUID || stat.Nlink != 1 {
		return ErrFounderSelectionFloor
	}
	if err := unix.Flock(fd, unix.LOCK_EX); err != nil {
		return err
	}
	defer unix.Flock(fd, unix.LOCK_UN)
	if _, err := floor.read(dir); err != nil {
		return err
	}
	return unix.Fsync(dir)
}

// completedAdmittedFounder reads only historical, root-verified ledger
// evidence. It cannot produce a current launch or mutation capability.
func completedAdmittedFounder(ctx context.Context, baked BakedInputs, accepted AcceptedInstall) (bool, error) {
	envelope, err := trust.DecodeEnvelope(baked.AnchorWire)
	if err != nil {
		return false, err
	}
	anchor, err := bootstrap.VerifyHistoricalBootstrapAnchor(envelope, baked.Roots,
		baked.Identity.AnchorExpectation(), accepted.AcceptedAt, bootstrap.BootstrapAnchorTrustPolicy())
	if err != nil || anchor.Digest() != accepted.AnchorSHA256 {
		return false, ErrFounderRuntime
	}
	config, err := historicalLedgerConfig(anchor, baked.Roots)
	if err != nil {
		return false, err
	}
	ledger, err := openHistoricalInstancePrincipalLedger(ctx, config, nil)
	if err != nil {
		return false, err
	}
	return founderPeersComplete(ctx, anchor.Anchor(), accepted, ledger)
}

func founderPeersComplete(ctx context.Context, anchor bootstrap.BootstrapAnchor,
	accepted AcceptedInstall, ledger SlotReader,
) (bool, error) {
	if ledger == nil || anchor.DeploymentID != accepted.DeploymentID ||
		string(anchor.Cell) != accepted.Cell || len(anchor.ControllerSlots) < 2 ||
		!slices.Contains(anchor.ControllerSlots, accepted.SeedSlot) || accepted.Slot != accepted.SeedSlot {
		return false, ErrFounderRuntime
	}
	complete := true
	for _, slot := range anchor.ControllerSlots {
		if slot == accepted.SeedSlot {
			continue
		}
		state, err := ledger.ReadSlot(ctx, bootstrap.BootstrapScope{
			DeploymentID: accepted.DeploymentID, Cell: accepted.Cell, Slot: slot})
		if err != nil {
			if errors.Is(err, bootstrap.ErrRecordMissing) || errors.Is(err, bootstrap.ErrRetryWindowExpired) ||
				errors.Is(err, bootstrap.ErrManagedPeerProofQuarantined) {
				complete = false
				continue
			}
			return false, err
		}
		if state.Head.ResultDigest == "" {
			complete = false
			continue
		}
		if state.Intent.Mode != bootstrap.IntentModeManaged || state.Result == nil ||
			state.Result.Mode != bootstrap.IntentModeManaged || state.ResultRecord == nil ||
			state.Head.ResultDigest != state.ResultRecord.SHA256 || state.PeerReceipt == nil ||
			state.PeerReceiptRecord == nil || state.Head.Attempt != state.Intent.Attempt ||
			state.Head.Attempt != state.Result.Attempt ||
			state.Intent.Slot != slot || state.Result.Slot != slot ||
			state.Intent.DeploymentID != accepted.DeploymentID || state.Intent.Cell != accepted.Cell ||
			state.Result.DeploymentID != accepted.DeploymentID || state.Result.Cell != accepted.Cell {
			return false, ErrFounderRuntime
		}
	}
	return complete, nil
}

type founderSnapshot struct {
	selected CurrentFounderAuthority
	ledger   *bootstrap.Ledger
	recovery bootstrap.ManagedPeerRecoveryAuthorization
	peer     bootstrap.VerifiedFounderPeer
	now      time.Time
}

type founderCaller struct {
	reader     *CurrentFounderAuthorityReader
	roots      trust.Keyring
	accepted   AcceptedInstall
	signers    FounderSignerStore
	adapter    *FounderOCI
	placement  func(context.Context) (bootstrap.ControllerPlacement, error)
	now        func() time.Time
	openLedger func(context.Context, CurrentFounderAuthority, trust.Keyring) (*bootstrap.Ledger, error)
}

func runFounderPeers(ctx context.Context, reader *CurrentFounderAuthorityReader, roots trust.Keyring,
	accepted AcceptedInstall, signers FounderSignerStore, adapter *FounderOCI, initial CurrentFounderAuthority,
	placement func(context.Context) (bootstrap.ControllerPlacement, error),
) error {
	if initial.Plan.Plan().SeedSlot != accepted.Slot {
		return ErrFounderRuntime
	}
	caller := founderCaller{reader: reader, roots: roots, accepted: accepted, signers: signers, adapter: adapter,
		placement: placement}
	for _, row := range initial.Plan.Plan().Peers {
		if err := caller.runPeer(ctx, row.Slot); err != nil {
			return fmt.Errorf("%w: peer %q: %w", ErrFounderRuntime, row.Slot, err)
		}
	}
	return nil
}

// checkAntiAffinity refuses a new launch that would put two controllers in
// one fault domain. It runs only before a first launch; a slot that already
// has a candidate or result is recovered regardless of placement.
func (caller founderCaller) checkAntiAffinity(ctx context.Context, plan bootstrap.FounderPlan) error {
	if caller.placement == nil {
		return fmt.Errorf("%w: seed placement source is unavailable", ErrFounderRuntime)
	}
	seed, err := caller.placement(ctx)
	if err != nil {
		return fmt.Errorf("read seed placement: %w", err)
	}
	return bootstrap.CheckControllerAntiAffinity(seed, plan.Peers)
}

func (caller founderCaller) fresh(ctx context.Context, slot string) (founderSnapshot, error) {
	if err := ctx.Err(); err != nil {
		return founderSnapshot{}, err
	}
	selected, err := caller.reader.ReadCurrent(ctx, time.Now().UTC())
	if err != nil {
		return founderSnapshot{}, err
	}
	if selected.Plan.Plan().SeedSlot != caller.accepted.Slot || selected.Anchor.Anchor().ClusterID == "" {
		return founderSnapshot{}, ErrFounderRuntime
	}
	opener := caller.openLedger
	if opener == nil {
		opener = OpenSelectedFounderLedger
	}
	ledger, err := opener(ctx, selected, caller.roots)
	if err != nil {
		return founderSnapshot{}, err
	}
	scope := bootstrap.BootstrapScope{DeploymentID: caller.accepted.DeploymentID, Cell: caller.accepted.Cell, Slot: slot}
	recovery, err := ledger.ReadForManagedPeerRecovery(ctx, scope)
	if errors.Is(err, bootstrap.ErrRecordMissing) {
		return founderSnapshot{selected: selected, ledger: ledger}, errFounderPeerUnreserved
	}
	if err != nil {
		return founderSnapshot{}, err
	}
	now := recovery.AuthorizationTime()
	if now.IsZero() || now.Location() != time.UTC || !now.Before(selected.SelectionExpiresAt) ||
		!now.Before(selected.Anchor.ExpiresAt()) {
		return founderSnapshot{}, ErrFounderRuntime
	}
	snapshot := founderSnapshot{selected: selected, ledger: ledger, recovery: recovery, now: now}
	manifest, err := verifiedFounderManifest(selected, slot, caller.roots, now)
	if err != nil {
		return founderSnapshot{}, err
	}
	if _, err := founderProofIssuedAt(snapshot, selected.ManifestWires[slot], manifest); err != nil {
		return founderSnapshot{}, err
	}
	keys, err := caller.signers.Load(selected, caller.accepted, caller.roots, now)
	if err != nil {
		return founderSnapshot{}, err
	}
	keys.Close()
	if err := ctx.Err(); err != nil {
		return founderSnapshot{}, err
	}
	now = recovery.AuthorizationTime()
	if now.IsZero() || !now.Before(selected.SelectionExpiresAt) || !now.Before(selected.Anchor.ExpiresAt()) {
		return founderSnapshot{}, ErrFounderRuntime
	}
	peer, err := selected.Plan.AuthorizePeerRecovery(slot, recovery, caller.roots, now, selected.SelectionExpiresAt,
		trust.Policy{MaxLifetime: 24 * time.Hour, ClockSkew: bootstrap.ManifestClockSkew})
	if err != nil || !now.Before(peer.EffectDeadline()) {
		return founderSnapshot{}, ErrFounderRuntime
	}
	snapshot.peer, snapshot.now = peer, now
	return snapshot, nil
}

func (caller founderCaller) peerRefresh(slot string) FounderPeerRefresh {
	return func(ctx context.Context) (bootstrap.VerifiedFounderPeer, time.Time, time.Time, error) {
		snapshot, err := caller.fresh(ctx, slot)
		return snapshot.peer, snapshot.now, snapshot.selected.SelectionExpiresAt, err
	}
}

func (caller founderCaller) completionRefresh(slot string) bootstrap.ManagedPeerRecoveryRefresh {
	return func(ctx context.Context) (bootstrap.VerifiedFounderPeer, error) {
		snapshot, err := caller.fresh(ctx, slot)
		return snapshot.peer, err
	}
}

func (caller founderCaller) runPeer(ctx context.Context, slot string) error {
	snapshot, err := caller.fresh(ctx, slot)
	if errors.Is(err, errFounderPeerUnreserved) {
		if err := caller.reservePeer(ctx, snapshot, slot); err != nil {
			return fmt.Errorf("reserve planned peer slot: %w", err)
		}
		snapshot, err = caller.fresh(ctx, slot)
	}
	if err != nil {
		return err
	}
	if snapshot.recovery.Phase() == bootstrap.ManagedPeerRecoveryComplete {
		return nil
	}
	var observation FounderOCIObservation
	switch snapshot.recovery.Phase() {
	case bootstrap.ManagedPeerRecoveryClean, bootstrap.ManagedPeerRecoveryManifestOnly:
		if err := caller.checkAntiAffinity(ctx, snapshot.selected.Plan.Plan()); err != nil {
			return err
		}
		attempt, err := NewFounderOCIAttempt(snapshot.peer, snapshot.now)
		if err != nil {
			return err
		}
		instanceID, err := caller.retryLaunch(ctx, attempt, slot)
		recordFounderLaunch(ctx, caller.accepted.Cell, caller.accepted.DeploymentID, slot, attempt, instanceID, err)
		if err != nil {
			return err
		}
		if err := caller.pinCandidate(ctx, snapshot, slot, instanceID); err != nil {
			return fmt.Errorf("pin launched founder candidate: %w", err)
		}
		snapshot, err = caller.fresh(ctx, slot)
		if err != nil {
			return err
		}
		observationAttempt, err := NewFounderOCIObservationAttempt(snapshot.peer, snapshot.now)
		if err != nil || observationAttempt.candidateID != instanceID {
			return fmt.Errorf("%w: launched founder candidate is not the pinned observation target", ErrFounderRuntime)
		}
		observation, err = caller.retryObserve(ctx, observationAttempt, slot, instanceID)
		if err != nil {
			return fmt.Errorf("observe pinned founder candidate: %w", err)
		}
	case bootstrap.ManagedPeerRecoveryCandidateOnly, bootstrap.ManagedPeerRecoveryProofStaged,
		bootstrap.ManagedPeerRecoveryQuarantined, bootstrap.ManagedPeerRecoveryReceiptOnly:
		if snapshot.recovery.Phase() == bootstrap.ManagedPeerRecoveryProofStaged {
			if progress, ok := snapshot.recovery.Progress(); ok &&
				progress.Phase == bootstrap.ManagedPeerProgressResult && snapshot.recovery.State().Result != nil {
				break // Replay the exact staged positive result without another OCI read.
			}
		}
		attempt, err := NewFounderOCIObservationAttempt(snapshot.peer, snapshot.now)
		if err != nil {
			return err
		}
		observation, err = caller.retryObserve(ctx, attempt, slot, attempt.candidateID)
		if err != nil {
			return err
		}
	case bootstrap.ManagedPeerRecoveryResultReady:
		// The exact persisted positive result is sufficient for HEAD repair.
	default:
		return ErrFounderRuntime
	}
	return caller.completePeer(ctx, slot, observation)
}

// errFounderPeerUnreserved marks a planned peer slot with no ledger records.
var errFounderPeerUnreserved = errors.New("founder peer slot is not reserved")

// reservePeer writes the signed attempt-one intent and initial HEAD for a
// planned peer that has no ledger records yet; only then can the founder
// launch it. The intent pins the exact selected plan row, so recovery and
// every later launch retry verify against the same reservation.
func (caller founderCaller) reservePeer(ctx context.Context, snapshot founderSnapshot, slot string) error {
	clock := caller.now
	if clock == nil {
		clock = time.Now
	}
	now := clock().UTC().Truncate(time.Second)
	selected := snapshot.selected
	keys, err := caller.signers.Load(selected, caller.accepted, caller.roots, now)
	if err != nil {
		return err
	}
	defer keys.Close()
	intent, err := selected.Plan.InitialManagedPeerIntent(slot, now)
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
	headWire, err := keys.signHead(bootstrap.SlotHead{SchemaVersion: 2, DeploymentID: intent.DeploymentID,
		Cell: intent.Cell, Environment: intent.Environment, Role: intent.Role, Slot: slot,
		Attempt: intent.Attempt, Generation: intent.Generation, IntentDigest: digest(intentWire)}, now, expiresAt)
	if err != nil {
		return err
	}
	scope := bootstrap.BootstrapScope{DeploymentID: caller.accepted.DeploymentID, Cell: caller.accepted.Cell, Slot: slot}
	_, err = snapshot.ledger.ReserveSlot(ctx, scope, intentWire, headWire)
	return err
}

func (caller founderCaller) retryLaunch(ctx context.Context, attempt FounderOCIAttempt, slot string) (string, error) {
	var last error
	for range 3 {
		if err := ctx.Err(); err != nil {
			return "", err
		}
		instanceID, err := caller.adapter.Launch(ctx, attempt, caller.peerRefresh(slot))
		if err == nil {
			return instanceID, nil
		}
		last = err
		if err := ctx.Err(); err != nil {
			return "", err
		}
	}
	return "", last
}

func (caller founderCaller) pinCandidate(ctx context.Context, snapshot founderSnapshot, slot, instanceID string) error {
	state := snapshot.recovery.State()
	if state.Intent.Mode != bootstrap.IntentModeManaged || state.Intent.Slot != slot ||
		!instanceIDRE.MatchString(instanceID) || snapshot.recovery.Phase() != bootstrap.ManagedPeerRecoveryClean &&
		snapshot.recovery.Phase() != bootstrap.ManagedPeerRecoveryManifestOnly {
		return ErrFounderRuntime
	}
	keys, err := caller.signers.Load(snapshot.selected, caller.accepted, caller.roots, snapshot.now)
	if err != nil {
		return err
	}
	defer keys.Close()
	manifest, err := verifiedFounderManifest(snapshot.selected, slot, caller.roots, snapshot.now)
	if err != nil {
		return err
	}
	issuedAt, err := founderProofIssuedAt(snapshot, snapshot.selected.ManifestWires[slot], manifest)
	if err != nil {
		return err
	}
	expiresAt := earliestFounderTime(snapshot.now.Add(5*time.Minute), snapshot.peer.EffectDeadline(),
		snapshot.selected.SelectionExpiresAt)
	if !expiresAt.After(issuedAt) {
		return ErrFounderRuntime
	}
	candidate := bootstrap.ManagedPeerCandidate{SchemaVersion: 1,
		DeploymentID: state.Intent.DeploymentID, Cell: state.Intent.Cell,
		Environment: state.Intent.Environment, Role: state.Intent.Role, Slot: slot,
		Attempt: state.Intent.Attempt, Generation: state.Intent.Generation,
		IntentDigest: state.IntentRecord.SHA256, CreateKey: state.Intent.CreateKey,
		FounderPlanSHA256: state.Intent.FounderPlanSHA256, PeerRowDigest: state.Intent.PeerRowDigest,
		ManifestDigest: state.Intent.ManifestDigest, LaunchProfileDigest: state.Intent.LaunchRequestDigest,
		InstanceOCID: instanceID}
	wire, err := keys.signCandidate(candidate, issuedAt, expiresAt)
	if err != nil {
		return err
	}
	scope := bootstrap.BootstrapScope{DeploymentID: caller.accepted.DeploymentID,
		Cell: caller.accepted.Cell, Slot: slot}
	return snapshot.ledger.RecordManagedPeerCandidate(ctx, scope, wire, keys.signProgress,
		caller.completionRefresh(slot))
}

func (caller founderCaller) retryObserve(ctx context.Context, attempt FounderOCIAttempt, slot, instanceID string) (FounderOCIObservation, error) {
	var last error
	for range 3 {
		if err := ctx.Err(); err != nil {
			return FounderOCIObservation{}, err
		}
		observed, err := caller.adapter.Observe(ctx, attempt, caller.peerRefresh(slot), instanceID)
		if err == nil {
			return observed, nil
		}
		last = err
		if err := ctx.Err(); err != nil {
			return FounderOCIObservation{}, err
		}
	}
	return FounderOCIObservation{}, last
}

func (caller founderCaller) completePeer(ctx context.Context, slot string, observed FounderOCIObservation) error {
	for range 3 {
		err := caller.completePeerOnce(ctx, slot, observed)
		if !errors.Is(err, errFounderObservationStale) {
			return err
		}
		snapshot, err := caller.fresh(ctx, slot)
		if err != nil {
			return err
		}
		if snapshot.recovery.Phase() == bootstrap.ManagedPeerRecoveryComplete ||
			snapshot.recovery.Phase() == bootstrap.ManagedPeerRecoveryResultReady {
			observed = FounderOCIObservation{}
			continue
		}
		attempt, err := NewFounderOCIObservationAttempt(snapshot.peer, snapshot.now)
		if err != nil {
			return err
		}
		observed, err = caller.retryObserve(ctx, attempt, slot, attempt.candidateID)
		if err != nil {
			return err
		}
	}
	return ErrFounderOCI
}

func (caller founderCaller) completePeerOnce(ctx context.Context, slot string, observed FounderOCIObservation) error {
	snapshot, err := caller.fresh(ctx, slot)
	if err != nil {
		return err
	}
	state := snapshot.recovery.State()
	if snapshot.recovery.Phase() == bootstrap.ManagedPeerRecoveryComplete {
		return nil
	}
	if state.Intent.Mode != bootstrap.IntentModeManaged || state.Intent.Slot != slot {
		return ErrFounderRuntime
	}
	if state.Candidate == nil || state.CandidateRecord == nil ||
		state.Candidate.InstanceOCID == "" || state.CandidateRecord.SHA256 == "" ||
		observed.InstanceOCID != "" && observed.InstanceOCID != state.Candidate.InstanceOCID {
		return ErrFounderRuntime
	}
	progress, hasProgress := snapshot.recovery.Progress()
	stagedResult := snapshot.recovery.Phase() == bootstrap.ManagedPeerRecoveryProofStaged && hasProgress &&
		progress.Phase == bootstrap.ManagedPeerProgressResult && state.Result != nil
	resultReady := snapshot.recovery.Phase() == bootstrap.ManagedPeerRecoveryResultReady || stagedResult
	quarantined := snapshot.recovery.Phase() == bootstrap.ManagedPeerRecoveryQuarantined
	if !resultReady && !observed.fresh() {
		return errFounderObservationStale
	}
	keys, err := caller.signers.Load(snapshot.selected, caller.accepted, caller.roots, snapshot.now)
	if err != nil {
		return err
	}
	defer keys.Close()
	manifest, err := verifiedFounderManifest(snapshot.selected, slot, caller.roots, snapshot.now)
	if err != nil {
		return err
	}
	manifestWire := snapshot.selected.ManifestWires[slot]
	if state.ManifestRecord != nil {
		manifestWire = state.ManifestRecord.Bytes
	}
	if digest(manifestWire) != manifest.Digest() {
		return ErrFounderRuntime
	}
	expiresAt, err := founderProofExpiry(snapshot, manifest)
	if err != nil {
		return err
	}
	// OCI Date is a lower bound on server time, while AuthorizationTime is an
	// upper bound for expiry checks. Sign from the lower bound so an immediate
	// write cannot precede its own issued-at time at OCI's second precision.
	issuedAt, err := founderProofIssuedAt(snapshot, manifestWire, manifest)
	if err != nil || !expiresAt.After(issuedAt) {
		return ErrFounderRuntime
	}
	var facts bootstrap.InstanceFacts
	if state.PeerReceipt != nil && !quarantined {
		facts, err = founderFactsFromReceipt(manifest, *state.PeerReceipt)
		if err != nil {
			return err
		}
		if observed.InstanceOCID != "" && observed.InstanceOCID != facts.InstanceOCID {
			return ErrFounderRuntime
		}
	} else {
		facts, err = founderFactsFromObservation(snapshot, manifest, observed)
		if err != nil {
			return err
		}
	}
	var receiptWire []byte
	if state.PeerReceiptRecord != nil && !quarantined {
		receiptWire = state.PeerReceiptRecord.Bytes
	} else if hasProgress && !quarantined && progress.Phase == bootstrap.ManagedPeerProgressReceipt {
		receiptWire = progress.PendingProofWire
	} else {
		receiptWire, err = keys.signPeerReceipt(manifest, facts, issuedAt, expiresAt)
		if err != nil {
			return err
		}
	}
	var resultWire []byte
	if state.ResultRecord != nil && !quarantined {
		resultWire = state.ResultRecord.Bytes
	} else if stagedResult {
		resultWire = progress.PendingProofWire
	} else {
		if observed.InstanceOCID == "" || observed.InstanceETag == "" {
			return ErrFounderRuntime
		}
		if validateFounderProofIssuedAt(snapshot, manifestWire, manifest, observed.ObservedAt) != nil {
			return errFounderObservationStale
		}
		result := bootstrap.Result{SchemaVersion: 1, Mode: bootstrap.IntentModeManaged,
			DeploymentID: state.Intent.DeploymentID, Cell: state.Intent.Cell, Environment: state.Intent.Environment,
			Role: state.Intent.Role, Slot: slot, Attempt: state.Intent.Attempt, Generation: state.Intent.Generation,
			RegionIntentGeneration: state.Intent.RegionIntentGeneration, IntentDigest: state.IntentRecord.SHA256,
			InstanceOCID: observed.InstanceOCID, ETag: observed.InstanceETag, OCIRegion: state.Intent.OCIRegion,
			CompartmentOCID: observed.CompartmentID, ImageOCID: observed.ImageID, Shape: observed.Shape,
			ObservedProfileDigest: state.Intent.LaunchRequestDigest, PeerReceiptDigest: digest(receiptWire),
			CreateKey: state.Intent.CreateKey, ObservedAt: observed.ObservedAt}
		resultWire, err = keys.signResult(result, issuedAt, expiresAt)
		if err != nil {
			return err
		}
	}
	head := state.Head
	head.CandidateDigest = state.CandidateRecord.SHA256
	head.ResultDigest = digest(resultWire)
	headWire, err := keys.signHead(head, issuedAt, expiresAt)
	if err != nil {
		return err
	}
	if !resultReady && !observed.fresh() {
		return errFounderObservationStale
	}
	scope := bootstrap.BootstrapScope{DeploymentID: caller.accepted.DeploymentID, Cell: caller.accepted.Cell, Slot: slot}
	_, err = snapshot.ledger.RecordManagedPeer(ctx, scope, manifestWire, receiptWire, facts,
		resultWire, headWire, keys.signProgress, caller.completionRefresh(slot))
	if errors.Is(err, bootstrap.ErrManagedPeerObservationStale) {
		return errFounderObservationStale
	}
	if err != nil {
		return fmt.Errorf("record managed founder peer: %w", err)
	}
	return nil
}

func founderProofExpiry(snapshot founderSnapshot, manifest bootstrap.VerifiedManifest) (time.Time, error) {
	expiresAt := earliestFounderTime(snapshot.now.Add(5*time.Minute), snapshot.peer.EffectDeadline(),
		snapshot.selected.SelectionExpiresAt)
	ledgerGrant, err := trust.DecodeEnvelope(snapshot.selected.Anchor.Anchor().LedgerDelegationWire)
	if err != nil {
		return time.Time{}, err
	}
	expiresAt = earliestFounderTime(expiresAt, ledgerGrant.ExpiresAt)
	if manifest.Manifest().PeerReceiptDelegation == nil {
		return time.Time{}, ErrFounderRuntime
	}
	expiresAt = earliestFounderTime(expiresAt, manifest.Manifest().PeerReceiptDelegation.ExpiresAt)
	if !expiresAt.After(snapshot.now) {
		return time.Time{}, ErrFounderRuntime
	}
	return expiresAt, nil
}

func founderProofIssuedAt(snapshot founderSnapshot, manifestWire []byte,
	manifest bootstrap.VerifiedManifest,
) (time.Time, error) {
	issuedAt := snapshot.recovery.ServerDate()
	if err := validateFounderProofIssuedAt(snapshot, manifestWire, manifest, issuedAt); err != nil {
		return time.Time{}, err
	}
	return issuedAt, nil
}

func validateFounderProofIssuedAt(snapshot founderSnapshot, manifestWire []byte,
	manifest bootstrap.VerifiedManifest, issuedAt time.Time,
) error {
	if issuedAt.IsZero() || issuedAt.Location() != time.UTC ||
		issuedAt.Before(snapshot.selected.Anchor.IssuedAt()) {
		return ErrFounderRuntime
	}
	manifestEnvelope, err := trust.DecodeEnvelope(manifestWire)
	if err != nil {
		return err
	}
	ledgerGrant, err := trust.DecodeEnvelope(snapshot.selected.Anchor.Anchor().LedgerDelegationWire)
	if err != nil {
		return err
	}
	peerGrant := manifest.Manifest().PeerReceiptDelegation
	if peerGrant == nil || issuedAt.Before(manifestEnvelope.IssuedAt) ||
		issuedAt.Before(ledgerGrant.IssuedAt) || issuedAt.Before(peerGrant.IssuedAt) {
		return ErrFounderRuntime
	}
	return nil
}

func earliestFounderTime(first time.Time, rest ...time.Time) time.Time {
	for _, next := range rest {
		if next.Before(first) {
			first = next
		}
	}
	return first
}

func founderFactsFromObservation(snapshot founderSnapshot, manifest bootstrap.VerifiedManifest,
	observed FounderOCIObservation,
) (bootstrap.InstanceFacts, error) {
	if observed.InstanceOCID == "" || observed.InstanceETag == "" {
		return bootstrap.InstanceFacts{}, ErrFounderRuntime
	}
	profile, ok := manifest.Profile(snapshot.recovery.State().Intent.Slot)
	if !ok {
		return bootstrap.InstanceFacts{}, ErrFounderRuntime
	}
	state := snapshot.recovery.State()
	return bootstrap.InstanceFacts{DeploymentID: state.Intent.DeploymentID,
		Environment: state.Intent.Environment, ClusterID: snapshot.selected.Anchor.Anchor().ClusterID,
		Cell: snapshot.selected.Anchor.Anchor().Cell, OCIRegion: state.Intent.OCIRegion,
		Role: state.Intent.Role, Slot: state.Intent.Slot, InstanceOCID: observed.InstanceOCID,
		CompartmentOCID: observed.CompartmentID, ImageOCID: observed.ImageID,
		CreateKey: state.Intent.CreateKey, IntentSHA256: state.IntentRecord.SHA256, Profile: profile}, nil
}

func founderFactsFromReceipt(manifest bootstrap.VerifiedManifest, receipt bootstrap.Receipt,
) (bootstrap.InstanceFacts, error) {
	profile, ok := manifest.Profile(receipt.Slot)
	if !ok || receipt.ManifestDigest != manifest.Digest() {
		return bootstrap.InstanceFacts{}, ErrFounderRuntime
	}
	return bootstrap.InstanceFacts{DeploymentID: receipt.DeploymentID, Environment: receipt.Environment,
		ClusterID: receipt.ClusterID, Cell: receipt.Cell, OCIRegion: receipt.OCIRegion,
		Role: receipt.Role, Slot: receipt.Slot, InstanceOCID: receipt.InstanceOCID,
		CompartmentOCID: receipt.CompartmentOCID, ImageOCID: receipt.ImageOCID,
		CreateKey: receipt.CreateKey, IntentSHA256: receipt.IntentSHA256, Profile: profile}, nil
}

// FounderSignerStore reads only the signed seed's installed 0600 material.
// Production uses the admission-owned fixed directory and service UID/GID.
type FounderSignerStore struct {
	directory            string
	uid                  uint32
	gid                  uint32
	allowUnsafeAncestors bool
}

func NewFounderSignerStore(serviceUID, serviceGID uint32) (FounderSignerStore, error) {
	if serviceUID == 0 || serviceGID == 0 {
		return FounderSignerStore{}, ErrFounderSigner
	}
	return FounderSignerStore{directory: MaterialDirectory, uid: serviceUID, gid: serviceGID}, nil
}

// FounderSigningKeys holds distinct delegated keys for peer receipt and
// bootstrap ledger records. The caller must close it after each transition.
type FounderSigningKeys struct {
	peer   ed25519.PrivateKey
	ledger ed25519.PrivateKey
}

func (keys *FounderSigningKeys) Close() {
	if keys == nil {
		return
	}
	clear(keys.peer)
	clear(keys.ledger)
	keys.peer = nil
	keys.ledger = nil
}

func (keys FounderSigningKeys) signResult(result bootstrap.Result, issuedAt, expiresAt time.Time) ([]byte, error) {
	return keys.signLedgerRecord(result, "bootstrap-result", result.DeploymentID, result.Cell,
		result.Environment, result.Role, result.Slot, issuedAt, expiresAt)
}

func (keys FounderSigningKeys) signCandidate(candidate bootstrap.ManagedPeerCandidate,
	issuedAt, expiresAt time.Time,
) ([]byte, error) {
	return keys.signLedgerRecord(candidate, "bootstrap-candidate", candidate.DeploymentID, candidate.Cell,
		candidate.Environment, candidate.Role, candidate.Slot, issuedAt, expiresAt)
}

func (keys FounderSigningKeys) signProgress(progress bootstrap.ManagedPeerProgress,
	issuedAt, expiresAt time.Time,
) ([]byte, error) {
	return keys.signLedgerRecord(progress, "bootstrap-progress", progress.DeploymentID, progress.Cell,
		progress.Environment, progress.Role, progress.Slot, issuedAt, expiresAt)
}

func (keys FounderSigningKeys) signHead(head bootstrap.SlotHead, issuedAt, expiresAt time.Time) ([]byte, error) {
	return keys.signLedgerRecord(head, "bootstrap-slot-head", head.DeploymentID, head.Cell,
		head.Environment, head.Role, head.Slot, issuedAt, expiresAt)
}

func (keys FounderSigningKeys) signLedgerRecord(value any, domain, deploymentID, cell,
	environment, role, slot string, issuedAt, expiresAt time.Time,
) ([]byte, error) {
	if len(keys.ledger) != ed25519.PrivateKeySize || issuedAt.IsZero() ||
		issuedAt.Location() != time.UTC || !expiresAt.After(issuedAt) {
		return nil, ErrFounderSigner
	}
	payload, err := trust.EncodePayload(value)
	if err != nil {
		return nil, err
	}
	envelope, err := trust.Sign(payload, trust.Scope{Domain: domain, DeploymentID: deploymentID,
		Cell: cell, Environment: environment, Role: role, Slot: slot}, issuedAt, expiresAt, keys.ledger)
	if err != nil {
		return nil, err
	}
	return trust.EncodeEnvelope(envelope)
}

func (keys FounderSigningKeys) signPeerReceipt(manifest bootstrap.VerifiedManifest,
	facts bootstrap.InstanceFacts, issuedAt, expiresAt time.Time,
) ([]byte, error) {
	if len(keys.peer) != ed25519.PrivateKeySize {
		return nil, ErrFounderSigner
	}
	envelope, err := bootstrap.SignPeerReceipt(manifest, facts, issuedAt, expiresAt, keys.peer)
	if err != nil {
		return nil, err
	}
	return trust.EncodeEnvelope(envelope)
}

func (store FounderSignerStore) Load(current CurrentFounderAuthority, accepted AcceptedInstall,
	roots trust.Keyring, now time.Time,
) (FounderSigningKeys, error) {
	if accepted.validate() != nil || !current.Plan.IsVerified() || !current.Anchor.IsVerified() ||
		len(roots) == 0 || now.IsZero() || now.Location() != time.UTC ||
		!now.Before(current.SelectionExpiresAt) {
		return FounderSigningKeys{}, ErrFounderSigner
	}
	plan := current.Plan.Plan()
	anchor := current.Anchor.Anchor()
	if plan.SeedSlot != accepted.Slot || plan.SeedManifestSHA256 != accepted.ManifestSHA256 ||
		plan.DeploymentID != accepted.DeploymentID || string(plan.Cell) != accepted.Cell ||
		anchor.ClusterID == "" || plan.AnchorSHA256 != current.Anchor.Digest() {
		return FounderSigningKeys{}, ErrFounderSigner
	}
	seed, err := verifiedFounderManifest(current, accepted.Slot, roots, now)
	if err != nil || seed.Digest() != accepted.ManifestSHA256 {
		return FounderSigningKeys{}, fmt.Errorf("%w: selected accepted seed manifest: %v", ErrFounderSigner, err)
	}
	manifest := seed.Manifest()
	peerReference, err := exactSeedSignerReference(manifest, bootstrap.SecretSeedFounder)
	if err != nil {
		return FounderSigningKeys{}, err
	}
	ledgerReference, err := exactSeedSignerReference(manifest, bootstrap.SecretSeedLedgerSigner)
	if err != nil {
		return FounderSigningKeys{}, err
	}
	ledgerGrant, err := current.Anchor.LedgerDelegation()
	if err != nil {
		return FounderSigningKeys{}, fmt.Errorf("%w: selected ledger delegation: %v", ErrFounderSigner, err)
	}
	var peerKeyID string
	for _, row := range plan.Peers {
		peerManifest, err := verifiedFounderManifest(current, row.Slot, roots, now)
		if err != nil || peerManifest.Digest() != row.ManifestSHA256 {
			return FounderSigningKeys{}, fmt.Errorf("%w: selected peer manifest %q: %v", ErrFounderSigner, row.Slot, err)
		}
		peerDelegation := peerManifest.Manifest().PeerReceiptDelegation
		if peerDelegation == nil {
			return FounderSigningKeys{}, ErrFounderSigner
		}
		verified, err := trust.VerifyDelegationCurrent(*peerDelegation, roots, now, bootstrap.ManifestTrustPolicy())
		if err != nil || peerKeyID != "" && peerKeyID != verified.SubjectKeyID() {
			return FounderSigningKeys{}, fmt.Errorf("%w: peer receipt delegations differ or expired: %v", ErrFounderSigner, err)
		}
		peerKeyID = verified.SubjectKeyID()
	}
	if peerKeyID == "" || peerKeyID == ledgerGrant.SubjectKeyID() {
		return FounderSigningKeys{}, fmt.Errorf("%w: receipt and ledger signing roles require distinct delegated keys", ErrFounderSigner)
	}
	fd, err := openMaterialDirectory(store.directory, store.uid, store.gid, 0o700, store.allowUnsafeAncestors)
	if err != nil {
		return FounderSigningKeys{}, fmt.Errorf("%w: open installed seed material: %v", ErrFounderSigner, err)
	}
	defer unix.Close(fd)
	peerKey, err := store.readKey(fd, peerReference, accepted.MaterialSHA256, peerKeyID)
	if err != nil {
		return FounderSigningKeys{}, err
	}
	ledgerKey, err := store.readKey(fd, ledgerReference, accepted.MaterialSHA256, ledgerGrant.SubjectKeyID())
	if err != nil {
		clear(peerKey)
		return FounderSigningKeys{}, err
	}
	return FounderSigningKeys{peer: peerKey, ledger: ledgerKey}, nil
}

func exactSeedSignerReference(manifest bootstrap.Manifest, purpose bootstrap.SecretPurpose) (bootstrap.SecretReference, error) {
	var selected bootstrap.SecretReference
	count := 0
	for _, reference := range manifest.Secrets {
		if reference.Purpose == purpose {
			if reference.Slot != manifest.SeedSlot {
				return bootstrap.SecretReference{}, ErrFounderSigner
			}
			selected = reference
			count++
		}
	}
	if count != 1 {
		return bootstrap.SecretReference{}, ErrFounderSigner
	}
	return selected, nil
}

func (store FounderSignerStore) readKey(fd int, reference bootstrap.SecretReference,
	installed map[string]string, delegatedKeyID string,
) (ed25519.PrivateKey, error) {
	if installed[reference.TargetFile] != reference.SHA256 {
		return nil, fmt.Errorf("%w: installed material digest differs from seed manifest", ErrFounderSigner)
	}
	wire, err := readMaterial(fd, reference.TargetFile, store.uid, store.gid, reference.SHA256, reference.MaxBytes)
	if err != nil {
		return nil, fmt.Errorf("%w: read exact installed signer: %v", ErrFounderSigner, err)
	}
	defer clear(wire)
	if len(wire) != ed25519.PrivateKeySize ||
		!bytes.Equal(ed25519.NewKeyFromSeed(wire[:ed25519.SeedSize]), wire) {
		return nil, ErrFounderSigner
	}
	key := ed25519.PrivateKey(bytes.Clone(wire))
	keyID, err := trust.KeyID(key.Public().(ed25519.PublicKey))
	if err != nil || keyID != delegatedKeyID {
		clear(key)
		return nil, fmt.Errorf("%w: installed signer key differs from current root delegation", ErrFounderSigner)
	}
	return key, nil
}

func verifiedFounderManifest(current CurrentFounderAuthority, slot string, roots trust.Keyring,
	now time.Time,
) (bootstrap.VerifiedManifest, error) {
	wire := current.ManifestWires[slot]
	if len(wire) == 0 || !slices.Contains(current.Plan.Plan().ControllerSlots, slot) {
		return bootstrap.VerifiedManifest{}, ErrFounderSigner
	}
	envelope, err := trust.DecodeEnvelope(wire)
	if err != nil {
		return bootstrap.VerifiedManifest{}, err
	}
	manifest, err := bootstrap.ManifestPayload(envelope.Payload)
	if err != nil {
		return bootstrap.VerifiedManifest{}, err
	}
	expected, err := current.Anchor.ManifestExpectation(slot, manifest.ImageOCID)
	if err != nil {
		return bootstrap.VerifiedManifest{}, err
	}
	return bootstrap.VerifyManifest(envelope, roots, expected, now, bootstrap.ManifestTrustPolicy())
}
