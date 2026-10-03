package app

import (
	"context"
	"crypto/ed25519"
	"crypto/sha256"
	"encoding/hex"
	"errors"
	"fmt"
	"io"
	"os"
	"path/filepath"
	"regexp"
	"slices"
	"strconv"
	"strings"
	"time"

	"git.terrascale.tech/TerraScale/ts-orchestrator/internal/authority"
	"git.terrascale.tech/TerraScale/ts-orchestrator/internal/delivery"
	"git.terrascale.tech/TerraScale/ts-orchestrator/internal/natscell"
	"git.terrascale.tech/TerraScale/ts-orchestrator/internal/placement"
	"git.terrascale.tech/TerraScale/ts-orchestrator/internal/protocol"
	staged "git.terrascale.tech/TerraScale/ts-orchestrator/internal/rollout"
	"github.com/nats-io/nats.go"
)

const (
	deployReleaseDirectory  = "releases"
	deployKnownBadDirectory = "known-bad"
	updateOutcomePoll       = 10 * time.Second
	defaultUpdateSeatWait   = 20 * time.Minute
	updateHeldPhase         = string(placement.ManagedUpdateSeatHeld)
	updatePreparedPhase     = string(placement.ManagedUpdateSeatPrepared)
	updateServingPhase      = string(placement.ManagedUpdateSeatCanaryServing)
	managedCompatibilitySig = time.Minute
)

var knownBadFilePattern = regexp.MustCompile(`^([0-9a-f]{64})\.json$`)

// terrabaseCompatibilitySigner is the independent actor that certifies a
// candidate's persistent-format and mixed-version compatibility.
type terrabaseCompatibilitySigner struct {
	Actor   string
	KeyFile string
}

// terrabaseUpdateOptions bound one rollout run.
type terrabaseUpdateOptions struct {
	// SeatWait bounds each seat's wait for a terminal outcome.
	SeatWait time.Duration
	// Soak is how long a promoted seat must keep serving the candidate with
	// the same process before the next seat is updated. Zero disables it.
	Soak time.Duration
	// AssumeCompatible certifies every compatibility statement for releases
	// that publish no compatibility declaration, which was the behaviour
	// before evidence was derived. Off by default: such releases fail closed.
	AssumeCompatible bool
	// poll is the status polling interval; tests shorten it.
	poll time.Duration
}

// operatorTerraBaseUpdate rolls one verified TerraBase release across the
// deployed pair: push and admit the artifact, then one managed update per
// seat in placement order, each waiting for the canary serving proof and a
// soak before the next. A held candidate is recorded known bad and every seat
// running it is rolled back to the artifact it replaced; the command fails.
// Reruns resume from the controller's durable seat state.
func operatorTerraBaseUpdate(ctx context.Context, cfg Config, runtime *natscell.Runtime, statePath string,
	files terrabaseReleaseFiles, compatibility terrabaseCompatibilitySigner, options terrabaseUpdateOptions, output io.Writer,
) error {
	state, err := openDeployState(statePath)
	if err != nil {
		return err
	}
	var intent placement.Intent
	var initial delivery.ArtifactRecord
	for name, value := range map[string]any{deployIntentFile: &intent, deployArtifactFile: &initial} {
		exists, err := state.readJSON(name, value)
		if err != nil {
			return err
		}
		if !exists {
			return fmt.Errorf("deployment state lacks %s; deploy before updating", name)
		}
	}
	if options.SeatWait <= 0 {
		options.SeatWait = defaultUpdateSeatWait
	}
	if options.Soak < 0 {
		return errors.New("soak must not be negative")
	}
	if options.poll <= 0 {
		options.poll = updateOutcomePoll
	}
	compatibilityKey, err := readPrivateKey(compatibility.KeyFile)
	if err != nil {
		return fmt.Errorf("compatibility signer key: %w", err)
	}
	defer clear(compatibilityKey)
	release, err := loadTerraBaseRelease(files)
	if err != nil {
		return err
	}
	record, err := pushArtifact(ctx, cfg, runtime, release.Binary, delivery.ArtifactClaimRequest{
		Source: release.Source, Cell: cfg.NATS.Cell, Role: initial.Role, Environment: initial.Environment})
	if err != nil {
		return classifyControllerError(fmt.Errorf("push TerraBase artifact: %w", err))
	}
	if record.Digest != release.Digest || record.Source != release.Source {
		return errors.New("controller admitted different TerraBase artifact bytes or source")
	}
	if _, err := state.ensureJSON(filepath.Join(deployReleaseDirectory, record.Digest+".json"), record); err != nil {
		return err
	}
	if err := retainReleaseCompatibility(state, release); err != nil {
		return err
	}
	report := func(step, status, detail string) error {
		return printJSON(output, terrabaseDeployStep{Step: step, Status: status, Detail: detail})
	}
	if err := report("artifact", "admitted", record.Digest); err != nil {
		return err
	}
	rollout := &terrabaseRollout{cfg: cfg, runtime: runtime, state: state, intent: intent, initial: initial,
		compatibility: compatibility, compatibilityKey: compatibilityKey, options: options, report: report,
		soaked: map[string]bool{}}
	return rollout.run(ctx, record)
}

type terrabaseRollout struct {
	cfg              Config
	runtime          *natscell.Runtime
	state            deployState
	intent           placement.Intent
	initial          delivery.ArtifactRecord
	compatibility    terrabaseCompatibilitySigner
	compatibilityKey ed25519.PrivateKey
	options          terrabaseUpdateOptions
	report           func(step, status, detail string) error
	// soaked holds seat/operation pairs that passed their soak in this run.
	soaked map[string]bool
	// failure is the terminal outcome of a held candidate, returned once
	// every seat running it has been rolled back.
	failure error
}

func (rollout *terrabaseRollout) run(ctx context.Context, candidate delivery.ArtifactRecord) error {
	for {
		knownBad, err := rollout.state.knownBad()
		if err != nil {
			return err
		}
		status, err := rollout.status(ctx)
		if err != nil {
			return err
		}
		if len(status.Members) != 2 || status.Terminal || status.Sequence == 0 ||
			status.PayloadSHA256 != rollout.payloadDigest() {
			return errors.New("the deployed placement is not the two-member placement in this deployment state")
		}
		if seat, pending := pendingUpdate(status); pending {
			if _, err := rollout.await(ctx, seat.SeatID, seat.Update.OperationID); err != nil {
				return err
			}
			continue
		}
		if held := slices.IndexFunc(status.Members, func(member placementMemberStatus) bool {
			return member.Update != nil && member.Update.Phase == updateHeldPhase
		}); held >= 0 {
			if err := rollout.recoverHeld(ctx, status, status.Members[held], knownBad); err != nil {
				return err
			}
			continue
		}
		reverted, err := rollout.revertKnownBad(ctx, status, knownBad)
		if err != nil {
			return err
		}
		if reverted {
			continue
		}
		if rollout.failure != nil {
			return rollout.failure
		}
		if err := knownBad.Refuse(candidate.Digest); err != nil {
			return fmt.Errorf("%w; remove %s after review to retry it", err,
				filepath.Join(deployKnownBadDirectory, candidate.Digest+".json"))
		}
		next := slices.IndexFunc(status.Members, func(member placementMemberStatus) bool {
			return member.ArtifactDigest != candidate.Digest
		})
		if next < 0 {
			if !status.Serving {
				return staged.Transient(errors.New("both members run the candidate but are not all serving"))
			}
			return rollout.report("rollout", "complete", candidate.Digest)
		}
		if !status.Serving {
			return staged.Transient(errors.New("a member is not serving; the rollout waits for a serving pair before its next seat"))
		}
		if err := rollout.soakPromoted(ctx, status, candidate.Digest); err != nil {
			if !errors.Is(err, staged.ErrSoakFailed) {
				return err
			}
			if err := rollout.recordKnownBad(status, candidate.Digest, err.Error()); err != nil {
				return err
			}
			rollout.failure = err
			continue
		}
		member := status.Members[next]
		operation, err := rollout.prepare(ctx, status, member, candidate)
		if err != nil {
			return err
		}
		if _, err := rollout.await(ctx, member.SeatID, operation); err != nil {
			return err
		}
	}
}

// recoverHeld records the held candidate known bad and prepares the held
// seat's return to the artifact it replaced. A held seat whose predecessor is
// itself known bad is a rollback that failed: it is never returned to that
// predecessor, and the rollout stops for review.
func (rollout *terrabaseRollout) recoverHeld(ctx context.Context, status placementStatusReport,
	member placementMemberStatus, knownBad staged.KnownBadSet,
) error {
	update := member.Update
	if err := knownBad.Refuse(update.PreviousArtifactDigest); err != nil {
		return staged.Terminal(fmt.Errorf("rollback of seat %s to %s is held (%s); the seat stays frozen and is never returned to its predecessor: %w",
			member.SeatID, update.ArtifactDigest, update.Outcome, err))
	}
	if err := rollout.recordKnownBad(status, update.ArtifactDigest, "held: "+update.Outcome); err != nil {
		return err
	}
	if err := rollout.rollBack(ctx, status, member, update.PreviousArtifactDigest); err != nil {
		return err
	}
	rollout.failure = staged.Terminal(fmt.Errorf("candidate %s was held on seat %s (%s) and rolled back to %s",
		update.ArtifactDigest, member.SeatID, update.Outcome, update.PreviousArtifactDigest))
	return nil
}

// revertKnownBad rolls one serving seat that still runs a known-bad candidate
// back to the artifact that candidate replaced, so a failure on one seat
// never leaves the pair mixed on a candidate that failed. It reports whether
// it acted.
func (rollout *terrabaseRollout) revertKnownBad(ctx context.Context, status placementStatusReport,
	knownBad staged.KnownBadSet,
) (bool, error) {
	for _, member := range status.Members {
		if _, bad := knownBad[member.ArtifactDigest]; !bad {
			continue
		}
		if member.Update == nil || member.Update.ArtifactDigest != member.ArtifactDigest {
			return false, staged.Terminal(fmt.Errorf("seat %s runs known-bad %s without a recorded predecessor; review it",
				member.SeatID, member.ArtifactDigest))
		}
		if member.Stage != string(placement.StageServing) {
			return false, staged.Terminal(fmt.Errorf("seat %s runs known-bad %s and is not serving; it stays frozen for review",
				member.SeatID, member.ArtifactDigest))
		}
		if !status.Serving {
			return false, staged.Transient(fmt.Errorf("seat %s runs known-bad %s; its rollback waits for a serving peer",
				member.SeatID, member.ArtifactDigest))
		}
		if err := knownBad.Refuse(member.Update.PreviousArtifactDigest); err != nil {
			return false, staged.Terminal(fmt.Errorf("seat %s cannot return from known-bad %s: %w",
				member.SeatID, member.ArtifactDigest, err))
		}
		if err := rollout.rollBack(ctx, status, member, member.Update.PreviousArtifactDigest); err != nil {
			return false, err
		}
		return true, nil
	}
	return false, nil
}

// rollBack prepares the seat's return to an earlier admitted artifact and
// requires that artifact to serve again. A rollback that does not reach the
// serving proof is terminal.
func (rollout *terrabaseRollout) rollBack(ctx context.Context, status placementStatusReport,
	member placementMemberStatus, digest string,
) error {
	previous, err := rollout.releaseRecord(digest)
	if err != nil {
		return staged.Terminal(err)
	}
	operation, err := rollout.prepare(ctx, status, member, previous)
	if err != nil {
		return err
	}
	phase, err := rollout.await(ctx, member.SeatID, operation)
	if err != nil {
		return err
	}
	if phase != updateServingPhase {
		return staged.Terminal(fmt.Errorf("rollback of seat %s to %s ended %s instead of serving; the seat stays frozen for review",
			member.SeatID, digest, phase))
	}
	return rollout.report("seat "+member.SeatID, "rolled-back", digest)
}

// soakPromoted holds the next seat until every seat already promoted to the
// candidate has served it, without restarting, for the soak window.
func (rollout *terrabaseRollout) soakPromoted(ctx context.Context, status placementStatusReport, digest string) error {
	for _, member := range status.Members {
		if member.ArtifactDigest != digest || member.Update == nil || member.Update.ArtifactDigest != digest {
			continue
		}
		key := member.SeatID + "/" + member.Update.OperationID
		if rollout.soaked[key] {
			continue
		}
		if err := rollout.soak(ctx, member.SeatID, member.Update.OperationID, digest); err != nil {
			return err
		}
		rollout.soaked[key] = true
		if err := rollout.report("seat "+member.SeatID, "soaked", digest); err != nil {
			return err
		}
	}
	return nil
}

func (rollout *terrabaseRollout) soak(ctx context.Context, seatID, operation, digest string) error {
	gate := &staged.Soak{Window: rollout.options.Soak, Digest: digest, Promoted: updateServingPhase}
	for {
		status, err := rollout.status(ctx)
		if err != nil {
			return err
		}
		index := slices.IndexFunc(status.Members, func(member placementMemberStatus) bool { return member.SeatID == seatID })
		if index < 0 {
			return staged.Terminal(fmt.Errorf("seat %s disappeared from placement status", seatID))
		}
		member := status.Members[index]
		sample := soakSample(member, time.Now())
		if sample.OperationID != operation {
			sample.Phase = "replaced"
		}
		done, err := gate.Observe(sample)
		if err != nil {
			return fmt.Errorf("seat %s: %w", seatID, err)
		}
		if done {
			return nil
		}
		timer := time.NewTimer(max(time.Millisecond, min(rollout.options.poll, gate.Remaining(time.Now()))))
		select {
		case <-ctx.Done():
			timer.Stop()
			return ctx.Err()
		case <-timer.C:
		}
	}
}

// soakSample reads one soak observation from placement status. A promoted
// canary keeps Stage serving even after it loses its serving proof (the
// controller only records a hold), so serving also requires the host's
// current report to carry a serving proof and no error. Without a current
// host session or report the sample is a gap: unknown, not failed.
func soakSample(member placementMemberStatus, now time.Time) staged.SoakSample {
	sample := staged.SoakSample{At: now, ArtifactDigest: member.ArtifactDigest,
		Serving: member.Stage == string(placement.StageServing)}
	if member.Update != nil {
		sample.OperationID, sample.Phase = member.Update.OperationID, member.Update.Phase
	}
	host := member.Host
	if host == nil || !host.SessionCurrent || host.ReportState == "" {
		sample.Gap = true
		return sample
	}
	sample.ProcessPID = host.ProcessPID
	sample.Serving = sample.Serving && host.ServingProof && host.ReportError == ""
	return sample
}

func (rollout *terrabaseRollout) prepare(ctx context.Context, status placementStatusReport,
	member placementMemberStatus, candidate delivery.ArtifactRecord,
) (string, error) {
	if member.UpdatePins == nil {
		return "", fmt.Errorf("seat %s has no controller update pins", member.SeatID)
	}
	pins := make([]placement.ManagedUpdateSeat, 0, len(status.Members))
	for _, current := range status.Members {
		if current.UpdatePins == nil {
			return "", fmt.Errorf("seat %s has no controller update pins", current.SeatID)
		}
		pins = append(pins, *current.UpdatePins)
	}
	slices.SortFunc(pins, func(left, right placement.ManagedUpdateSeat) int { return strings.Compare(left.SeatID, right.SeatID) })
	verdict, err := rollout.compatibilityVerdict(member.UpdatePins.ArtifactDigest, candidate.Digest)
	if err != nil {
		return "", err
	}
	epoch, err := authoritySnapshot(ctx, rollout.runtime, rollout.cfg.NATS.Cell)
	if err != nil {
		return "", staged.Transient(err)
	}
	desired := member.UpdatePins.DesiredGeneration + 1
	sum := sha256.Sum256([]byte(candidate.Digest + "\x00" + member.SeatID + "\x00" + strconv.FormatUint(desired, 10)))
	update := placement.ManagedUpdateIntent{SchemaVersion: placement.ManagedUpdateSchemaVersion,
		Cell: rollout.cfg.NATS.Cell, DatabaseID: rollout.intent.DatabaseID, PartitionID: rollout.intent.PartitionID,
		PlacementGeneration: rollout.intent.Generation, PlacementPayloadDigest: rollout.payloadDigest(),
		PlacementSequence: status.Sequence, AuthorityEpoch: epoch, OperationID: "u-" + hex.EncodeToString(sum[:15]),
		Role: rollout.initial.Role, Environment: rollout.initial.Environment,
		OldArtifactDigest: member.UpdatePins.ArtifactDigest, CandidateArtifactDigest: candidate.Digest,
		CandidateManifestDigest: candidate.ManifestDigest, CandidateSourceDigest: candidate.Source.TreeDigest,
		CanarySeatID: member.SeatID, CanaryDesiredGeneration: desired, Seats: pins,
		DurabilityProfile: rollout.durabilityProfile(pins)}
	profileDigest, err := update.DurabilityProfile.Digest()
	if err != nil {
		return "", err
	}
	evidence, err := protocol.EncodeJSON(placement.ManagedCompatibilityEvidence{
		SchemaVersion: placement.ManagedCompatibilitySchemaVersion, Cell: update.Cell, OperationID: update.OperationID,
		OldArtifactDigest: update.OldArtifactDigest, CandidateArtifactDigest: update.CandidateArtifactDigest,
		CandidateManifestDigest: update.CandidateManifestDigest, DurabilityProfileSHA256: profileDigest,
		MixedVersionReplicationSupported: verdict.MixedVersionReplication,
		ClientDataCompatibilitySupported: verdict.ClientData,
		PersistentFormatReadSupported:    verdict.PersistentFormatRead,
		PersistentFormatWriteSupported:   verdict.PersistentFormatWrite})
	if err != nil {
		return "", err
	}
	now := time.Now().UTC()
	update.CompatibilityEvidence, err = protocol.SignEnvelope(evidence, protocol.EnvelopeScope{
		Region: update.Cell, Kind: placement.ManagedCompatibilityEnvelopeKind, Actor: rollout.compatibility.Actor,
		OperationID: update.OperationID, Generation: update.CanaryDesiredGeneration, Epoch: epoch,
	}, now, now.Add(managedCompatibilitySig), rollout.compatibilityKey)
	if err != nil {
		return "", err
	}
	response, err := requestManagedUpdatePrepare(ctx, rollout.cfg, rollout.runtime, update)
	if err != nil {
		return "", classifyControllerError(fmt.Errorf("prepare update of seat %s: %w", member.SeatID, err))
	}
	return update.OperationID, rollout.report("seat "+member.SeatID, "prepared",
		fmt.Sprintf("%s -> %s operation %s sequence %d", update.OldArtifactDigest, candidate.Digest,
			update.OperationID, response.Sequence))
}

// compatibilityVerdict derives the evidence the compatibility signer
// certifies from both releases' retained declarations. A release without a
// declaration fails closed unless the operator explicitly assumes
// compatibility; incompatible declarations are refused either way.
func (rollout *terrabaseRollout) compatibilityVerdict(old, candidate string) (staged.CompatibilityVerdict, error) {
	oldDeclaration, oldKnown, err := releaseCompatibility(rollout.state, old)
	if err != nil {
		return staged.CompatibilityVerdict{}, err
	}
	candidateDeclaration, candidateKnown, err := releaseCompatibility(rollout.state, candidate)
	if err != nil {
		return staged.CompatibilityVerdict{}, err
	}
	if oldKnown && candidateKnown {
		verdict, err := staged.RequireCompatible(oldDeclaration, candidateDeclaration)
		if err != nil {
			return verdict, fmt.Errorf("%s -> %s: %w", old, candidate, err)
		}
		return verdict, nil
	}
	// Name every release that lacks a declaration, so the operator publishes
	// all of them at once.
	var missing []string
	if !oldKnown {
		missing = append(missing, old)
	}
	if !candidateKnown {
		missing = append(missing, candidate)
	}
	if !rollout.options.AssumeCompatible {
		return staged.CompatibilityVerdict{}, staged.Terminal(fmt.Errorf(
			"%w: %s; publish compatibility in each qualification.json or pass --assume-compatibility to certify it unverified",
			staged.ErrNoCompatibilityData, strings.Join(missing, ", ")))
	}
	if err := rollout.report("compatibility", "assumed", old+" -> "+candidate); err != nil {
		return staged.CompatibilityVerdict{}, err
	}
	return staged.CompatibilityVerdict{MixedVersionReplication: true, ClientData: true,
		PersistentFormatRead: true, PersistentFormatWrite: true}, nil
}

// await polls the controller until the seat's operation reaches a terminal
// outcome and returns that phase. The controller itself holds a candidate
// that misses its serving proof deadline, so a held outcome always arrives;
// a wait that ends first is transient and resumes on the next run.
func (rollout *terrabaseRollout) await(ctx context.Context, seatID, operation string) (string, error) {
	deadline := time.Now().Add(rollout.options.SeatWait)
	for {
		status, err := rollout.status(ctx)
		if err != nil {
			return "", err
		}
		index := slices.IndexFunc(status.Members, func(member placementMemberStatus) bool { return member.SeatID == seatID })
		if index < 0 {
			return "", staged.Terminal(fmt.Errorf("seat %s disappeared from placement status", seatID))
		}
		member := status.Members[index]
		if member.Update != nil && member.Update.OperationID == operation && member.Update.Phase != updatePreparedPhase {
			return member.Update.Phase, rollout.report("seat "+seatID, member.Update.Phase, member.Update.ArtifactDigest)
		}
		if !time.Now().Before(deadline) {
			return "", staged.Transient(fmt.Errorf("seat %s operation %s did not reach an outcome within %s",
				seatID, operation, rollout.options.SeatWait))
		}
		timer := time.NewTimer(min(rollout.options.poll, time.Until(deadline)))
		select {
		case <-ctx.Done():
			timer.Stop()
			return "", ctx.Err()
		case <-timer.C:
		}
	}
}

// status reads signed placement status. Transport, timeout and authority
// lease failures are transient; authorization, key and reply verification
// failures are terminal, because no retry can fix them.
func (rollout *terrabaseRollout) status(ctx context.Context) (placementStatusReport, error) {
	status, err := requestPlacementStatus(ctx, rollout.cfg, rollout.runtime, rollout.intent.DatabaseID, rollout.intent.PartitionID)
	if err != nil {
		return placementStatusReport{}, classifyStatusError(err)
	}
	return status, nil
}

// recordKnownBad durably marks digest known bad before any rollback acts on
// it. The first record wins; later failures of the same digest keep it.
func (rollout *terrabaseRollout) recordKnownBad(status placementStatusReport, digest, reason string) error {
	record := staged.KnownBad{Digest: digest, Reason: reason, RecordedAt: time.Now().UTC()}
	for _, member := range status.Members {
		if member.Update != nil && member.Update.ArtifactDigest == digest {
			record.SeatID, record.OperationID = member.SeatID, member.Update.OperationID
			break
		}
	}
	if err := record.Validate(); err != nil {
		return err
	}
	if _, err := rollout.state.readOrCreateJSON(filepath.Join(deployKnownBadDirectory, digest+".json"), record); err != nil {
		return err
	}
	return rollout.report("known-bad", "recorded", digest)
}

// knownBad loads every retained known-bad record of the deployment.
func (state deployState) knownBad() (staged.KnownBadSet, error) {
	entries, err := os.ReadDir(filepath.Join(state.directory, deployKnownBadDirectory))
	if err != nil {
		return nil, err
	}
	set := staged.KnownBadSet{}
	for _, entry := range entries {
		match := knownBadFilePattern.FindStringSubmatch(entry.Name())
		if match == nil {
			continue
		}
		var record staged.KnownBad
		if _, err := state.readJSON(filepath.Join(deployKnownBadDirectory, entry.Name()), &record); err != nil {
			return nil, err
		}
		if err := record.Validate(); err != nil || record.Digest != match[1] {
			return nil, fmt.Errorf("retained known-bad record %s is invalid", entry.Name())
		}
		set[record.Digest] = record
	}
	return set, nil
}

// classifyStatusError keeps a placement status read retryable unless
// requestPlacementStatus marked it rejected.
func classifyStatusError(err error) error {
	if _, rejected := errors.AsType[statusRejected](err); rejected {
		return staged.Terminal(err)
	}
	return staged.Transient(err)
}

// classifyConnectError keeps an unreachable broker retryable while
// configuration, credential and TLS material errors, which no retry can fix,
// stop the run at once.
func classifyConnectError(err error) error {
	if errors.Is(err, natscell.ErrUnavailable) {
		return staged.Transient(err)
	}
	return classifyControllerError(err)
}

// classifyControllerError marks controller transport, leadership and
// fencing failures transient; anything else, such as an admission
// rejection, stays terminal.
func classifyControllerError(err error) error {
	if errors.Is(err, nats.ErrTimeout) || errors.Is(err, nats.ErrNoResponders) ||
		errors.Is(err, nats.ErrConnectionClosed) || errors.Is(err, nats.ErrDisconnected) ||
		errors.Is(err, context.DeadlineExceeded) || errors.Is(err, authority.ErrFenced) ||
		errors.Is(err, authority.ErrNotLeader) {
		return staged.Transient(err)
	}
	return staged.Terminal(err)
}

func (rollout *terrabaseRollout) payloadDigest() string {
	wire, err := protocol.EncodeJSON(rollout.intent)
	if err != nil {
		return ""
	}
	sum := sha256.Sum256(wire)
	return hex.EncodeToString(sum[:])
}

func (rollout *terrabaseRollout) durabilityProfile(pins []placement.ManagedUpdateSeat) placement.ManagedUpdateDurabilityProfile {
	manifests := rollout.intent.RuntimeManifests
	profile := placement.ManagedUpdateDurabilityProfile{SchemaVersion: placement.ManagedUpdateSchemaVersion,
		Region: manifests[0].Region, SQLSchemaBundleSHA256: manifests[0].SQLSchemaBundleSHA256,
		LiveS3ConfigSHA256: manifests[0].LiveS3ConfigSHA256, LiveS3TargetSHA256: manifests[0].LiveS3TargetSHA256,
		LiveS3Credential: manifests[0].LiveS3Credential}
	for _, pin := range pins {
		for _, manifest := range manifests {
			if manifest.SeatID == pin.SeatID {
				profile.Volumes = append(profile.Volumes, placement.ManagedUpdateVolumeProfile{SeatID: pin.SeatID,
					VolumeID: pin.VolumeID, FileSystemUUID: manifest.FileSystemUUID, FileSystemType: manifest.FileSystemType})
			}
		}
	}
	return profile
}

// releaseRecord finds the admitted artifact record of an earlier release in
// the deployment state: the initial artifact or a retained update.
func (rollout *terrabaseRollout) releaseRecord(digest string) (delivery.ArtifactRecord, error) {
	if rollout.initial.Digest == digest {
		return rollout.initial, nil
	}
	var record delivery.ArtifactRecord
	exists, err := rollout.state.readJSON(filepath.Join(deployReleaseDirectory, digest+".json"), &record)
	if err != nil {
		return delivery.ArtifactRecord{}, err
	}
	if !exists || record.Digest != digest {
		return delivery.ArtifactRecord{}, fmt.Errorf("deployment state has no admitted release %s to roll back to", digest)
	}
	return record, nil
}

func pendingUpdate(status placementStatusReport) (placementMemberStatus, bool) {
	for _, member := range status.Members {
		if member.Update != nil && member.Update.Phase == updatePreparedPhase {
			return member, true
		}
	}
	return placementMemberStatus{}, false
}
