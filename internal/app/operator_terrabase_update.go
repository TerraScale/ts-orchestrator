package app

import (
	"context"
	"crypto/ed25519"
	"crypto/sha256"
	"encoding/hex"
	"errors"
	"fmt"
	"io"
	"path/filepath"
	"slices"
	"strconv"
	"strings"
	"time"

	"git.terrascale.tech/TerraScale/ts-orchestrator/internal/delivery"
	"git.terrascale.tech/TerraScale/ts-orchestrator/internal/natscell"
	"git.terrascale.tech/TerraScale/ts-orchestrator/internal/placement"
	"git.terrascale.tech/TerraScale/ts-orchestrator/internal/protocol"
)

const (
	deployReleaseDirectory  = "releases"
	updateOutcomePoll       = 10 * time.Second
	defaultUpdateSeatWait   = 20 * time.Minute
	updateHeldPhase         = string(placement.ManagedUpdateSeatHeld)
	updatePreparedPhase     = string(placement.ManagedUpdateSeatPrepared)
	managedCompatibilitySig = time.Minute
)

// terrabaseCompatibilitySigner is the independent actor that certifies a
// candidate's persistent-format and mixed-version compatibility.
type terrabaseCompatibilitySigner struct {
	Actor   string
	KeyFile string
}

// operatorTerraBaseUpdate rolls one verified TerraBase release across the
// deployed pair: push and admit the artifact, then one managed update per
// seat in placement order, each waiting for the canary serving proof before
// the next. A held candidate is rolled back to the artifact it replaced and
// the command fails; its peer keeps serving throughout. Reruns resume from
// the controller's durable seat state.
func operatorTerraBaseUpdate(ctx context.Context, cfg Config, runtime *natscell.Runtime, statePath string,
	files terrabaseReleaseFiles, compatibility terrabaseCompatibilitySigner, seatWait time.Duration, output io.Writer,
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
	if seatWait <= 0 {
		seatWait = defaultUpdateSeatWait
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
		return fmt.Errorf("push TerraBase artifact: %w", err)
	}
	if record.Digest != release.Digest || record.Source != release.Source {
		return errors.New("controller admitted different TerraBase artifact bytes or source")
	}
	if _, err := state.ensureJSON(filepath.Join(deployReleaseDirectory, record.Digest+".json"), record); err != nil {
		return err
	}
	report := func(step, status, detail string) error {
		return printJSON(output, terrabaseDeployStep{Step: step, Status: status, Detail: detail})
	}
	if err := report("artifact", "admitted", record.Digest); err != nil {
		return err
	}
	rollout := terrabaseRollout{cfg: cfg, runtime: runtime, state: state, intent: intent, initial: initial,
		compatibility: compatibility, compatibilityKey: compatibilityKey, seatWait: seatWait, report: report}
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
	seatWait         time.Duration
	report           func(step, status, detail string) error
}

func (rollout terrabaseRollout) run(ctx context.Context, candidate delivery.ArtifactRecord) error {
	for {
		status, err := requestPlacementStatus(ctx, rollout.cfg, rollout.runtime, rollout.intent.DatabaseID, rollout.intent.PartitionID)
		if err != nil {
			return err
		}
		if len(status.Members) != 2 || status.Terminal || status.Sequence == 0 ||
			status.PayloadSHA256 != rollout.payloadDigest() {
			return errors.New("the deployed placement is not the two-member placement in this deployment state")
		}
		if seat, pending := pendingUpdate(status); pending {
			if err := rollout.await(ctx, seat.SeatID, seat.Update.OperationID); err != nil {
				return err
			}
			continue
		}
		if held := slices.IndexFunc(status.Members, func(member placementMemberStatus) bool {
			return member.Update != nil && member.Update.Phase == updateHeldPhase
		}); held >= 0 {
			member := status.Members[held]
			if err := rollout.rollBack(ctx, status, member); err != nil {
				return err
			}
			return fmt.Errorf("candidate %s was held on seat %s (%s) and rolled back to %s",
				member.Update.ArtifactDigest, member.SeatID, member.Update.Outcome, member.Update.PreviousArtifactDigest)
		}
		next := slices.IndexFunc(status.Members, func(member placementMemberStatus) bool {
			return member.ArtifactDigest != candidate.Digest
		})
		if next < 0 {
			if !status.Serving {
				return errors.New("both members run the candidate but are not all serving")
			}
			return rollout.report("rollout", "complete", candidate.Digest)
		}
		if !status.Serving {
			return errors.New("a member is not serving; the rollout waits for a serving pair before its next seat")
		}
		member := status.Members[next]
		operation, err := rollout.prepare(ctx, status, member, candidate)
		if err != nil {
			return err
		}
		if err := rollout.await(ctx, member.SeatID, operation); err != nil {
			return err
		}
	}
}

// rollBack prepares the held seat's return to the artifact its candidate
// replaced, and waits for that artifact to serve again.
func (rollout terrabaseRollout) rollBack(ctx context.Context, status placementStatusReport, member placementMemberStatus) error {
	previous, err := rollout.releaseRecord(member.Update.PreviousArtifactDigest)
	if err != nil {
		return err
	}
	operation, err := rollout.prepare(ctx, status, member, previous)
	if err != nil {
		return err
	}
	return rollout.await(ctx, member.SeatID, operation)
}

func (rollout terrabaseRollout) prepare(ctx context.Context, status placementStatusReport,
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
	epoch, err := authoritySnapshot(ctx, rollout.runtime, rollout.cfg.NATS.Cell)
	if err != nil {
		return "", err
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
		MixedVersionReplicationSupported: true, ClientDataCompatibilitySupported: true,
		PersistentFormatReadSupported: true, PersistentFormatWriteSupported: true})
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
		return "", fmt.Errorf("prepare update of seat %s: %w", member.SeatID, err)
	}
	return update.OperationID, rollout.report("seat "+member.SeatID, "prepared",
		fmt.Sprintf("%s -> %s operation %s sequence %d", update.OldArtifactDigest, candidate.Digest,
			update.OperationID, response.Sequence))
}

// await polls the controller until the seat's operation reaches a terminal
// outcome. The controller itself holds a candidate that misses its serving
// proof deadline, so a held outcome always arrives.
func (rollout terrabaseRollout) await(ctx context.Context, seatID, operation string) error {
	deadline := time.Now().Add(rollout.seatWait)
	for {
		status, err := requestPlacementStatus(ctx, rollout.cfg, rollout.runtime, rollout.intent.DatabaseID, rollout.intent.PartitionID)
		if err != nil {
			return err
		}
		index := slices.IndexFunc(status.Members, func(member placementMemberStatus) bool { return member.SeatID == seatID })
		if index < 0 {
			return fmt.Errorf("seat %s disappeared from placement status", seatID)
		}
		member := status.Members[index]
		if member.Update != nil && member.Update.OperationID == operation && member.Update.Phase != updatePreparedPhase {
			return rollout.report("seat "+seatID, member.Update.Phase, member.Update.ArtifactDigest)
		}
		if !time.Now().Before(deadline) {
			return fmt.Errorf("seat %s operation %s did not reach an outcome within %s", seatID, operation, rollout.seatWait)
		}
		timer := time.NewTimer(min(updateOutcomePoll, time.Until(deadline)))
		select {
		case <-ctx.Done():
			timer.Stop()
			return ctx.Err()
		case <-timer.C:
		}
	}
}

func (rollout terrabaseRollout) payloadDigest() string {
	wire, err := protocol.EncodeJSON(rollout.intent)
	if err != nil {
		return ""
	}
	sum := sha256.Sum256(wire)
	return hex.EncodeToString(sum[:])
}

func (rollout terrabaseRollout) durabilityProfile(pins []placement.ManagedUpdateSeat) placement.ManagedUpdateDurabilityProfile {
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
func (rollout terrabaseRollout) releaseRecord(digest string) (delivery.ArtifactRecord, error) {
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
