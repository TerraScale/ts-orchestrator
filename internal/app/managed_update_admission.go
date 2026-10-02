package app

import (
	"bytes"
	"context"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json/v2"
	"errors"
	"fmt"
	"io"
	"slices"
	"time"

	"git.terrascale.tech/TerraScale/ts-orchestrator/internal/authority"
	"git.terrascale.tech/TerraScale/ts-orchestrator/internal/decisionlog"
	"git.terrascale.tech/TerraScale/ts-orchestrator/internal/delivery"
	"git.terrascale.tech/TerraScale/ts-orchestrator/internal/natscell"
	"git.terrascale.tech/TerraScale/ts-orchestrator/internal/placement"
	"git.terrascale.tech/TerraScale/ts-orchestrator/internal/protocol"
	"github.com/nats-io/nats.go"
)

const managedUpdateRequestMaxBytes = protocol.MaxPayloadBytes + 4096

func managedUpdatePrepareSubject(cell string) string {
	return protocol.ManagedUpdatePrepareSubject(cell)
}

type managedUpdatePrepareResponse struct {
	DatabaseID  string `json:"databaseId"`
	PartitionID string `json:"partitionId"`
	OperationID string `json:"operationId"`
	Phase       string `json:"phase"`
	Sequence    uint64 `json:"sequence"`
	Error       string `json:"error,omitempty"`
}

func operatorManagedUpdatePrepare(ctx context.Context, cfg Config, runtime *natscell.Runtime,
	path string, output io.Writer,
) error {
	data, err := readBoundedConfigFile(path)
	if err != nil || len(data) == 0 || len(data) > protocol.MaxPayloadBytes {
		return errors.New("managed update intent file is invalid or oversized")
	}
	var intent placement.ManagedUpdateIntent
	if err := protocol.DecodeStrict(data, &intent, protocol.MaxPayloadBytes); err != nil {
		return fmt.Errorf("parse managed update intent: %w", err)
	}
	canonicalIntent, err := protocol.EncodeJSON(intent)
	if err != nil {
		return err
	}
	if !bytes.Equal(data, canonicalIntent) {
		return errors.New("managed update intent is not canonical JSON")
	}
	response, err := requestManagedUpdatePrepare(ctx, cfg, runtime, intent)
	if err != nil {
		return err
	}
	return printJSON(output, response)
}

// requestManagedUpdatePrepare signs one managed update intent with the
// operator key and requests its Prepare admission from the regional leader.
func requestManagedUpdatePrepare(ctx context.Context, cfg Config, runtime *natscell.Runtime,
	intent placement.ManagedUpdateIntent,
) (managedUpdatePrepareResponse, error) {
	if err := intent.Validate(); err != nil {
		return managedUpdatePrepareResponse{}, err
	}
	if intent.Cell != cfg.NATS.Cell {
		return managedUpdatePrepareResponse{}, errors.New("managed update intent does not select this regional cell")
	}
	policy, err := buildSignerPolicy(cfg)
	if err != nil {
		return managedUpdatePrepareResponse{}, err
	}
	grant, exists := policy.grants[cfg.Operator.Actor]
	if !exists || !grant.CanPlaceTerraBase || !grant.CanUpdateTerraBaseRuntime ||
		!slices.Contains(grant.Roles, intent.Role) || !slices.Contains(grant.Environments, intent.Environment) {
		return managedUpdatePrepareResponse{}, errors.New("operator lacks current TerraBase managed runtime update scope")
	}
	codec, err := policy.withOperator(cfg.Operator)
	if err != nil {
		return managedUpdatePrepareResponse{}, err
	}
	epoch, err := authoritySnapshot(ctx, runtime, cfg.NATS.Cell)
	if err != nil {
		return managedUpdatePrepareResponse{}, err
	}
	if intent.AuthorityEpoch != epoch {
		return managedUpdatePrepareResponse{}, authority.ErrFenced
	}
	canonicalIntent, err := protocol.EncodeJSON(intent)
	if err != nil {
		return managedUpdatePrepareResponse{}, err
	}
	now := time.Now().UTC()
	envelope, err := protocol.SignEnvelope(canonicalIntent, protocol.EnvelopeScope{
		Region: cfg.NATS.Cell, Kind: placement.ManagedUpdateEnvelopeKind, Actor: cfg.Operator.Actor,
		OperationID: intent.OperationID, Generation: intent.CanaryDesiredGeneration, Epoch: epoch,
	}, now, now.Add(time.Minute), codec.PrivateKey)
	if err != nil {
		return managedUpdatePrepareResponse{}, err
	}
	wire, err := protocol.EncodeJSON(envelope)
	if err != nil {
		return managedUpdatePrepareResponse{}, err
	}
	for attempt := range 3 {
		requestCtx, cancel := context.WithTimeout(ctx, 10*time.Second)
		message, requestErr := runtime.Conn().RequestWithContext(requestCtx, managedUpdatePrepareSubject(cfg.NATS.Cell), wire)
		cancel()
		if requestErr == nil {
			var response managedUpdatePrepareResponse
			if err := protocol.DecodeStrict(message.Data, &response, 16<<10); err != nil {
				return managedUpdatePrepareResponse{}, fmt.Errorf("decode managed update Prepare reply: %w", err)
			}
			if response.Error != "" {
				return managedUpdatePrepareResponse{}, errors.New(response.Error)
			}
			if response.DatabaseID != intent.DatabaseID || response.PartitionID != intent.PartitionID ||
				response.OperationID != intent.OperationID || response.Phase != string(authority.ManagedUpdatePrepared) || response.Sequence == 0 {
				return managedUpdatePrepareResponse{}, errors.New("controller returned a different managed update Prepare receipt")
			}
			return response, nil
		}
		if (!errors.Is(requestErr, nats.ErrTimeout) && !errors.Is(requestErr, context.DeadlineExceeded)) || attempt == 2 {
			return managedUpdatePrepareResponse{}, fmt.Errorf("request managed update Prepare: %w", requestErr)
		}
	}
	return managedUpdatePrepareResponse{}, errors.New("managed update Prepare request exhausted")
}

func serveManagedUpdateAdmission(ctx context.Context, conn *nats.Conn, cell string, policy signerPolicy,
	control *authority.Runtime, controller *placement.Controller, artifacts *delivery.Service,
) (*nats.Subscription, error) {
	if control == nil || controller == nil || artifacts == nil {
		return nil, errors.New("managed update admission requires authority, placement controller, and artifact service")
	}
	return conn.Subscribe(managedUpdatePrepareSubject(cell), func(message *nats.Msg) {
		if message.Reply == "" || len(message.Data) == 0 || len(message.Data) > managedUpdateRequestMaxBytes ||
			!control.Current().CanMutate() {
			return
		}
		requestCtx, cancel := context.WithTimeout(ctx, 30*time.Second)
		defer cancel()
		response, err := verifyAndPrepareManagedUpdate(requestCtx, message.Data, cell, policy, control,
			controller, artifacts)
		if errors.Is(err, authority.ErrFenced) || errors.Is(err, authority.ErrNotLeader) || !control.Current().CanMutate() {
			return
		}
		if err != nil {
			response = managedUpdatePrepareResponse{Error: err.Error()}
		}
		wire, err := json.Marshal(response)
		if err == nil {
			_ = message.Respond(wire)
		}
	})
}

func verifyAndPrepareManagedUpdate(ctx context.Context, wire []byte, cell string, policy signerPolicy,
	control *authority.Runtime, controller *placement.Controller, artifacts *delivery.Service,
) (managedUpdatePrepareResponse, error) {
	var envelope protocol.Envelope
	if err := protocol.DecodeStrict(wire, &envelope, managedUpdateRequestMaxBytes); err != nil {
		return managedUpdatePrepareResponse{}, err
	}
	var intent placement.ManagedUpdateIntent
	if err := protocol.DecodeStrict(envelope.Payload, &intent, protocol.MaxPayloadBytes); err != nil {
		return managedUpdatePrepareResponse{}, err
	}
	if err := intent.Validate(); err != nil {
		return managedUpdatePrepareResponse{}, err
	}
	if err := validateManagedUpdateEnvelopeScope(intent, envelope, cell); err != nil {
		return managedUpdatePrepareResponse{}, err
	}
	if intent.Role != "terrabase" {
		return managedUpdatePrepareResponse{}, errors.New("managed update scope differs from the regional controller")
	}
	grant, exists := policy.grants[envelope.Actor]
	if !exists || !grant.CanPlaceTerraBase || !grant.CanUpdateTerraBaseRuntime ||
		!slices.Contains(grant.Roles, intent.Role) || !slices.Contains(grant.Environments, intent.Environment) {
		return managedUpdatePrepareResponse{}, errors.New("managed update actor is unauthorized for this role or environment")
	}
	trusted, exists := policy.codec.Trusted[envelope.KeyID]
	if !exists || trusted.Actor != envelope.Actor {
		return managedUpdatePrepareResponse{}, errors.New("managed update signing key is untrusted")
	}
	if err := protocol.VerifyEnvelope(envelope, protocol.EnvelopeScope{
		Region: cell, Kind: placement.ManagedUpdateEnvelopeKind, Actor: trusted.Actor,
		OperationID: intent.OperationID, Generation: intent.CanaryDesiredGeneration, Epoch: intent.AuthorityEpoch,
	}, trusted.PublicKey, time.Now().UTC(), protocol.VerifyPolicy{MaxLifetime: 5 * time.Minute, ClockSkew: 30 * time.Second}); err != nil {
		return managedUpdatePrepareResponse{}, err
	}
	snapshot := control.Current()
	if intent.AuthorityEpoch == 0 || snapshot.Epoch != intent.AuthorityEpoch || !snapshot.CanMutate() {
		return managedUpdatePrepareResponse{}, authority.ErrFenced
	}
	canonical, err := protocol.EncodeJSON(intent)
	if err != nil || !bytes.Equal(canonical, envelope.Payload) {
		return managedUpdatePrepareResponse{}, errors.New("signed managed update payload is not canonical")
	}
	if err := verifyManagedCompatibility(intent, envelope, policy); err != nil {
		return managedUpdatePrepareResponse{}, err
	}
	artifact, err := artifacts.ResolveAdmittedArtifact(ctx, intent.CandidateArtifactDigest, intent.Role, intent.Environment)
	if err != nil {
		return managedUpdatePrepareResponse{}, fmt.Errorf("resolve admitted managed update artifact: %w", err)
	}
	if artifact.Digest != intent.CandidateArtifactDigest || artifact.ManifestDigest != intent.CandidateManifestDigest ||
		artifact.Source.TreeDigest != intent.CandidateSourceDigest {
		return managedUpdatePrepareResponse{}, errors.New("candidate artifact bytes, manifest, or source tree differs from signed update")
	}
	if len(grant.Repositories) > 0 && !slices.Contains(grant.Repositories, artifact.Source.Repository) {
		return managedUpdatePrepareResponse{}, errors.New("managed update actor is not authorized for the candidate source repository")
	}
	profileDigest, err := intent.DurabilityProfile.Digest()
	if err != nil {
		return managedUpdatePrepareResponse{}, err
	}
	requestDigest := sha256.Sum256(wire)
	record := authority.ManagedUpdateRecord{
		SchemaVersion: 1, Cell: cell, DatabaseID: intent.DatabaseID, PartitionID: intent.PartitionID,
		OperationID: intent.OperationID, Phase: authority.ManagedUpdatePrepared,
		SignedRequest: bytes.Clone(wire), SignedRequestSHA256: hex.EncodeToString(requestDigest[:]),
		PlacementGeneration: intent.PlacementGeneration, PlacementPayloadDigest: intent.PlacementPayloadDigest,
		PlacementSequence: intent.PlacementSequence, CanarySeatID: intent.CanarySeatID,
		CanaryDesiredGeneration: intent.CanaryDesiredGeneration, OldArtifactDigest: intent.OldArtifactDigest,
		CandidateArtifactDigest: intent.CandidateArtifactDigest, CandidateManifestDigest: intent.CandidateManifestDigest,
		CandidateSourceDigest: intent.CandidateSourceDigest, DurabilityProfileSHA256: profileDigest,
	}
	sequence, err := controller.PrepareManagedUpdate(ctx, record)
	if err != nil {
		return managedUpdatePrepareResponse{}, err
	}
	recordManagedUpdateAdmission(ctx, cell, envelope.Actor, intent, sequence)
	return managedUpdatePrepareResponse{DatabaseID: intent.DatabaseID, PartitionID: intent.PartitionID,
		OperationID: intent.OperationID, Phase: string(authority.ManagedUpdatePrepared), Sequence: sequence}, nil
}

func validateManagedUpdateEnvelopeScope(intent placement.ManagedUpdateIntent, envelope protocol.Envelope, cell string) error {
	canonicalCell, err := protocol.CanonicalRegion(cell)
	if err != nil || intent.Cell != cell || envelope.Region != canonicalCell {
		return errors.New("managed update scope differs from the regional controller")
	}
	return nil
}

func verifyManagedCompatibility(intent placement.ManagedUpdateIntent, update protocol.Envelope,
	policy signerPolicy,
) error {
	envelope := intent.CompatibilityEvidence
	grant, exists := policy.grants[envelope.Actor]
	if !exists || !grant.CanCertifyTerraBaseCompatibility || envelope.Actor == update.Actor ||
		!slices.Contains(grant.Roles, intent.Role) || !slices.Contains(grant.Environments, intent.Environment) {
		return errors.New("managed compatibility evidence lacks an independent authorized signer")
	}
	trusted, exists := policy.codec.Trusted[envelope.KeyID]
	if !exists || trusted.Actor != envelope.Actor || envelope.KeyID == update.KeyID {
		return errors.New("managed compatibility evidence key is not independent and trusted")
	}
	if err := protocol.VerifyEnvelope(envelope, protocol.EnvelopeScope{
		Region: envelope.Region, Kind: placement.ManagedCompatibilityEnvelopeKind, Actor: trusted.Actor,
		OperationID: intent.OperationID, Generation: intent.CanaryDesiredGeneration, Epoch: intent.AuthorityEpoch,
	}, trusted.PublicKey, time.Now().UTC(), protocol.VerifyPolicy{MaxLifetime: 5 * time.Minute, ClockSkew: 30 * time.Second}); err != nil {
		return fmt.Errorf("verify independent managed compatibility evidence: %w", err)
	}
	return nil
}

// recordManagedUpdateAdmission journals the admitted update as the root of
// its decision chain; the placement reconciler's canary phases link to it.
func recordManagedUpdateAdmission(ctx context.Context, cell, actor string, intent placement.ManagedUpdateIntent,
	sequence uint64,
) {
	id := decisionlog.Record(ctx, decisionlog.Decision{
		Region: cell,
		Actor:  decisionlog.Actor{Slice: "placement"},
		Kind:   decisionlog.KindReleaseAdmitted,
		Subject: decisionlog.Subject{Kind: "operation", ID: intent.OperationID,
			Name: fmt.Sprintf("managed update of %s/%s", intent.DatabaseID, intent.PartitionID)},
		Summary: fmt.Sprintf("Managed TerraBase update of %s/%s admitted for canary seat %s", intent.DatabaseID,
			intent.PartitionID, intent.CanarySeatID),
		Reason: "The signed request verified against a trusted key, the actor's grant, the current authority " +
			"epoch and the admitted candidate artifact.",
		Rule:   "managed update admission",
		Status: decisionlog.StatusInProgress,
		Epoch:  intent.AuthorityEpoch,
		Signals: []decisionlog.Signal{
			{Name: "placement_generation", Value: float64(intent.PlacementGeneration)},
			{Name: "canary_desired_generation", Value: float64(intent.CanaryDesiredGeneration)},
			{Name: "authority_sequence", Value: float64(sequence)},
		},
		Attrs: map[string]string{"signed_by": actor, "candidate_artifact_digest": intent.CandidateArtifactDigest,
			"old_artifact_digest": intent.OldArtifactDigest, "canary_seat": intent.CanarySeatID},
	})
	decisionlog.Correlate(placement.ManagedUpdateCorrelation(intent.OperationID), id)
}
