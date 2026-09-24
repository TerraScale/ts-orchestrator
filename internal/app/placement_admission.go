package app

import (
	"bytes"
	"context"
	"crypto/sha256"
	"encoding/base32"
	"encoding/json/v2"
	"errors"
	"fmt"
	"io"
	"slices"
	"strings"
	"time"

	"git.terrascale.tech/TerraScale/ts-orchestrator/internal/authority"
	"git.terrascale.tech/TerraScale/ts-orchestrator/internal/natscell"
	"git.terrascale.tech/TerraScale/ts-orchestrator/internal/oci"
	"git.terrascale.tech/TerraScale/ts-orchestrator/internal/placement"
	"git.terrascale.tech/TerraScale/ts-orchestrator/internal/protocol"
	"github.com/nats-io/nats.go"
)

const maxPlacementIntentBytes = 16 << 10
const maxPlacementWireBytes = maxPlacementIntentBytes + 4096

func placementApplySubject(cell string) string { return "ts.orch.v1." + cell + ".placement.apply" }

func placementOperationID(intent placement.Intent) string {
	sum := sha256.Sum256([]byte(fmt.Sprintf("%s\x00%s\x00%d", intent.DatabaseID, intent.PartitionID, intent.Generation)))
	return "p-" + strings.ToLower(base32.StdEncoding.WithPadding(base32.NoPadding).EncodeToString(sum[:]))
}

func intentSelectsCell(intent placement.Intent, cell string) bool {
	return slices.ContainsFunc(intent.ActiveRegions, func(region oci.Region) bool { return strings.EqualFold(string(region), cell) })
}

func operatorPlacementApply(ctx context.Context, cfg Config, runtime *natscell.Runtime, path string, output io.Writer) error {
	data, err := readBoundedConfigFile(path)
	if err != nil {
		return err
	}
	if len(data) == 0 || len(data) > maxPlacementIntentBytes {
		return errors.New("placement intent file exceeds size limit")
	}
	var intent placement.Intent
	if err := json.Unmarshal(data, &intent, json.RejectUnknownMembers(true)); err != nil {
		return fmt.Errorf("parse placement intent: %w", err)
	}
	if err := intent.Validate(); err != nil {
		return err
	}
	if !intentSelectsCell(intent, cfg.NATS.Cell) {
		return errors.New("placement intent does not select this regional cell")
	}
	policy, err := buildSignerPolicy(cfg)
	if err != nil {
		return err
	}
	grant, exists := policy.grants[cfg.Operator.Actor]
	if !exists || !grant.CanPlaceTerraBase {
		return errors.New("operator is not authorized to apply TerraBase placement")
	}
	codec, err := policy.withOperator(cfg.Operator)
	if err != nil {
		return err
	}
	snapshot, err := authority.Observe(ctx, runtime.JetStream(), cfg.NATS.Cell)
	if err != nil {
		return err
	}
	if !snapshot.Ready || snapshot.Reason != "observed" || snapshot.Epoch == 0 || !time.Now().Before(snapshot.ExpiresAt) {
		return errors.New("regional authority lease is not current")
	}
	payload, err := json.Marshal(intent)
	if err != nil {
		return err
	}
	now := time.Now().UTC()
	envelope, err := protocol.SignEnvelope(payload, protocol.EnvelopeScope{
		Region: cfg.NATS.Cell, Kind: "placement.intent", Actor: cfg.Operator.Actor,
		OperationID: placementOperationID(intent), Generation: intent.Generation, Epoch: snapshot.Epoch,
	}, now, now.Add(time.Minute), codec.PrivateKey)
	if err != nil {
		return err
	}
	wire, err := protocol.EncodeJSON(envelope)
	if err != nil {
		return err
	}
	for attempt := range 3 {
		requestCtx, cancel := context.WithTimeout(ctx, 10*time.Second)
		message, requestErr := runtime.Conn().RequestWithContext(requestCtx, placementApplySubject(cfg.NATS.Cell), wire)
		cancel()
		if requestErr == nil {
			var response placementApplyResponse
			if err := json.Unmarshal(message.Data, &response, json.RejectUnknownMembers(true)); err != nil {
				return fmt.Errorf("decode placement reply: %w", err)
			}
			if response.Error != "" {
				return errors.New(response.Error)
			}
			if response.DatabaseID != intent.DatabaseID || response.PartitionID != intent.PartitionID || response.Generation != intent.Generation || response.Sequence == 0 {
				return errors.New("controller returned a different placement receipt")
			}
			return printJSON(output, response)
		}
		if (!errors.Is(requestErr, nats.ErrTimeout) && !errors.Is(requestErr, context.DeadlineExceeded)) || attempt == 2 {
			return fmt.Errorf("request placement admission: %w", requestErr)
		}
	}
	return errors.New("placement admission request exhausted")
}

type placementApplyResponse struct {
	DatabaseID  string `json:"databaseId"`
	PartitionID string `json:"partitionId"`
	Generation  uint64 `json:"generation"`
	Sequence    uint64 `json:"sequence"`
	Error       string `json:"error,omitempty"`
}

func servePlacementAdmission(ctx context.Context, conn *nats.Conn, cell string, policy signerPolicy, control *authority.Runtime) (*nats.Subscription, error) {
	return conn.Subscribe(placementApplySubject(cell), func(message *nats.Msg) {
		if message.Reply == "" || len(message.Data) == 0 || len(message.Data) > maxPlacementWireBytes || !control.Current().CanMutate() {
			return
		}
		requestCtx, cancel := context.WithTimeout(ctx, 10*time.Second)
		defer cancel()
		response, err := verifyAndApplyPlacement(requestCtx, message.Data, cell, policy, control)
		if errors.Is(err, authority.ErrFenced) || errors.Is(err, authority.ErrNotLeader) || !control.Current().CanMutate() {
			return
		}
		if err != nil {
			response = placementApplyResponse{Error: err.Error()}
		}
		wire, err := json.Marshal(response)
		if err == nil {
			_ = message.Respond(wire)
		}
	})
}

func verifyAndApplyPlacement(ctx context.Context, wire []byte, cell string, policy signerPolicy, control *authority.Runtime) (placementApplyResponse, error) {
	var envelope protocol.Envelope
	if err := protocol.DecodeStrict(wire, &envelope, maxPlacementWireBytes); err != nil {
		return placementApplyResponse{}, err
	}
	var intent placement.Intent
	if err := protocol.DecodeStrict(envelope.Payload, &intent, maxPlacementIntentBytes); err != nil {
		return placementApplyResponse{}, err
	}
	if err := intent.Validate(); err != nil {
		return placementApplyResponse{}, err
	}
	if !intentSelectsCell(intent, cell) {
		return placementApplyResponse{}, errors.New("placement intent does not select this regional cell")
	}
	grant, exists := policy.grants[envelope.Actor]
	if !exists || !grant.CanPlaceTerraBase {
		return placementApplyResponse{}, errors.New("placement actor is unauthorized")
	}
	trusted, exists := policy.codec.Trusted[envelope.KeyID]
	if !exists || trusted.Actor != envelope.Actor {
		return placementApplyResponse{}, errors.New("placement signing key is untrusted")
	}
	if err := protocol.VerifyEnvelope(envelope, protocol.EnvelopeScope{
		Region: cell, Kind: "placement.intent", Actor: trusted.Actor,
		OperationID: placementOperationID(intent), Generation: intent.Generation, Epoch: envelope.Epoch,
	}, trusted.PublicKey, time.Now().UTC(), protocol.VerifyPolicy{MaxLifetime: 5 * time.Minute, ClockSkew: 30 * time.Second}); err != nil {
		return placementApplyResponse{}, err
	}
	if envelope.Epoch == 0 || control.Current().Epoch != envelope.Epoch {
		return placementApplyResponse{}, authority.ErrFenced
	}
	payload, err := json.Marshal(intent)
	if err != nil {
		return placementApplyResponse{}, err
	}
	for range 8 {
		var expected uint64
		current, err := control.ReadPlacementIntent(ctx, intent.DatabaseID, intent.PartitionID)
		if err == nil {
			var old placement.Intent
			if err := json.Unmarshal(current.Payload, &old, json.RejectUnknownMembers(true)); err != nil || old.Validate() != nil || old.DatabaseID != intent.DatabaseID || old.PartitionID != intent.PartitionID {
				return placementApplyResponse{}, errors.New("durable placement intent is corrupt")
			}
			if old.Generation > intent.Generation || old.Generation == intent.Generation && !bytes.Equal(current.Payload, payload) {
				return placementApplyResponse{}, authority.ErrConflict
			}
			if old.Generation == intent.Generation {
				return placementApplyResponse{DatabaseID: intent.DatabaseID, PartitionID: intent.PartitionID, Generation: intent.Generation, Sequence: current.Sequence}, nil
			}
			expected = current.Sequence
		} else if !errors.Is(err, authority.ErrNotFound) {
			return placementApplyResponse{}, err
		}
		sequence, err := control.CommitPlacementIntent(ctx, envelope.Epoch, intent.DatabaseID, intent.PartitionID, placementOperationID(intent), expected, payload)
		if err == nil {
			return placementApplyResponse{DatabaseID: intent.DatabaseID, PartitionID: intent.PartitionID, Generation: intent.Generation, Sequence: sequence}, nil
		}
		if !errors.Is(err, authority.ErrConflict) {
			return placementApplyResponse{}, err
		}
	}
	return placementApplyResponse{}, errors.New("placement intent contention")
}
