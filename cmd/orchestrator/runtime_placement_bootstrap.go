package main

import (
	"context"
	"crypto/ed25519"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json/v2"
	"errors"
	"github.com/nats-io/nats.go"
	"google.golang.org/grpc/codes"
	"google.golang.org/grpc/status"
	"time"

	"google.golang.org/protobuf/proto"
	"terrascale.tech/orchestrator/src/orchestrator/databaseadmission"
	"terrascale.tech/orchestrator/src/orchestrator/placementtransition"
	pb "terrascale.tech/orchestrator/src/orchestrator/tbep/wire/terrabase/v1"
)

// RunBootstrap retries typed member-transport outages without treating a malformed
// signed grant or missing durable state as an outage. Authority loss returns to
// the global session supervisor; it cannot be healed by inventing a new grant.
func (t *productionPlacementTransition) RunBootstrap(ctx context.Context) error {
	for {
		err := t.Bootstrap(ctx)
		if err == nil {
			return nil
		}
		if ctx.Err() != nil {
			return ctx.Err()
		}
		if !transientBootstrapError(err) {
			return err
		}
		if authorityErr := t.check(ctx); authorityErr != nil {
			return authorityErr
		}
		timer := time.NewTimer(time.Second)
		select {
		case <-ctx.Done():
			timer.Stop()
			return ctx.Err()
		case <-timer.C:
		}
	}
}
func transientBootstrapError(err error) bool {
	if errors.Is(err, nats.ErrTimeout) || errors.Is(err, nats.ErrNoResponders) || errors.Is(err, nats.ErrConnectionClosed) || errors.Is(err, nats.ErrDisconnected) || errors.Is(err, context.DeadlineExceeded) {
		return true
	}
	switch status.Code(err) {
	case codes.Unavailable, codes.DeadlineExceeded:
		return true
	}
	return false
}

// Bootstrap admits only the explicitly configured empty cluster before any
// customer request. Its immutable operation and signed grant are deployment
// inputs, never chosen from missing state or a customer's generated database ID.
// Already accepted clusters skip initial Stage; they retain their current head.
func (t *productionPlacementTransition) Bootstrap(ctx context.Context) error {
	if t == nil || t.config.Bootstrap == nil {
		return errors.New("runtime transition: explicit cluster bootstrap configuration required")
	}
	config := t.config.Bootstrap
	record := databaseadmission.Record{Request: databaseadmission.Request{Environment: config.Environment}}
	for _, target := range config.Targets {
		stage := new(pb.PlacementStageRequest)
		if proto.Unmarshal(target.Proposal, stage) != nil || stage.Proposal == nil || len(stage.Proposal.Assignments) != 0 || len(stage.Declarations) != 0 || stage.ExpectedRevision != 0 || stage.Proposal.Epoch != 1 || stage.Proposal.Generation != 1 {
			return errors.New("runtime transition: bootstrap requires exact empty initial placement")
		}
		if t.bootstrapPublishers[target.ServerIdentity] == nil {
			return placementtransition.ErrInvalid
		}
		// The host independently validates its empty configured catalog.
		record.PlacementTargets = append(record.PlacementTargets, databaseadmission.PlacementTarget{ServerIdentity: target.ServerIdentity, MemberID: target.MemberID, Region: target.Region, Proposal: target.Proposal, Proposed: true})
	}
	request, err := transitionRequest(record)
	if err != nil {
		return err
	}
	request.OperationID = config.OperationID
	d, err := placementtransition.RequestDigest(request)
	if err != nil {
		return err
	}
	grant, ok := t.config.GenesisGrants[config.OperationID]
	var authorization placementtransition.GenesisGrant
	key := t.config.Issuer.GenesisKeys[grant.KeyID]
	if !ok || len(key) != ed25519.PublicKeySize || !ed25519.Verify(key, append([]byte("terrabase-placement-transition-v1\x00"), grant.Payload...), grant.Signature) || json.Unmarshal(grant.Payload, &authorization, json.RejectUnknownMembers(true)) != nil || authorization.Kind != "genesis_grant" || authorization.RequestDigest != d {
		return errors.New("runtime transition: configured bootstrap differs from explicit genesis grant")
	}
	head, err := t.issuer.Head(ctx, request.ScopeID)
	if err == nil {
		var proof placementtransition.Proof
		if json.Unmarshal(head.Payload, &proof, json.RejectUnknownMembers(true)) != nil {
			return placementtransition.ErrInvalid
		}
		if proof.Request.OperationID != config.OperationID {
			return nil
		}
		if t.completion != nil {
			sum := sha256.Sum256(head.Payload)
			if err := t.completion(ctx, config.OperationID, hex.EncodeToString(sum[:]), false); err == nil {
				return nil
			} else if !errors.Is(err, placementtransition.ErrMissing) {
				return err
			}
		}
		// Retry a committed genesis whose accepted delivery outcome was unknown.
		if proof.RequestDigest != d {
			return placementtransition.ErrConflict
		}
		return t.activate(ctx, record, config.OperationID)
	}
	if !errors.Is(err, placementtransition.ErrMissing) {
		return err
	}
	// A retained operation with no scope head is missing durable state, not a
	// fresh cluster. Never use its old genesis authorization to recreate state.
	if _, err := t.issuer.Load(ctx, config.OperationID); err == nil {
		return errors.New("runtime transition: bootstrap head missing for retained operation")
	} else if !errors.Is(err, placementtransition.ErrMissing) {
		return err
	}
	for _, target := range record.PlacementTargets {
		stage := new(pb.PlacementStageRequest)
		_ = proto.Unmarshal(target.Proposal, stage)
		publisher := t.bootstrapPublishers[target.ServerIdentity]
		if err := publisher.Accept(ctx, config.OperationID, stage); err != nil {
			return err
		}
		if _, err := publisher.Reconcile(ctx); err != nil {
			return err
		}
	}
	return t.activate(ctx, record, config.OperationID)
}
