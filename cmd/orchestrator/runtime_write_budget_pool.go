package main

import (
	"context"
	"encoding/json/v2"
	"errors"
	"time"

	"github.com/nats-io/nats.go"
	"terrascale.tech/orchestrator/src/orchestrator/databaseadmission"
	"terrascale.tech/orchestrator/src/orchestrator/writebudget"
)

// HandlePoolWork trusts only the broker's exact host publish subject, checked
// against the currently accepted writer target before any journal transaction.
func (r *runtimeWriteBudget) HandlePoolWork(ctx context.Context, subject string, work databaseadmission.PoolWork) (databaseadmission.PoolWorkReply, error) {
	reply := databaseadmission.PoolWorkReply{RefillOperationID: work.Request.RefillOperationID}
	if r == nil || r.authority == nil || r.poolTarget == nil || len(work.Consumptions) > 64 {
		return reply, writebudget.ErrInvalid
	}
	q := work.Request
	target, err := r.poolTarget(ctx, writebudget.AllocationEnvelope{Placement: q.Placement, Grant: writebudget.Grant{OrganizationID: q.OrganizationID, DatabaseID: q.DatabaseID, HolderID: q.HolderID, Regions: q.Regions, WriterEpoch: q.WriterEpoch}})
	if err != nil {
		return reply, err
	}
	expected, err := databaseadmission.PoolSubject(target.ServerIdentity)
	if err != nil || expected != subject || target.MemberID != q.HolderID || target.Region != q.Region || q.OrganizationID != r.policy.OrganizationID || q.Units < 0 || q.Units > 1024 || q.MaxPoolUnits > 1024 {
		return reply, writebudget.ErrInvalid
	}
	for _, fact := range work.Consumptions {
		if fact.DatabaseID != q.DatabaseID || fact.PoolID != q.PoolID {
			return reply, writebudget.ErrInvalid
		}
		if _, err := r.authority.RecordPoolConsumption(ctx, fact); err != nil {
			return reply, err
		}
	}
	if q.Units == 0 {
		reply.State = "reported"
		return reply, nil
	}
	// An expired request can be retired but no balance is reclaimed at GRU.
	// Any unknown prior reservation remains reserved and cannot be reissued.
	if !q.ExpiresAt.After(time.Now()) {
		reply.State = "expired"
		return reply, nil
	}
	if _, err := r.RefillPool(ctx, q); err != nil {
		if errors.Is(err, writebudget.ErrExhausted) {
			reply.State = "reported"
			return reply, nil
		}
		return reply, err
	}
	reply.State = "installed"
	return reply, nil
}
func (r *runtimeWriteBudget) startPoolRefills(ctx context.Context, connection *nats.Conn) error {
	if !secureWriteBudgetConnection(connection) || r.poolTarget == nil || r.poolDelivery == nil {
		return writebudget.ErrUnavailable
	}
	sub, err := connection.Subscribe(databaseadmission.PoolRefillAuthoritySubject, func(message *nats.Msg) {
		if message.Reply == "" || len(message.Data) > 64<<10 {
			return
		}
		var request databaseadmission.PoolAuthorityRequest
		if json.Unmarshal(message.Data, &request, json.RejectUnknownMembers(true)) != nil || request.Work.Request.RefillOperationID == "" {
			_ = message.Respond([]byte("invalid"))
			return
		}
		opctx, cancel := context.WithTimeout(ctx, 20*time.Second)
		defer cancel()
		target, err := r.poolTarget(opctx, writebudget.AllocationEnvelope{Placement: request.Work.Request.Placement, Grant: writebudget.Grant{OrganizationID: request.Work.Request.OrganizationID, DatabaseID: request.Work.Request.DatabaseID, HolderID: request.MemberID, Regions: request.Work.Request.Regions, WriterEpoch: request.Work.Request.WriterEpoch}})
		if err != nil || target.ServerIdentity != request.ServerIdentity || target.MemberID != request.MemberID {
			_ = message.Respond([]byte("unavailable"))
			return
		}
		subject, err := databaseadmission.PoolSubject(target.ServerIdentity)
		if err != nil {
			_ = message.Respond([]byte("unavailable"))
			return
		}
		reply, err := r.HandlePoolWork(opctx, subject, request.Work)
		if err != nil {
			_ = message.Respond([]byte("unavailable"))
			return
		}
		data, err := json.Marshal(reply)
		if err == nil {
			_ = message.Respond(data)
		}
	})
	if err != nil {
		return err
	}
	if err = sub.SetPendingLimits(128, 8<<20); err != nil {
		_ = sub.Unsubscribe()
		return err
	}
	if err = connection.FlushTimeout(5 * time.Second); err != nil {
		_ = sub.Unsubscribe()
		return err
	}
	r.poolSubscription = sub
	context.AfterFunc(ctx, func() { _ = sub.Unsubscribe() })
	return nil
}
