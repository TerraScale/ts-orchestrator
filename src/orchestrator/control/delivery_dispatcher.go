package control

import (
	"context"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"time"

	"github.com/nats-io/nats.go"
	"github.com/nats-io/nats.go/jetstream"
	"terrascale.tech/orchestrator/src/orchestrator/control/authority"
	"terrascale.tech/orchestrator/src/orchestrator/delivery"
	"terrascale.tech/orchestrator/src/orchestrator/nodeauthority"
	"terrascale.tech/orchestrator/src/orchestrator/protocol"
)

type signedDeliveryDispatcher struct {
	cell, instance string
	connection     *nats.Conn
	authority      *RegionalAuthorityCoordinator
	leaders, store jetstream.KeyValue
	executor       *delivery.Executor
}

type deliveryAdmission struct {
	Version           int    `json:"version"`
	OperationID       string `json:"operationId"`
	PayloadDigest     string `json:"payloadDigest"`
	IdempotencyDigest string `json:"idempotencyDigest"`
	Generation        int64  `json:"generation"`
}

type signedDeliveryContext struct {
	admission deliveryAdmission
	epoch     int64
}
type signedDeliveryContextKey struct{}

func (d *signedDeliveryDispatcher) dispatch(ctx context.Context, envelope protocol.CommandEnvelope) error {
	if ctx == nil || envelope.Cell.Value != d.cell || envelope.AggregateId.Value != "delivery" || envelope.WriterEpoch.Value <= 0 || envelope.DesiredGeneration.Value <= 0 {
		return errors.New("signed delivery: envelope scope is invalid")
	}
	request, err := delivery.ParseRequest(string(envelope.Payload.Bytes()))
	if err != nil {
		return errors.New("signed delivery: invalid delivery request")
	}
	if err := delivery.ValidateRequest(request); err != nil || request.OperationID != envelope.OperationId.Value || request.Artifact == nil || request.Artifact.Architecture == "" {
		return errors.New("signed delivery: operation or artifact identity differs from its envelope")
	}
	// A regional lease authorizes only that region. GRU's master role does
	// not grant its regional writer another region's mutation authority.
	// Fanout must issue separately signed requests with their own operation IDs.
	if len(request.Target.Regions) != 1 || request.Target.Regions[0] != d.cell {
		return errors.New("signed delivery: request must target exactly its admitted cell")
	}
	if !time.Now().Before(envelope.ExpiresAt) {
		return errors.New("signed delivery: command has expired")
	}
	ctx, cancel := context.WithDeadline(ctx, envelope.ExpiresAt)
	defer cancel()
	if err := d.checkLeader(ctx, envelope.WriterEpoch.Value); err != nil {
		return err
	}
	payload := sha256.Sum256(envelope.Payload.Bytes())
	idempotency := sha256.Sum256([]byte(envelope.IdempotencyKey.Value))
	admission := deliveryAdmission{Version: 1, OperationID: request.OperationID, PayloadDigest: hex.EncodeToString(payload[:]), IdempotencyDigest: hex.EncodeToString(idempotency[:]), Generation: envelope.DesiredGeneration.Value}
	if err := d.admit(ctx, admission, envelope.WriterEpoch.Value); err != nil {
		return err
	}
	ctx = context.WithValue(ctx, signedDeliveryContextKey{}, signedDeliveryContext{admission, envelope.WriterEpoch.Value})
	ctx, err = delivery.WithRegionalCommandAuthority(ctx, func(readCtx context.Context) (delivery.RegionalCommandAuthority, error) {
		if err := d.checkAuthority(readCtx, request); err != nil {
			return delivery.RegionalCommandAuthority{}, err
		}
		lease, err := d.readLeader(readCtx, envelope.WriterEpoch.Value)
		if err != nil {
			return delivery.RegionalCommandAuthority{}, err
		}
		return delivery.RegionalCommandAuthority{AuthorityID: lease.AuthorityId, Epoch: lease.Epoch, CandidateID: lease.CandidateId, LeaseID: lease.LeaseId, IssuedAt: lease.IssuedAt, ExpiresAt: lease.IssuedAt.Add(time.Duration(lease.DurationMilliseconds) * time.Millisecond), DesiredGeneration: admission.Generation}, nil
	})
	if err != nil {
		return err
	}
	receipt, err := d.executor.Submit(ctx, request)
	if err != nil {
		return err
	}
	if receipt == nil || receipt.Status != delivery.StatusSucceeded {
		return errors.New("signed delivery: terminal receipt did not prove success")
	}
	return nil
}

func (d *signedDeliveryDispatcher) checkLeader(ctx context.Context, epoch int64) error {
	_, err := d.readLeader(ctx, epoch)
	return err
}

func (d *signedDeliveryDispatcher) readLeader(ctx context.Context, epoch int64) (authority.RegionalAuthorityLeaseDocument, error) {
	if ctx == nil || d.authority == nil || d.leaders == nil {
		return authority.RegionalAuthorityLeaseDocument{}, errors.New("signed delivery: live authority is unavailable")
	}
	if err := ctx.Err(); err != nil {
		return authority.RegionalAuthorityLeaseDocument{}, err
	}
	snapshot := d.authority.Snapshot()
	if !snapshot.Ready() || !snapshot.IsLeader || snapshot.State != "leader" || snapshot.Epoch != epoch {
		return authority.RegionalAuthorityLeaseDocument{}, errors.New("signed delivery: regional writer is fenced")
	}
	readCtx, cancel := context.WithTimeout(ctx, 5*time.Second)
	defer cancel()
	body, _, err := nodeauthority.ReadLeaderKV(readCtx, d.connection, d.leaders.Bucket(), "authority.regional")
	if err != nil {
		return authority.RegionalAuthorityLeaseDocument{}, errors.New("signed delivery: regional authority reread failed")
	}
	var lease authority.RegionalAuthorityLeaseDocument
	if json.Unmarshal(body, &lease) != nil || lease.Validate() != nil || lease.AuthorityId != d.cell+"-regional" || lease.CandidateId != d.cell+"-controller-"+d.instance || lease.Epoch != epoch || !time.Now().Before(lease.IssuedAt.Add(time.Duration(lease.DurationMilliseconds)*time.Millisecond)) {
		return authority.RegionalAuthorityLeaseDocument{}, errors.New("signed delivery: authoritative regional lease differs")
	}
	return lease, nil
}

func (d *signedDeliveryDispatcher) checkAuthority(ctx context.Context, request *delivery.Request) error {
	if ctx == nil {
		return errors.New("signed delivery: command authority is missing")
	}
	bound, ok := ctx.Value(signedDeliveryContextKey{}).(signedDeliveryContext)
	if !ok || request == nil || request.OperationID != bound.admission.OperationID {
		return errors.New("signed delivery: command authority is missing")
	}
	if err := d.checkLeader(ctx, bound.epoch); err != nil {
		return err
	}
	readCtx, cancel := context.WithTimeout(ctx, 5*time.Second)
	defer cancel()
	body, _, err := nodeauthority.ReadLeaderKV(readCtx, d.connection, d.store.Bucket(), "signed-delivery.head")
	if err != nil {
		return errors.New("signed delivery: generation reread failed")
	}
	var head deliveryAdmission
	if json.Unmarshal(body, &head) != nil || head != bound.admission {
		return errors.New("signed delivery: desired generation has been superseded")
	}
	return nil
}

func (d *signedDeliveryDispatcher) admit(ctx context.Context, value deliveryAdmission, epoch int64) error {
	ctx, cancel := context.WithTimeout(ctx, 5*time.Second)
	defer cancel()
	if err := d.checkLeader(ctx, epoch); err != nil {
		return err
	}
	body, _ := json.Marshal(value)
	key := "signed-delivery.idempotency." + value.IdempotencyDigest
	if _, err := d.store.Create(ctx, key, body); err != nil {
		if !errors.Is(err, jetstream.ErrKeyExists) {
			return fmt.Errorf("signed delivery: durable idempotency admission: %w", err)
		}
		prior, _, readErr := nodeauthority.ReadLeaderKV(ctx, d.connection, d.store.Bucket(), key)
		if readErr != nil {
			return readErr
		}
		var admitted deliveryAdmission
		if json.Unmarshal(prior, &admitted) != nil || admitted.Version != 1 || admitted.OperationID != value.OperationID || admitted.PayloadDigest != value.PayloadDigest {
			return errors.New("signed delivery: idempotency key conflicts")
		}
	}
	for attempt := 0; attempt < 8; attempt++ {
		headBody, revision, err := nodeauthority.ReadLeaderKV(ctx, d.connection, d.store.Bucket(), "signed-delivery.head")
		if checkErr := d.checkLeader(ctx, epoch); checkErr != nil {
			return checkErr
		}
		if errors.Is(err, jetstream.ErrKeyNotFound) {
			_, err = d.store.Create(ctx, "signed-delivery.head", body)
		} else if err == nil {
			var head deliveryAdmission
			if json.Unmarshal(headBody, &head) != nil || head.Version != 1 || head.Generation <= 0 {
				return errors.New("signed delivery: durable generation is invalid")
			}
			if head == value {
				return nil
			}
			if value.Generation <= head.Generation {
				return errors.New("signed delivery: stale or conflicting desired generation")
			}
			_, err = d.store.Update(ctx, "signed-delivery.head", body, revision)
		}
		if err == nil {
			return nil
		}
		if !errors.Is(err, jetstream.ErrKeyExists) {
			return err
		}
	}
	return errors.New("signed delivery: generation admission remained contended")
}
