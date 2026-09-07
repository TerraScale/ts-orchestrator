package main

import (
	"context"
	"crypto/tls"
	"encoding/json/v2"
	"errors"
	"slices"
	"strings"
	"time"

	"github.com/nats-io/nats.go"
	"terrascale.tech/orchestrator/src/orchestrator/databaseadmission"
	"terrascale.tech/orchestrator/src/orchestrator/writebudget"
)

const writeBudgetDeliveryLimit = 16 << 10

// writeBudgetTargetResolver reads the accepted lifecycle record and returns
// the single current writer admitted for the grant holder. It is deliberately
// a resolver rather than a host list: Grant.Regions is a pricing set.
type writeBudgetTargetResolver func(context.Context, string, string) (databaseadmission.Target, error)

// runtimeWriteBudgetDelivery is the production allocation transport. The
// signed allocation is marshalled once and sent unchanged to one host subject.
type runtimeWriteBudgetDelivery struct {
	connection *nats.Conn
	resolve    writeBudgetTargetResolver
	check      func(context.Context) error
}

func newRuntimeWriteBudgetDelivery(connection *nats.Conn, resolve writeBudgetTargetResolver, check func(context.Context) error) (*runtimeWriteBudgetDelivery, error) {
	if !secureWriteBudgetConnection(connection) || resolve == nil || check == nil {
		return nil, errors.New("write budget delivery: authenticated NATS and admitted target resolver are required")
	}
	return &runtimeWriteBudgetDelivery{connection: connection, resolve: resolve, check: check}, nil
}

func secureWriteBudgetConnection(connection *nats.Conn) bool {
	if connection == nil || !connection.IsConnected() || !connection.AuthRequired() {
		return false
	}
	opts := connection.Opts
	if opts.Nkey == "" || opts.SignatureCB == nil || opts.AllowReconnect || opts.ReconnectBufSize >= 0 || opts.TLSConfig == nil || opts.TLSConfig.InsecureSkipVerify || opts.TLSConfig.RootCAs == nil || (len(opts.TLSConfig.Certificates) == 0 && opts.TLSConfig.GetClientCertificate == nil && opts.TLSCertCB == nil) {
		return false
	}
	state, err := connection.TLSConnectionState()
	return err == nil && state.HandshakeComplete && state.Version >= tls.VersionTLS13 && len(state.VerifiedChains) > 0
}

func (d *runtimeWriteBudgetDelivery) SendAllocation(ctx context.Context, signed writebudget.SignedAllocation) error {
	if d == nil || !secureWriteBudgetConnection(d.connection) || ctx == nil || d.resolve == nil || d.check == nil {
		return errors.New("write budget delivery: unavailable")
	}
	if err := d.check(ctx); err != nil {
		return err
	}
	var envelope writebudget.AllocationEnvelope
	if len(signed.Payload) == 0 || len(signed.Signature) == 0 || signed.KeyID == "" || json.Unmarshal(signed.Payload, &envelope, json.RejectUnknownMembers(true)) != nil || envelope.SchemaVersion != 1 {
		return errors.New("write budget delivery: malformed allocation")
	}
	grant := envelope.Grant
	if grant.OperationID == "" || grant.DatabaseID == "" || grant.HolderID == "" || envelope.CycleID == "" || envelope.Placement == "" || len(grant.Regions) == 0 || !slices.IsSorted(grant.Regions) || slices.Contains(grant.Regions[1:], grant.Regions[0]) {
		return errors.New("write budget delivery: invalid allocation identity")
	}
	for _, region := range grant.Regions {
		if region == "" || strings.TrimSpace(region) != region {
			return errors.New("write budget delivery: invalid allocation region")
		}
	}
	payload, err := json.Marshal(signed)
	if err != nil || len(payload) > writeBudgetDeliveryLimit {
		return errors.New("write budget delivery: allocation exceeds transport limit")
	}
	target, err := d.resolve(ctx, grant.DatabaseID, grant.HolderID)
	if err != nil {
		return err
	}
	if target.ServerIdentity == "" || target.MemberID != grant.HolderID || !slices.Contains(grant.Regions, target.Region) {
		return errors.New("write budget delivery: holder is not the admitted writer")
	}
	subject, err := databaseadmission.HostSubject(target.ServerIdentity)
	if err != nil {
		return err
	}
	opctx, cancel := context.WithTimeout(ctx, 20*time.Second)
	defer cancel()
	reply, err := d.connection.RequestWithContext(opctx, subject, payload)
	if err != nil {
		return errors.New("write budget delivery: holder unavailable")
	}
	if len(reply.Data) > writeBudgetDeliveryLimit || string(reply.Data) != "installed" {
		return errors.New("write budget delivery: installation unresolved")
	}
	return nil
}
