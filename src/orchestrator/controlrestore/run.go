// Package controlrestore executes the finite final snapshot restoration phase.
// It never starts application workers, obtains an election lease, or removes a
// conflicting stream. The admitted candidate runtime owns isolation and routes.
package controlrestore

import (
	"bytes"
	"context"
	"encoding/json/v2"
	"errors"
	"fmt"
	"io"
	"reflect"
	"time"

	"github.com/nats-io/nats.go"
	"terrascale.tech/orchestrator/src/orchestrator/controltransition"
	"terrascale.tech/orchestrator/src/orchestrator/finalcapture"
	"terrascale.tech/orchestrator/src/orchestrator/restoredrill"
	"terrascale.tech/orchestrator/src/orchestrator/security"
)

type ObjectReader interface {
	OpenSnapshot(context.Context, controltransition.CaptureObject) (io.ReadCloser, error)
}
type ReceiptStore interface {
	Read(context.Context) ([]byte, bool, error)
	Publish(context.Context, []byte) error
}

// Runtime must hold exclusive admitted restore access throughout Run. Account
// connections must be bound to the plan's distinct destination namespaces.
type Runtime interface {
	Check(context.Context, controltransition.VerifiedPlan) error
	Account(string) (*nats.Conn, error)
}
type Config struct {
	Plan               controltransition.VerifiedPlan
	NodeID             string
	CutReceipt         []byte
	SourceStateReceipt []byte
	CaptureReceipt     []byte
	Objects            ObjectReader
	Receipts           ReceiptStore
	Runtime            Runtime
	Signer             *security.CommandSignatureSigner
}

// Run restores and verifies the complete final inventory before signing a
// receipt. Replays re-observe every stream and consumer; stored success alone
// cannot conceal a now-missing peer, changed state, or consumer identity.
func Run(ctx context.Context, c Config) ([]byte, error) {
	if ctx == nil || c.Objects == nil || c.Receipts == nil || c.Runtime == nil || c.Signer == nil {
		return nil, errors.New("controlrestore: required dependency absent")
	}
	plan, err := c.Plan.Plan()
	if err != nil {
		return nil, err
	}
	if c.NodeID != plan.Destinations[0].NodeID {
		return nil, errors.New("controlrestore: only admitted GRU destination restores")
	}
	ctx, cancel := context.WithDeadline(ctx, plan.ExpiresAt)
	defer cancel()
	check := func() error {
		if err := ctx.Err(); err != nil {
			return err
		}
		if err := c.Plan.Check(time.Now().UTC()); err != nil {
			return err
		}
		return c.Runtime.Check(ctx, c.Plan)
	}
	if err := check(); err != nil {
		return nil, err
	}
	capture, err := controltransition.VerifyCaptureReceipt(c.Plan, c.CutReceipt, c.SourceStateReceipt, c.CaptureReceipt)
	if err != nil {
		return nil, err
	}
	prior, exists, err := c.Receipts.Read(ctx)
	if err != nil {
		return nil, err
	}
	if exists {
		if _, err := controltransition.VerifyRestoreReceipt(c.Plan, c.CutReceipt, c.SourceStateReceipt, c.CaptureReceipt, prior); err != nil {
			return nil, err
		}
	}
	result := controltransition.RestoreReceipt{Version: 1, Phase: "final-restored-r3", PlanSHA256: c.Plan.Digest(), CaptureReceiptSHA256: controltransition.Digest(c.CaptureReceipt), NodeID: c.NodeID, Cluster: plan.ClusterName, GlobalElectionFloor: capture.GlobalElectionFloor, RegionalElectionFloor: capture.RegionalElectionFloor, Streams: []controltransition.RestoredStream{}}
	// A second complete pass proves the whole inventory after all mutations. It
	// performs no promotion if the first pass completed, and detects intervening
	// state/assignment changes before a global receipt is signed.
	for pass := range 2 {
		result.Streams = nil
		for index, object := range capture.Objects {
			if err := check(); err != nil {
				return nil, err
			}
			source := capture.Streams[index]
			reader, err := c.Objects.OpenSnapshot(ctx, object)
			if err != nil {
				return nil, err
			}
			envelope, readErr := io.ReadAll(io.LimitReader(reader, object.Size+1))
			closeErr := reader.Close()
			if err := errors.Join(readErr, closeErr); err != nil {
				return nil, err
			}
			if int64(len(envelope)) != object.Size || controltransition.Digest(envelope) != object.SHA256 {
				return nil, errors.New("controlrestore: final archive digest differs")
			}
			observed, err := finalcapture.EnvelopeEvidence(envelope, plan.Limits.MaxSnapshotBytes, source.Role, source.Account, source.Stream)
			if err != nil {
				return nil, err
			}
			if !reflect.DeepEqual(observed, source) {
				return nil, errors.New("controlrestore: captured source state differs from envelope")
			}
			nc, err := c.Runtime.Account(source.Role)
			if err != nil {
				return nil, err
			}
			evidence, err := restoredrill.RestoreFinalSnapshot(ctx, nc, c.Plan, source.Role, source.Stream, envelope)
			if err != nil {
				return nil, fmt.Errorf("controlrestore: %s/%s: %w", source.Role, source.Stream, err)
			}
			stream := source
			stream.Created = evidence.RestoredCreated
			stream.Consumers = append([]controltransition.ConsumerEvidence(nil), source.Consumers...)
			for _, account := range plan.Accounts {
				if account.Role == source.Role {
					stream.Account = account.DestinationName
					for _, item := range account.Streams {
						if item.Name == source.Stream {
							stream.ConfigSHA256 = item.FinalConfigSHA256
							for i := range stream.Consumers {
								stream.Consumers[i].ConfigSHA256 = item.Consumers[i].FinalConfigSHA256
							}
						}
					}
				}
			}
			if evidence.Snapshot.RecordsSHA256 != source.RecordsSHA256 {
				return nil, errors.New("controlrestore: restored records differ")
			}
			if pass == 1 {
				result.Streams = append(result.Streams, controltransition.RestoredStream{SourceCreated: source.Created, Observed: stream, Servers: evidence.Servers})
			}
		}
	}
	if err := check(); err != nil {
		return nil, err
	}
	if exists {
		previous, err := controltransition.VerifyRestoreReceipt(c.Plan, c.CutReceipt, c.SourceStateReceipt, c.CaptureReceipt, prior)
		if err != nil {
			return nil, err
		}
		if !reflect.DeepEqual(previous.Streams, result.Streams) {
			return nil, errors.New("controlrestore: restored inventory differs from durable receipt")
		}
		return prior, nil
	}
	result.RestoredAt = time.Now().UTC()
	signed, err := controltransition.SignRestoreReceipt(c.Signer, c.Plan, c.CutReceipt, c.SourceStateReceipt, c.CaptureReceipt, result)
	if err != nil {
		return nil, err
	}
	if err := c.Receipts.Publish(ctx, signed); err != nil {
		return nil, err
	}
	readback, found, err := c.Receipts.Read(ctx)
	if err != nil {
		return nil, err
	}
	if !found || !bytes.Equal(readback, signed) {
		return nil, errors.New("controlrestore: receipt durable readback differs")
	}
	if _, err := controltransition.VerifyRestoreReceipt(c.Plan, c.CutReceipt, c.SourceStateReceipt, c.CaptureReceipt, readback); err != nil {
		return nil, err
	}
	return readback, nil
}

// CanonicalEvidence is useful to durably pin a readback without JSON map-order
// ambiguity; the receipt still requires its verified predecessor and signature.
func CanonicalEvidence(e controltransition.RestoreReceipt) ([]byte, error) { return json.Marshal(e) }
