package app

import (
	"bytes"
	"context"
	"encoding/json/v2"
	"errors"
	"log"
	"strings"
	"time"

	"github.com/TerraScale/ts-orchestrator/internal/authority"
	"github.com/TerraScale/ts-orchestrator/internal/entityid"
	"github.com/TerraScale/ts-orchestrator/internal/protocol"
	"github.com/TerraScale/ts-orchestrator/internal/rootoci"
	"github.com/nats-io/nats.go"
)

func netBirdReadOpenSubject(cell string) string {
	return protocol.Regional(cell, "netbird", "read-open")
}

// Controllers publish public desired facts, never mutate the NetBird account.
func runNetBirdIntentProducer(ctx context.Context, cfg Config, conn *nats.Conn, control *authority.Runtime, root *rootoci.Client) error {
	if conn == nil || control == nil || root == nil {
		return errors.New("NetBird intent producer requires its actual broker, lease and root client")
	}
	sub, err := conn.Subscribe(netBirdReadOpenSubject(cfg.NATS.Cell), func(message *nats.Msg) {
		if !control.Current().CanMutate() {
			return
		}
		var request rootoci.NetBirdReadOpen
		if message.Reply == "" || protocol.DecodeStrict(message.Data, &request, 4096) != nil ||
			request.Schema != 1 || request.Cell != strings.ToUpper(cfg.NATS.Cell) || !entityid.Valid(request.Nonce) ||
			len(request.Signature) != 64 || !time.Now().Before(request.ExpiresAt) {
			return
		}
		attempt, cancel := context.WithDeadline(ctx, minDeadline(request.ExpiresAt, time.Now().Add(10*time.Second)))
		defer cancel()
		entry, err := control.ReadNetBirdIntent(attempt)
		var intent rootoci.NetBirdIntent
		if err == nil {
			err = protocol.DecodeStrict(entry.Payload, &intent, 1<<20)
		}
		if err == nil {
			input := netBirdIntentRequest(intent, entry.Sequence)
			input.ReadOpen = &request
			_, err = root.AuthorizeNetBirdIntent(attempt, input)
		}
		if err == nil {
			err = control.OpenNetBirdRead(attempt, request.Nonce)
		}
		if err == nil {
			err = control.OpenNetBirdSourceRead(attempt, request.Nonce)
		}
		if err == nil {
			input := netBirdIntentRequest(intent, entry.Sequence)
			input.ReadOpen = &request
			_, err = root.AuthorizeNetBirdIntent(attempt, input)
		}
		if err != nil {
			_ = message.Respond([]byte(`{"error":"NetBird source pending"}`))
			return
		}
		wire, err := json.Marshal(struct {
			Nonce string `json:"nonce"`
		}{Nonce: request.Nonce})
		if err == nil {
			_ = message.Respond(wire)
		}
	})
	if err != nil {
		return err
	}
	defer sub.Unsubscribe()
	if err := conn.FlushWithContext(ctx); err != nil {
		return err
	}
	ticker := time.NewTicker(5 * time.Second)
	defer ticker.Stop()
	for {
		if control.Current().CanMutate() {
			if err := publishNetBirdIntent(ctx, cfg, control, root); err != nil && ctx.Err() == nil {
				log.Printf("NetBird regional desired source pending: %v", err)
			}
		}
		select {
		case <-ctx.Done():
			return ctx.Err()
		case <-ticker.C:
		}
	}
}

func minDeadline(a, b time.Time) time.Time {
	if a.Before(b) {
		return a
	}
	return b
}

func netBirdIntentRequest(intent rootoci.NetBirdIntent, revision uint64) rootoci.NetBirdIntentRequest {
	return rootoci.NetBirdIntentRequest{Cell: intent.Cell, IntentRevision: revision, OperationID: intent.OperationID,
		RuntimeID: intent.RuntimeID, OwnerID: intent.OwnerID, Epoch: intent.Epoch, LeaseRevision: intent.LeaseRevision, ExpiresAt: intent.ExpiresAt}
}

func publishNetBirdIntent(ctx context.Context, cfg Config, control *authority.Runtime, root *rootoci.Client) error {
	snapshot := control.Current()
	if !snapshot.CanMutate() {
		return authority.ErrNotLeader
	}
	if err := control.Guard(ctx, snapshot.Epoch); err != nil {
		return err
	}
	snapshot = control.Current()
	request := rootoci.NetBirdIntentRequest{Cell: strings.ToUpper(cfg.NATS.Cell), OperationID: entityid.New(), RuntimeID: snapshot.CandidateID,
		OwnerID: snapshot.OwnerID, Epoch: snapshot.Epoch, LeaseRevision: snapshot.Revision, ExpiresAt: snapshot.ExpiresAt}
	attempt, cancel := context.WithDeadline(ctx, request.ExpiresAt)
	defer cancel()
	prepared, err := root.AuthorizeNetBirdIntent(attempt, request)
	if err != nil {
		return err
	}
	if prepared.Intent.IntentRevision != 0 || !prepared.Intent.IssuedAt.IsZero() ||
		!intentMatchesRequest(prepared.Intent, request) {
		return errors.New("root NetBird preparation differs from its original lease expectations")
	}
	wire, err := json.Marshal(prepared.Intent, json.Deterministic(true))
	if err != nil {
		return err
	}
	var previous uint64
	entry, err := control.ReadNetBirdIntent(attempt)
	if err == nil {
		previous = entry.Sequence
	} else if !errors.Is(err, authority.ErrNotFound) {
		return err
	}
	revision, err := control.CommitNetBirdIntent(attempt, snapshot.Epoch, request.OperationID, previous, wire, func(ctx context.Context) error {
		// Root rechecks its original source and lease; the outer log CAS orders
		// the resulting exact payload with every concurrent lease transition.
		current, err := root.AuthorizeNetBirdIntent(ctx, request)
		if err != nil {
			return err
		}
		actual, err := json.Marshal(current.Intent, json.Deterministic(true))
		if err != nil || !bytes.Equal(wire, actual) {
			return errors.New("NetBird source changed before the original commit")
		}
		return nil
	})
	if err != nil {
		return err
	}
	request.IntentRevision = revision
	_, err = root.AuthorizeNetBirdIntent(attempt, request)
	return err
}

func intentMatchesRequest(intent rootoci.NetBirdIntent, request rootoci.NetBirdIntentRequest) bool {
	return intent.Cell == request.Cell && intent.OperationID == request.OperationID && intent.RuntimeID == request.RuntimeID &&
		intent.OwnerID == request.OwnerID && intent.Epoch == request.Epoch && intent.LeaseRevision == request.LeaseRevision && intent.ExpiresAt.Equal(request.ExpiresAt)
}
