package app

import (
	"bytes"
	"crypto/ed25519"
	"encoding/base64"
	"encoding/json/v2"
	"strings"
	"testing"
	"time"

	"github.com/TerraScale/ts-orchestrator/internal/entityid"
	"github.com/TerraScale/ts-orchestrator/internal/protocol"
)

func TestNodeOperationRequestVerifiesExactOriginalScope(t *testing.T) {
	key := ed25519.NewKeyFromSeed(bytes.Repeat([]byte{7}, ed25519.SeedSize))
	grant := TrustedSignerConfig{Actor: "operator", PublicKey: base64.StdEncoding.EncodeToString(key.Public().(ed25519.PublicKey)),
		Roles: []string{"terrabase"}, Environments: []string{"production"}, CanRegisterHosts: true}
	policy, err := buildSignerPolicy(Config{Controller: ControllerConfig{TrustedSigners: []TrustedSignerConfig{grant}}})
	if err != nil {
		t.Fatal(err)
	}
	now := time.Now().UTC().Truncate(time.Second)
	scope := protocol.EnvelopeScope{Region: "gru", Kind: nodeOpSubmitKind, Actor: "operator", OperationID: entityid.Derive("node-operation", "original"), Generation: 1, Epoch: 3}
	payload, err := protocol.EncodeJSON(nodeOpRequest{Node: "ctl-1", Op: nodeOpDrain})
	if err != nil {
		t.Fatal(err)
	}
	for name, change := range map[string]func(*protocol.EnvelopeScope, *time.Time, *time.Time){
		"original":             func(*protocol.EnvelopeScope, *time.Time, *time.Time) {},
		"other region":         func(s *protocol.EnvelopeScope, _, _ *time.Time) { s.Region = "iad" },
		"status kind":          func(s *protocol.EnvelopeScope, _, _ *time.Time) { s.Kind = nodeOpStatusKind },
		"successor generation": func(s *protocol.EnvelopeScope, _, _ *time.Time) { s.Generation = 2 },
		"successor epoch":      func(s *protocol.EnvelopeScope, _, _ *time.Time) { s.Epoch = 4 },
		"other actor":          func(s *protocol.EnvelopeScope, _, _ *time.Time) { s.Actor = "other" },
		"expired inside skew": func(_ *protocol.EnvelopeScope, issued, expires *time.Time) {
			*issued, *expires = now.Add(-time.Minute), now.Add(-time.Second)
		},
		"extended lifetime": func(_ *protocol.EnvelopeScope, _, expires *time.Time) { *expires = now.Add(2 * time.Minute) },
	} {
		t.Run(name, func(t *testing.T) {
			selected, issued, expires := scope, now, now.Add(time.Minute)
			change(&selected, &issued, &expires)
			envelope, err := protocol.SignEnvelope(payload, selected, issued, expires, key)
			if err != nil {
				t.Fatal(err)
			}
			wire, err := protocol.EncodeJSON(envelope)
			if err != nil {
				t.Fatal(err)
			}
			_, _, err = verifyNodeOperationRequest(wire, "gru", 3, policy, now)
			if (err == nil) != (name == "original") {
				t.Fatalf("verify %s: %v", name, err)
			}
			if name == "original" {
				grant.CanRegisterHosts = false
				revoked, err := buildSignerPolicy(Config{Controller: ControllerConfig{TrustedSigners: []TrustedSignerConfig{grant}}})
				if err != nil {
					t.Fatal(err)
				}
				if _, _, err := verifyNodeOperationRequest(wire, "gru", 3, revoked, now); err == nil {
					t.Fatal("revoked host-management grant admitted")
				}
				grant.CanRegisterHosts = true
				envelope.Signature = strings.Repeat("A", len(envelope.Signature))
				forged, err := protocol.EncodeJSON(envelope)
				if err != nil {
					t.Fatal(err)
				}
				if _, _, err := verifyNodeOperationRequest(forged, "gru", 3, policy, now); err == nil {
					t.Fatal("forged original admitted")
				}
			}
		})
	}
}

func TestNodeOperationOriginalJournalRejectsRebindingAndDeletion(t *testing.T) {
	ops, _, _ := newNodeOpsTest(t)
	ctx := t.Context()
	op, err := ops.submitTest(t, ctx, 3, "mariogk", entityid.Derive("node-operation", "immutable"), nodeOpRequest{Node: "ctl-1", Op: nodeOpReboot})
	if err != nil {
		t.Fatal(err)
	}
	entry, err := ops.fence.kv.Get(ctx, nodeOperationRequestKey(op.ID))
	if err != nil {
		t.Fatal(err)
	}
	var record nodeOperationRequestRecord
	if err := json.Unmarshal(entry.Value(), &record); err != nil {
		t.Fatal(err)
	}
	original := nodeOperationRequestReference{SHA256: op.RequestSHA256, Revision: op.RequestRevision}
	again, err := retainNodeOperationRequest(ctx, ops.fence.kv, op.ID, record)
	if err != nil || again != original {
		t.Fatalf("original retry changed: %+v %v", again, err)
	}
	retried, err := ops.submit(ctx, 3, op.Actor, op.ID, nodeOpRequest{Node: op.Node, Op: op.Op}, original)
	if err != nil || !retried.RequestedAt.Equal(op.RequestedAt) {
		t.Fatalf("first attempt changed: %+v %v", retried, err)
	}
	changed := record
	changed.Policy.SpecRevision++
	if _, err := retainNodeOperationRequest(ctx, ops.fence.kv, op.ID, changed); err == nil {
		t.Fatal("policy successor rebound original operation")
	}
	altered := op
	altered.Op = nodeOpUndrain
	if _, err := matchNodeOperationRequest(altered, record); err == nil {
		t.Fatal("unsigned progress selected a different action")
	}
	altered = op
	altered.RequestSHA256 = strings.Repeat("f", 64)
	if _, err := matchNodeOperationRequest(altered, record); err == nil {
		t.Fatal("unsigned progress replaced original digest")
	}
	// A descriptive phase can record an accepted result, but cannot erase it.
	op.ActedAt, op.Backup = time.Now().UTC(), "accepted-backup"
	if err := ops.save(ctx, 3, op); err != nil {
		t.Fatal(err)
	}
	altered = op
	altered.ActedAt, altered.Backup = time.Time{}, ""
	if err := ops.save(ctx, 3, altered); err == nil {
		t.Fatal("accepted receipt was erased")
	}
	if err := ops.fence.kv.Delete(ctx, nodeOperationRequestKey(op.ID)); err != nil {
		t.Fatal(err)
	}
	if _, err := retainNodeOperationRequest(ctx, ops.fence.kv, op.ID, record); err == nil {
		t.Fatal("deleted immutable original was recreated")
	}
	if _, err := ops.originalRequest(ctx, op); err == nil {
		t.Fatal("resume accepted missing original")
	}
}

func TestNodeOperationExpiredResumeDoesNotAct(t *testing.T) {
	ops, _, instances := newNodeOpsTest(t)
	ctx := t.Context()
	op, err := ops.submitTest(t, ctx, 3, "mariogk", entityid.Derive("node-operation", "expired"), nodeOpRequest{Node: "ctl-1", Op: nodeOpReboot})
	if err != nil {
		t.Fatal(err)
	}
	entry, err := ops.fence.kv.Get(ctx, nodeOperationRequestKey(op.ID))
	if err != nil {
		t.Fatal(err)
	}
	var record nodeOperationRequestRecord
	var envelope protocol.Envelope
	if err := json.Unmarshal(entry.Value(), &record); err != nil {
		t.Fatal(err)
	}
	if err := protocol.DecodeStrict(record.Wire, &envelope, maxRegistrationWireBytes); err != nil {
		t.Fatal(err)
	}
	envelope.IssuedAt, envelope.ExpiresAt = time.Now().Add(-2*time.Minute).UTC(), time.Now().Add(-time.Minute).UTC()
	record.Wire, err = protocol.EncodeJSON(envelope)
	if err != nil {
		t.Fatal(err)
	}
	wire, err := protocol.EncodeJSON(record)
	if err != nil {
		t.Fatal(err)
	}
	// Simulate tampered progress and archive together: even this unsigned resume
	// path must preserve the original expiry; root separately verifies signature.
	revision, err := ops.fence.kv.Put(ctx, nodeOperationRequestKey(op.ID), wire)
	if err != nil {
		t.Fatal(err)
	}
	op.RequestSHA256, op.RequestRevision = controllerSHA256(record.Wire), revision
	progress, err := protocol.EncodeJSON(op)
	if err != nil {
		t.Fatal(err)
	}
	if _, err := ops.fence.kv.Put(ctx, nodeOpKey(op.Node), progress); err != nil {
		t.Fatal(err)
	}
	if err := ops.pass(ctx); err != nil {
		t.Fatal(err)
	}
	if len(instances.calls) != 0 {
		t.Fatalf("expired request mutated compute: %v", instances.calls)
	}
	current := ops.operation(t, op.Node)
	if current.State != nodeOpFailed || !strings.Contains(current.Reason, "expired") {
		t.Fatalf("expired progress %+v", current)
	}
}
