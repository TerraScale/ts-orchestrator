package control

import (
	"bytes"
	"context"
	"crypto/ed25519"
	"crypto/rand"
	"encoding/json"
	"errors"
	"os"
	"testing"
	"time"

	"terrascale.tech/orchestrator/src/orchestrator/control/authority"
	"terrascale.tech/orchestrator/src/orchestrator/delivery"
	"terrascale.tech/orchestrator/src/orchestrator/estate"
)

type masterEdgeFixture struct {
	serving           bool
	applies, observes int
	afterApply        func() error
}

func (e *masterEdgeFixture) Observe(ctx context.Context, _ *delivery.Request, _ *delivery.ReleaseArtifact, fence delivery.OperationFence, check func(delivery.OperationFence) error) (bool, error) {
	e.observes++
	if err := check(fence); err != nil {
		return false, err
	}
	return e.serving, nil
}
func (e *masterEdgeFixture) Apply(ctx context.Context, _ *delivery.Request, _ *delivery.ReleaseArtifact, fence delivery.OperationFence, check func(delivery.OperationFence) error) error {
	if err := check(fence); err != nil {
		return err
	}
	e.applies++
	e.serving = true
	if e.afterApply != nil {
		return e.afterApply()
	}
	return errors.New("provider response lost")
}

func TestMasterGlobalEdgeDurableRecovery(t *testing.T) {
	for _, kind := range []string{"site", "package", "lease-loss"} {
		t.Run(kind, func(t *testing.T) {
			ctx, nc, js := masterTestNATS(t)
			leaders := masterTestKV(t, ctx, js, "edge_leaders")
			journal := masterTestKV(t, ctx, js, "edge_journal")
			global, err := authority.RegionalAuthorityCoordinatorStartGlobalAsync(ctx, leaders, "gru", "master")
			if err != nil {
				t.Fatal(err)
			}
			defer global.Dispose()
			signer, verifier := masterTestSigner(t)
			pub, priv, err := ed25519.GenerateKey(rand.Reader)
			if err != nil {
				t.Fatal(err)
			}
			trust, err := delivery.NewTrustSet(map[string]ed25519.PublicKey{"release": pub})
			if err != nil {
				t.Fatal(err)
			}
			body := []byte("verified edge module")
			mirror, err := delivery.NewArtifactMirror(estate.Default(), &masterMirrorFixture{})
			if err != nil {
				t.Fatal(err)
			}
			edge := &masterEdgeFixture{}
			cfg := MasterDeliveryConfig{Cell: "gru", Instance: "master", Connection: nc, Leaders: leaders, Journal: journal, Authority: global.Snapshot, Fetcher: &ingressReleaseFetcher{body: body, signature: ed25519.Sign(priv, body)}, Trust: func() *delivery.TrustSet { return trust }, Mirror: mirror, Signer: signer, IntentVerifier: verifier, GlobalEdge: edge, Regions: map[string]RegionalDeliveryRoute{}, RequestTimeout: time.Second}
			for _, cell := range []string{"gru", "sfo"} {
				cfg.Regions[cell] = RegionalDeliveryRoute{Connection: nc, Leaders: leaders, MasterSignerKeyID: signer.PublicKeyID()}
			}
			raw, err := os.ReadFile("../delivery/testdata/request-v1.json")
			if err != nil {
				t.Fatal(err)
			}
			request, err := delivery.ParseRequest(string(raw))
			if err != nil {
				t.Fatal(err)
			}
			request.OperationID = "global-edge-release"
			request.Target.Regions = []string{"gru", "sfo"}
			request.Artifact.Kind = kind
			if kind == "lease-loss" {
				request.Artifact.Kind = "site"
			}
			request.Rollback = nil
			request.Artifact.Digest = delivery.SHA256Digest(body)
			wire := masterGenerationWire(t, signer, request, global.Snapshot().Epoch, 1)
			live := true
			if kind == "lease-loss" {
				cfg.Authority = func() RegionalAuthoritySnapshot {
					if !live {
						return RegionalAuthoritySnapshot{}
					}
					return global.Snapshot()
				}
				edge.afterApply = func() error { live = false; return nil }
			}
			master, err := NewMasterDelivery(ctx, cfg)
			if err != nil {
				t.Fatal(err)
			}
			receipt, err := master.Submit(ctx, wire)
			if err == nil || receipt == nil || receipt.Complete || len(receipt.Regions) != 0 || edge.applies != 1 {
				t.Fatalf("unknown result: %+v %v applies=%d", receipt, err, edge.applies)
			}
			saved, err := master.store.Get(masterRecordKey(request.OperationID))
			if err != nil {
				t.Fatal(err)
			}
			var record masterDeliveryRecord
			if json.Unmarshal(saved.Value, &record) != nil || !bytes.Equal(record.OriginalEnvelope, wire) || record.GlobalEdge == nil || record.GlobalEdge.Attempt != 1 || record.GlobalEdge.Accepted || len(record.Children) != 0 {
				t.Fatalf("durable lineage lost: %+v", record)
			}
			live = true
			master, err = NewMasterDelivery(ctx, cfg)
			if err != nil {
				t.Fatal(err)
			}
			receipt, err = master.Submit(ctx, wire)
			if err != nil || !receipt.Complete || edge.applies != 1 || edge.observes != 2 || receipt.GlobalEdge == nil || receipt.GlobalEdge.OperationID != request.OperationID || receipt.GlobalEdge.PayloadDigest != record.PayloadDigest || receipt.GlobalEdge.ArtifactDigest != request.Artifact.Digest {
				t.Fatalf("recovery: %+v %v applies=%d observes=%d", receipt, err, edge.applies, edge.observes)
			}
		})
	}
}
