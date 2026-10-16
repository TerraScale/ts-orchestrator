package swarmruntime

import (
	"bytes"
	"context"
	"crypto/ed25519"
	"crypto/rand"
	"crypto/sha256"
	"encoding/base64"
	"fmt"
	"io"
	"strings"
	"testing"
	"time"

	"github.com/TerraScale/ts-orchestrator/internal/release"
	"github.com/TerraScale/ts-orchestrator/internal/trust"
	"github.com/moby/swarmkit/v2/api"
)

func TestSignedReleaseRaftIntegration(t *testing.T) {
	ctx, cancel := context.WithTimeout(t.Context(), 100*time.Second)
	defer cancel()
	cfg := serviceConfig(t, "ts-gru-1", "manager")
	node, err := StartNode(ctx, cfg, serviceExecutor{})
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() {
		stopCtx, cancel := context.WithTimeout(context.Background(), 15*time.Second)
		defer cancel()
		if err := node.Stop(stopCtx); err != nil {
			t.Errorf("stop signed release fixture: %v", err)
		}
	})
	client, err := node.ControlClient(ctx)
	if err != nil {
		t.Fatal(err)
	}
	if _, err := AdmitNode(ctx, client, node.ID(), cfg.Admission); err != nil {
		t.Fatal(err)
	}
	public, key, err := ed25519.GenerateKey(rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	keyID, _ := trust.KeyID(public)
	roots := trust.Keyring{keyID: public}
	now := time.Now().UTC().Truncate(time.Second)
	migration := release.SequenceMigration{Schema: release.SequenceMigrationSchema, Namespace: "test", Bucket: "gru-1-head", Region: "GRU", SignerKeyID: keyID, SignerPublicKey: base64.RawURLEncoding.EncodeToString(public), Role: "ts-auth", Environment: "production", SequenceFloor: 100}
	for _, cell := range []string{"GRU", "SFO", "FRA"} {
		migration.Regions = append(migration.Regions, release.SequenceFloor{Cell: cell, RunNumber: 100, EvidenceSHA256: strings.Repeat("1", 64)})
	}
	migrationEnvelope, err := release.SignSequenceMigration(migration, now, key)
	if err != nil {
		t.Fatal(err)
	}
	migrationWire, _ := trust.EncodeEnvelope(migrationEnvelope)
	migrationSHA, _ := trust.Fingerprint(migrationEnvelope)
	intent := serviceIntent()
	evidence := []byte("retained exact candidate integration evidence")
	evidenceSHA := fmt.Sprintf("%x", sha256.Sum256(evidence))
	readEvidence := func(context.Context, string) (io.ReadCloser, error) {
		return io.NopCloser(bytes.NewReader(evidence)), nil
	}
	bundle := func(sequence uint64, source string) release.ContainerBundle {
		t.Helper()
		candidate := release.ProductionExpectation{SourceRevision: source, ArtifactSHA256: strings.Repeat("a", 64), QualificationSHA256: strings.Repeat("b", 64), Cell: "GRU", Environment: "production", Runtime: release.ProductionRuntime, Architecture: intent.Architecture, Role: intent.Role}
		qualification := release.ProductionQualification{Schema: release.ProductionQualificationSchema, Candidate: candidate, Evidence: []release.ProductionGateEvidence{{Gate: "runtime-ha", SHA256: evidenceSHA, Bytes: int64(len(evidence)), CompletedAt: now}, {Gate: "workload-safety", SHA256: evidenceSHA, Bytes: int64(len(evidence)), CompletedAt: now}}}
		payload, _ := trust.EncodePayload(qualification)
		proof, err := trust.Sign(payload, release.ProductionQualificationScope(candidate), now, now.Add(time.Hour), key)
		if err != nil {
			t.Fatal(err)
		}
		proofWire, _ := trust.EncodeEnvelope(proof)
		claim := release.ContainerClaim{Schema: release.ContainerClaimSchema, Image: intent.Container.Image, SourceRevision: source, Cell: "GRU", Environment: intent.Environment, Role: intent.Role, Architecture: intent.Architecture, ReleaseSequence: sequence, SequenceMigrationSHA256: migrationSHA, QualificationSHA256: candidate.QualificationSHA256, Production: release.ProductionProof{Qualification: proofWire}}
		payload, _ = trust.EncodePayload(claim)
		signed, err := trust.Sign(payload, release.ContainerScope(release.ContainerTarget{Cell: "GRU", Environment: intent.Environment, Role: intent.Role, Architecture: intent.Architecture}), now, now.Add(time.Hour), key)
		if err != nil {
			t.Fatal(err)
		}
		wire, _ := trust.EncodeEnvelope(signed)
		return release.ContainerBundle{Claim: wire, Migration: migrationWire}
	}
	legacy := release.SequenceFloor{Cell: "GRU", RunNumber: 100, EvidenceSHA256: strings.Repeat("1", 64)}
	first := bundle(101, strings.Repeat("c", 40))
	tooNew := legacy
	tooNew.RunNumber = 101
	if _, err := ApplySignedService(ctx, client, intent, first, roots, tooNew, readEvidence); err == nil {
		t.Fatal("migration erased retained legacy floor")
	}
	created, err := ApplySignedService(ctx, client, intent, first, roots, legacy, readEvidence)
	if err != nil {
		t.Fatal(err)
	}
	serviceEventually(t, ctx, func() bool {
		view, err := ObserveService(ctx, client, created.ID, nil)
		return err == nil && view.RunningReplicas == 1
	})
	replayed, err := ApplySignedService(ctx, client, intent, first, roots, legacy, readEvidence)
	if err != nil || replayed.ID != created.ID {
		t.Fatalf("signed replay not idempotent: %+v %v", replayed, err)
	}
	if _, err := ApplySignedService(ctx, client, intent, bundle(101, strings.Repeat("d", 40)), roots, legacy, readEvidence); err == nil {
		t.Fatal("same signed sequence admitted different provenance")
	}
	second := bundle(102, strings.Repeat("c", 40))
	intent.Container = intent.Container.Copy()
	intent.Container.Args = []string{"reject"}
	if _, err := ApplySignedService(ctx, client, intent, second, roots, legacy, readEvidence); err != nil {
		t.Fatal(err)
	}
	serviceEventually(t, ctx, func() bool {
		response, err := client.GetService(ctx, &api.GetServiceRequest{ServiceID: created.ID})
		return err == nil && response.Service.UpdateStatus != nil && response.Service.UpdateStatus.State == api.UpdateStatus_ROLLBACK_COMPLETED
	})
	if _, err := ApplySignedService(ctx, client, intent, first, roots, legacy, readEvidence); err == nil {
		t.Fatal("automatic rollback reset durable sequence floor")
	}
	if _, err := ApplySignedService(ctx, client, intent, second, roots, legacy, readEvidence); err == nil {
		t.Fatal("known failed release started rolling again")
	}
	configs, err := client.ListConfigs(ctx, &api.ListConfigsRequest{})
	if err != nil || len(configs.Configs) != 1 {
		t.Fatalf("durable release evidence: %+v %v", configs, err)
	}
	if !bytes.Equal(configs.Configs[0].Spec.Data, migrationWire) || configs.Configs[0].Spec.Annotations.Labels["terrascale.legacy-evidence"] != legacy.EvidenceSHA256 || configs.Configs[0].Spec.Annotations.Labels[labelReleaseSequence] != "102" {
		t.Fatal("legacy signed provenance or high-water was lost")
	}
	stopCtx, stopCancel := context.WithTimeout(context.Background(), 15*time.Second)
	err = node.Stop(stopCtx)
	stopCancel()
	if err != nil {
		t.Fatal(err)
	}
	node, err = StartNode(ctx, cfg, serviceExecutor{})
	if err != nil {
		t.Fatal(err)
	}
	client, err = node.ControlClient(ctx)
	if err != nil {
		t.Fatal(err)
	}
	if _, err := ApplySignedService(ctx, client, intent, first, roots, legacy, readEvidence); err == nil {
		t.Fatal("manager restart reset durable ordering floor")
	}
	intent.Container.Args = nil
	if _, err := ApplySignedService(ctx, client, intent, bundle(103, strings.Repeat("c", 40)), roots, legacy, readEvidence); err != nil {
		t.Fatal("new signed release after rollback: ", err)
	}
}
