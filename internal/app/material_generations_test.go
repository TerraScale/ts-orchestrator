package app

import (
	"crypto/ed25519"
	"crypto/rand"
	"encoding/base64"
	"strings"
	"testing"
	"time"

	"github.com/TerraScale/ts-orchestrator/internal/bootstrap"
	"github.com/TerraScale/ts-orchestrator/internal/bootstrap/generationtest"
	"github.com/TerraScale/ts-orchestrator/internal/bootstrapstart"
	"github.com/TerraScale/ts-orchestrator/internal/generationinstall"
	"github.com/TerraScale/ts-orchestrator/internal/natscell"
	"github.com/TerraScale/ts-orchestrator/internal/protocol"
	"github.com/TerraScale/ts-orchestrator/internal/trust"
)

// Any trusted signer reads the status; only can_install_material publishes
// or arms, and only a chain the cell's roots signed.
func TestMaterialGenerationRequestsNeedTheGrant(t *testing.T) {
	expected := bootstrap.MaterialGenerationExpectation{DeploymentID: "0000000000YY15F5R431V5JPJ9", Environment: "production",
		ClusterID: "00000000006GRRF84JEVN9TX7M", Cell: "GRU", ControllerSlots: []string{"controller-a", "controller-b", "controller-c"}}
	previous := materialGenerationTarget
	materialGenerationTarget = func() (bootstrapstart.GenerationTarget, error) {
		return bootstrapstart.GenerationTarget{Slot: "controller-a", Expected: expected}, nil
	}
	t.Cleanup(func() { materialGenerationTarget = previous })
	rootPublic, rootKey, _ := ed25519.GenerateKey(rand.Reader)
	genesis, _ := trust.ParseKeyring(rootPublic)
	roots, err := newRootRegistry(genesis, trust.ChainIdentity{DeploymentID: "0000000000YY15F5R431V5JPJ9", Cell: "gru",
		Environment: "production"}, trust.RootChain{Version: 1}, "")
	if err != nil {
		t.Fatal(err)
	}
	if err := roots.open(t.Context(), testRolloutJetStream(t), 1); err != nil {
		t.Fatal(err)
	}
	opsPublic, opsKey, _ := ed25519.GenerateKey(rand.Reader)
	ciPublic, ciKey, _ := ed25519.GenerateKey(rand.Reader)
	policy, err := buildSignerPolicy(Config{NATS: natscell.Config{Cell: "gru"},
		Controller: ControllerConfig{TrustedSigners: []TrustedSignerConfig{
			{Actor: "ops", PublicKey: base64.StdEncoding.EncodeToString(opsPublic), Roles: []string{"terrabase"},
				Environments: []string{"production"}, CanInstallMaterial: true},
			{Actor: "ci", PublicKey: base64.StdEncoding.EncodeToString(ciPublic), Roles: []string{"terrabase"},
				Environments: []string{"production"}}}}})
	if err != nil {
		t.Fatal(err)
	}
	now := time.Now()
	material := generationtest.New(t, now).WithoutIssuers(t).InterRegion(t, now, expected.ControllerSlots)
	signed, err := bootstrap.SignMaterialGeneration(material.Generation(expected, 1, ""), now.Add(-time.Minute),
		now.AddDate(0, 6, 0), rootKey)
	if err != nil {
		t.Fatal(err)
	}
	chain, _ := bootstrap.EncodeMaterialGenerationChain([]trust.Envelope{signed})
	stranger := generationtest.New(t, now)
	_, strangerKey, _ := ed25519.GenerateKey(rand.Reader)
	foreign, _ := bootstrap.SignMaterialGeneration(stranger.Generation(expected, 1, ""), now.Add(-time.Minute),
		now.AddDate(0, 6, 0), strangerKey)
	foreignChain, _ := bootstrap.EncodeMaterialGenerationChain([]trust.Envelope{foreign})
	request := func(actor string, kind string, payload materialGenerationRequest) (string, uint64, error) {
		t.Helper()
		key := map[string]ed25519.PrivateKey{"ops": opsKey, "ci": ciKey}[actor]
		signer := &rolloutRequester{t: t, key: key}
		wire := signer.sign(kind, payload, func(scope *protocol.EnvelopeScope, _ *time.Time) { scope.Actor = actor })
		report, err := serveMaterialGenerations(t.Context(), wire, policy, rolloutTestFence{epoch: 7}, roots)
		return report.Status, report.Generation, err
	}
	if _, _, err := request("ci", materialGenerationStatusKind, materialGenerationRequest{}); err != nil {
		t.Fatalf("status: %v", err)
	}
	if _, _, err := request("ci", materialGenerationPublishKind, materialGenerationRequest{Chain: chain}); err == nil ||
		!strings.Contains(err.Error(), "can_install_material") {
		t.Fatalf("publish without the grant: %v", err)
	}
	if _, _, err := request("ops", materialGenerationPublishKind, materialGenerationRequest{Chain: foreignChain}); err == nil {
		t.Fatal("published a chain another root signed")
	}
	if status, generation, err := request("ops", materialGenerationPublishKind,
		materialGenerationRequest{Chain: chain}); err != nil || status != "published" || generation != 1 {
		t.Fatalf("publish = %q %d %v", status, generation, err)
	}
	config := material.Files[bootstrapstart.GenerationConfigFile("controller-a")]
	if status, _, err := request("ops", materialGenerationConfigKind,
		materialGenerationRequest{Slot: "controller-a", Config: config}); err != nil || status != "stored" {
		t.Fatalf("config = %q %v", status, err)
	}
	if status, _, err := request("ops", materialGenerationArmKind,
		materialGenerationRequest{Slot: "controller-a", Armed: true}); err != nil || status != "armed" {
		t.Fatalf("arm = %q %v", status, err)
	}
	expired, err := bootstrap.SignMaterialGeneration(material.Generation(expected, 1, ""), now.Add(-time.Hour), now.Add(-time.Minute), rootKey)
	if err != nil {
		t.Fatal(err)
	}
	expiredChain, err := bootstrap.EncodeMaterialGenerationChain([]trust.Envelope{expired})
	if err != nil {
		t.Fatal(err)
	}
	record, err := protocol.EncodeJSON(generationinstall.Record{Chain: expiredChain, Configs: map[string][]byte{"controller-a": config}, Armed: []string{"controller-a"}})
	if err != nil {
		t.Fatal(err)
	}
	if _, err := roots.kv.Put(t.Context(), generationinstall.RecordKey, record); err != nil {
		t.Fatal(err)
	}
	if _, generation, err := request("ci", materialGenerationStatusKind, materialGenerationRequest{}); err != nil || generation != 1 {
		t.Fatalf("expired material status = %d, %v", generation, err)
	}
	if status, _, err := request("ops", materialGenerationArmKind, materialGenerationRequest{Slot: "controller-a"}); err != nil || status != "disarmed" {
		t.Fatalf("expired material disarm reported failure = %q, %v", status, err)
	}
	if _, _, err := request("ops", materialGenerationArmKind, materialGenerationRequest{Slot: "controller-a", Armed: true}); err == nil {
		t.Fatal("inspection restored expired installation authority")
	}
}
