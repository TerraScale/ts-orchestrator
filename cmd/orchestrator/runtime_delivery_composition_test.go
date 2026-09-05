package main

import (
	"context"
	"crypto/ecdsa"
	"crypto/ed25519"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/x509"
	"errors"
	"io"
	"testing"
	"time"

	"github.com/nats-io/nats-server/v2/server"
	"github.com/nats-io/nats.go"
	"github.com/nats-io/nats.go/jetstream"
	"terrascale.tech/orchestrator/src/orchestrator/control"
	"terrascale.tech/orchestrator/src/orchestrator/delivery"
	"terrascale.tech/orchestrator/src/orchestrator/estate"
	"terrascale.tech/orchestrator/src/orchestrator/security"
)

func TestProductionDeliveryRequiresDelegationAndSharesVerifiedArtifactPath(t *testing.T) {
	config, spec, mirror := productionDeliveryFixture(t)
	missing := config
	missing.Delegation = nil
	if _, _, err := composeProductionDelivery(missing, spec, mirror); err == nil {
		t.Fatal("regional composition admitted bare delivery")
	}
	invalidMaster := *config.Master
	invalidMaster.Fetcher = nil
	missing = config
	missing.Master = &invalidMaster
	if _, _, err := composeProductionDelivery(missing, spec, mirror); err == nil {
		t.Fatal("master composition admitted a missing registry adapter")
	}
	regional, master, err := composeProductionDelivery(config, spec, mirror)
	if err != nil {
		t.Fatal(err)
	}
	if regional.Mirror != mirror || master.Mirror != mirror || regional.Trust() != config.Trust() || master.Trust() != config.Trust() || master.IntentVerifier != config.Delegation.IntentVerifier || regional.Delegation.MasterVerifier != config.Delegation.MasterVerifier {
		t.Fatal("composition split artifact preparation, release trust, or intent authority")
	}
	if master.Signer != config.Master.Signer || master.Fetcher != config.Master.Fetcher {
		t.Fatal("master lost explicit preparation or signing adapter")
	}
	config.Delegation.MasterVerifier = nil
	delete(config.Master.Regions, "gru")
	if regional.Delegation.MasterVerifier == nil || len(master.Regions) != 1 {
		t.Fatal("caller mutation changed admitted delegation or regional route map")
	}
}

func TestProductionDeliveryBindsOnlyExplicitGRUMaster(t *testing.T) {
	config, spec, mirror := productionDeliveryFixture(t)
	regional, master, err := composeProductionDelivery(config, spec, mirror)
	if err != nil {
		t.Fatal(err)
	}
	runtime := &productionRuntime{delivery: regional, masterDelivery: master}
	if err := runtime.BindGlobalDelivery(nil); err == nil {
		t.Fatal("master configuration was silently unused without a global runtime")
	}
	regionalOnly := &productionRuntime{delivery: regional}
	if err := regionalOnly.BindGlobalDelivery(nil); err != nil {
		t.Fatal(err)
	}
	global := &control.GlobalNatsRuntimeConfiguration{Cell: "gru", Authority: &control.GlobalAuthorityNatsConfiguration{Cell: "gru"}}
	if err := regionalOnly.BindGlobalDelivery(global); err == nil {
		t.Fatal("GRU started without explicit master adapters")
	}
	wrongRegion := &control.GlobalNatsRuntimeConfiguration{Cell: "sfo", Authority: &control.GlobalAuthorityNatsConfiguration{Cell: "sfo"}}
	if err := runtime.BindGlobalDelivery(wrongRegion); err == nil {
		t.Fatal("master delivery bound outside GRU")
	}
	if err := runtime.BindGlobalDelivery(global); err != nil {
		t.Fatal(err)
	}
	if !global.DeliveryEnabled || global.Delivery != master {
		t.Fatal("GRU global runtime did not receive admitted master adapters")
	}
	if err := runtime.BindGlobalDelivery(global); err == nil {
		t.Fatal("master delivery silently replaced an existing configuration")
	}
}

func productionDeliveryFixture(t *testing.T) (productionDeliveryConfig, estate.Spec, *delivery.ArtifactMirror) {
	t.Helper()
	broker, err := server.NewServer(&server.Options{Host: "127.0.0.1", Port: -1, NoSigs: true, JetStream: true, StoreDir: t.TempDir()})
	if err != nil {
		t.Fatal(err)
	}
	broker.Start()
	t.Cleanup(func() { broker.Shutdown(); broker.WaitForShutdown() })
	if !broker.ReadyForConnections(5 * time.Second) {
		t.Fatal("fixture broker unavailable")
	}
	nc, err := nats.Connect(broker.ClientURL())
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(nc.Close)
	js, err := jetstream.New(nc)
	if err != nil {
		t.Fatal(err)
	}
	leaders, err := js.CreateKeyValue(t.Context(), jetstream.KeyValueConfig{Bucket: "leaders", Storage: jetstream.FileStorage})
	if err != nil {
		t.Fatal(err)
	}
	signer, masterVerifier := compositionDeliverySigner(t)
	_, intentVerifier := compositionDeliverySigner(t)
	pub, _, err := ed25519.GenerateKey(rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	trust, err := delivery.NewTrustSet(map[string]ed25519.PublicKey{"release": pub})
	if err != nil {
		t.Fatal(err)
	}
	ports := compositionDeliveryPorts{}
	spec := estate.Default()
	mirror, err := delivery.NewArtifactMirror(spec, ports)
	if err != nil {
		t.Fatal(err)
	}
	return productionDeliveryConfig{
		Delegation: &control.MasterDeliveryAdmissionConfig{Connection: nc, Leaders: leaders, MasterVerifier: masterVerifier, IntentVerifier: intentVerifier},
		Trust:      func() *delivery.TrustSet { return trust },
		Rollout:    delivery.RolloutConfig{Hosts: ports, Control: ports, Edge: ports, KV: ports, Gates: []delivery.Gate{compositionDeliveryGate("health"), compositionDeliveryGate("catch-up")}},
		Master:     &productionMasterDeliveryConfig{Fetcher: ports, Signer: signer, Regions: map[string]control.RegionalDeliveryRoute{"gru": {Connection: nc, Leaders: leaders, MasterSignerKeyID: signer.PublicKeyID()}}, RequestTimeout: time.Second},
	}, spec, mirror
}

func compositionDeliverySigner(t *testing.T) (*security.CommandSignatureSigner, *security.CommandSignatureVerifier) {
	t.Helper()
	key, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	signer, err := security.NewCommandSignatureSignerFromKey(key)
	if err != nil {
		t.Fatal(err)
	}
	spki, err := x509.MarshalPKIXPublicKey(&key.PublicKey)
	if err != nil {
		t.Fatal(err)
	}
	verifier, err := security.NewCommandSignatureVerifierFromKeys([]security.CommandSignatureTrustKey{{KeyID: signer.PublicKeyID(), Algorithm: security.CommandSignatureAlgorithm, PublicKeySPKI: spki}})
	if err != nil {
		t.Fatal(err)
	}
	return signer, verifier
}

// Composition must not execute any provider or registry operation.
var errCompositionEffect = errors.New("composition attempted a live effect")

type compositionDeliveryPorts struct{}

func (compositionDeliveryPorts) Fetch(context.Context, *delivery.Request) ([]byte, []byte, error) {
	return nil, nil, errCompositionEffect
}
func (compositionDeliveryPorts) Put(context.Context, string, string, string, []byte) error {
	return errCompositionEffect
}
func (compositionDeliveryPorts) PutFenced(context.Context, string, string, string, []byte, delivery.OperationFence) error {
	return errCompositionEffect
}
func (compositionDeliveryPorts) Get(context.Context, string, string, string) (io.ReadCloser, delivery.ObjectIdentity, error) {
	return nil, delivery.ObjectIdentity{}, errCompositionEffect
}
func (compositionDeliveryPorts) Hosts(context.Context, string) ([]string, error) {
	return nil, errCompositionEffect
}
func (compositionDeliveryPorts) Cordon(context.Context, string, bool) error {
	return errCompositionEffect
}
func (compositionDeliveryPorts) DrainStatus(context.Context, string) (delivery.DrainReport, error) {
	return delivery.DrainReport{}, errCompositionEffect
}
func (compositionDeliveryPorts) Converge(context.Context, string, []byte) error {
	return errCompositionEffect
}
func (compositionDeliveryPorts) PromoteWorker(context.Context, string, string) error {
	return errCompositionEffect
}
func (compositionDeliveryPorts) PromoteSnippet(context.Context, string, string) error {
	return errCompositionEffect
}
func (compositionDeliveryPorts) PublishKV(context.Context, string, string) error {
	return errCompositionEffect
}

type compositionDeliveryGate string

func (g compositionDeliveryGate) Name() string { return string(g) }
func (compositionDeliveryGate) Check(context.Context, string, string) error {
	return errCompositionEffect
}

func productionMasterDeliveryFixture(t *testing.T) *control.MasterDeliveryRuntimeConfig {
	t.Helper()
	config, spec, mirror := productionDeliveryFixture(t)
	_, master, err := composeProductionDelivery(config, spec, mirror)
	if err != nil {
		t.Fatal(err)
	}
	return master
}
