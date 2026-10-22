package bootstrapstart

import (
	"bytes"
	"context"
	"crypto/rand"
	"crypto/rsa"
	"crypto/x509"
	"encoding/json/v2"
	"encoding/pem"
	"errors"
	"net/http"
	"net/http/httptest"
	"slices"
	"testing"
	"time"

	"github.com/TerraScale/ts-orchestrator/internal/bootstrap"
	"github.com/TerraScale/ts-orchestrator/internal/trust"
	"github.com/oracle/oci-go-sdk/v65/common"
	"github.com/oracle/oci-go-sdk/v65/core"
	"github.com/oracle/oci-go-sdk/v65/objectstorage"
)

// Readback crosses the existing real signed OCI SDK fixture. A transport tuple
// cannot convert its genuine ordinary seed history to original provenance.
func TestOriginalSeedRejectsOrdinarySDKHistoryPromotionIntegration(t *testing.T) {
	f := newOriginalSeedFixture(t)
	slot := f.founder.plan.SeedSlot
	scope := bootstrap.BootstrapScope{DeploymentID: f.founder.plan.DeploymentID, Cell: string(f.founder.plan.Cell), Slot: slot}
	state, err := f.sources.ledger.ReadSlot(t.Context(), scope)
	if err != nil {
		t.Fatal(err)
	}
	envelope, err := trust.DecodeEnvelope(state.ManifestRecord.Bytes)
	if err != nil {
		t.Fatal(err)
	}
	expected, err := f.founder.current.Anchor.ManifestExpectation(slot, state.Intent.ImageOCID)
	if err != nil {
		t.Fatal(err)
	}
	manifest, err := bootstrap.VerifyManifest(envelope, f.founder.baked.Roots, expected, time.Now().UTC(), bootstrap.ManifestTrustPolicy())
	if err != nil {
		t.Fatal(err)
	}
	observed, err := f.sources.observer.ObserveInstance(t.Context(), state.Result.InstanceOCID)
	if err != nil {
		t.Fatal(err)
	}
	if _, err := (Gate{Instances: f.sources.observer}).observe(t.Context(), observed.InstanceOCID, state, f.founder.current.Anchor.Anchor()); err != nil {
		t.Fatalf("ordinary signed SDK exact-instance result no longer verifies: %v", err)
	}
	before := bytes.Clone(state.IntentRecord.Bytes)
	promoted := state
	promoted.Intent.SchemaVersion = 2
	promoted.Intent.OriginalLaunch = new(bootstrap.OriginalLaunchIdentity{ActorOperationID: "0000000000NBCYX286D4RHE6ZP", InstanceOCID: observed.InstanceOCID})
	if _, err := VerifyExternalSeedObservation(f.founder.current.Anchor, manifest, promoted, observed, f.founder.plan.SeedPrivateIP); !errors.Is(err, ErrExternalSeedObservation) {
		t.Fatalf("ordinary manifest accepted original schema2 transport: %v", err)
	}
	wrongTag := observed
	wrongTag.BootstrapCreateKey = ""
	if _, err := VerifyExternalSeedObservation(f.founder.current.Anchor, manifest, state, wrongTag, f.founder.plan.SeedPrivateIP); !errors.Is(err, ErrExternalSeedObservation) {
		t.Fatalf("ordinary observation accepted absent actual create tag: %v", err)
	}
	var decoded bootstrap.Intent
	envelope, err = trust.DecodeEnvelope(before)
	if err != nil || json.Unmarshal(envelope.Payload, &decoded) != nil || decoded.SchemaVersion != 1 || decoded.OriginalLaunch != nil {
		t.Fatal("rejected promotion altered the original immutable intent")
	}
	journalCalls := 0
	if _, err := EnsureOriginalSeed(t.Context(), bootstrap.DerivedStartupAuthority{}, f.founder.ledgerKey, func(_ context.Context, _ *ExternalSeedCompletionRecords) (ExternalSeedCompletionRecords, error) {
		journalCalls++
		return ExternalSeedCompletionRecords{}, nil
	}); err == nil || journalCalls != 0 {
		t.Fatalf("unsealed original seed reached journal: calls=%d err=%v", journalCalls, err)
	}
}

// newOriginalSeedFixture builds only the seed's signed SDK history. The peer
// launches of newControllerRecipientFixture are not needed here, and under
// -race on a loaded runner their real-time work outlasted the 10s
// ManagedPeerObservationMaxAge window.
func newOriginalSeedFixture(t *testing.T) *controllerRecipientFixture {
	t.Helper()
	founder, _, objects, _ := newFounderRuntimeFixtureWithReservation(t,
		func(f *founderSignerFixture) { founderFixtureWithAdmissibleRelease(t, f) }, false)
	f := &controllerRecipientFixture{founder: founder, objects: objects,
		states: make(map[string]bootstrap.SlotState), live: make(map[string]InstanceObservation)}
	server := httptest.NewServer(http.HandlerFunc(f.serveHTTP))
	t.Cleanup(server.Close)
	key, err := rsa.GenerateKey(rand.Reader, 2048)
	if err != nil {
		t.Fatal(err)
	}
	private := pem.EncodeToMemory(&pem.Block{Type: "RSA PRIVATE KEY", Bytes: x509.MarshalPKCS1PrivateKey(key)})
	provider := common.NewRawConfigurationProvider("ocid1.tenancy.oc1..test", "ocid1.user.oc1..test",
		"sa-saopaulo-1", "test-fingerprint", string(private), nil)
	storage, err := objectstorage.NewObjectStorageClientWithConfigurationProvider(provider)
	if err != nil {
		t.Fatal(err)
	}
	compute, err := core.NewComputeClientWithConfigurationProvider(provider)
	if err != nil {
		t.Fatal(err)
	}
	network, err := core.NewVirtualNetworkClientWithConfigurationProvider(provider)
	if err != nil {
		t.Fatal(err)
	}
	for _, client := range []*common.BaseClient{&storage.BaseClient, &compute.BaseClient, &network.BaseClient} {
		client.Host, client.HTTPClient = server.URL, server.Client()
	}
	f.storage = &storage
	config, err := currentLedgerConfig(founder.current.Anchor, founder.baked.Roots)
	if err != nil {
		t.Fatal(err)
	}
	ledger, err := bootstrap.NewLedger(&storage, config)
	if err != nil {
		t.Fatal(err)
	}
	f.sources = controllerRecipientSources{trust: admissionTrustStore(t, founder.baked.Roots),
		ledger: ledger, observer: &OCIInstanceObserver{compute: &compute, network: &network}}
	f.completeSeed(t)
	slot := founder.plan.SeedSlot
	state, err := ledger.ReadSlot(t.Context(), bootstrap.BootstrapScope{
		DeploymentID: founder.plan.DeploymentID, Cell: string(founder.plan.Cell), Slot: slot})
	if err != nil {
		t.Fatal(err)
	}
	f.states[slot] = state
	f.live[state.Result.InstanceOCID] = InstanceObservation{InstanceOCID: state.Result.InstanceOCID,
		CompartmentOCID: state.Intent.CompartmentOCID, ImageOCID: state.Intent.ImageOCID,
		AvailabilityDomain: state.Intent.AvailabilityDomain, FaultDomain: state.Intent.FaultDomain,
		Shape: state.Intent.Shape, SubnetOCID: state.Intent.SubnetOCID,
		NSGOCIDs:         slices.Clone(state.Intent.NetworkSecurityGroupIDs),
		PrimaryVNICOCID:  "ocid1.vnic.oc1.sa-saopaulo-1." + slot,
		PrimaryPrivateIP: founder.plan.SeedPrivateIP, PrimaryVNIC: true, LifecycleState: "RUNNING"}
	return f
}
