package budget

import (
	"cmp"
	"context"
	"crypto/ed25519"
	"crypto/rand"
	"crypto/rsa"
	"crypto/sha256"
	"crypto/x509"
	"encoding/hex"
	"encoding/pem"
	"errors"
	"net/http"
	"net/http/httptest"
	"path/filepath"
	"slices"
	"strings"
	"testing"
	"time"

	"github.com/TerraScale/ts-orchestrator/internal/authority"
	"github.com/TerraScale/ts-orchestrator/internal/bootstrap"
	"github.com/TerraScale/ts-orchestrator/internal/entityid"
	"github.com/TerraScale/ts-orchestrator/internal/globalcontrol"
	"github.com/TerraScale/ts-orchestrator/internal/oci"
	"github.com/TerraScale/ts-orchestrator/internal/ociclient"
	"github.com/TerraScale/ts-orchestrator/internal/ociregion/capacityinventory"
	"github.com/TerraScale/ts-orchestrator/internal/protocol"
	"github.com/TerraScale/ts-orchestrator/internal/region"
	"github.com/TerraScale/ts-orchestrator/internal/trust"
	"github.com/nats-io/nats-server/v2/server"
	"github.com/nats-io/nats.go"
	"github.com/nats-io/nats.go/jetstream"
	"github.com/oracle/oci-go-sdk/v65/common"
)

func TestSignedSpendingAuthorityDeniesCanceledObservation(t *testing.T) {
	ctx, cancel := context.WithTimeout(t.Context(), 30*time.Second)
	defer cancel()
	writer, _, epoch := reservationStoreHome(t, ctx)
	now := time.Now().UTC().Truncate(time.Second)
	public, private, err := ed25519.GenerateKey(rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	roots, err := trust.ParseKeyring(public)
	if err != nil {
		t.Fatal(err)
	}
	deployment, cluster, installation := entityid.New(), entityid.New(), entityid.New()
	const tenancy = "ocid1.tenancy.oc1..integration"
	const parent = "ocid1.compartment.oc1..parent"
	const shared = "ocid1.compartment.oc1..shared"
	grant := region.FoundationGrant{InstallationID: installation, SchemaVersion: 1, Generation: 1, TenancyID: tenancy,
		ParentCompartmentID: parent, SharedCompartmentID: shared, Currency: "USD", MonthlyLimitMinor: 10000, CleanupOwner: "integration",
		Regions: []region.FoundationIntent{{Generation: 1, Plan: map[string]any{"cell": "GRU", "region": "sa-saopaulo-1", "tenancy_id": tenancy,
			"parent_compartment_id": parent, "shared_compartment_id": shared, "resource_ids": map[string]any{
				"control_compartment": "ocid1.compartment.oc1..control", "network_compartment": "ocid1.compartment.oc1..network", "workload_compartment": "ocid1.compartment.oc1..workload"}}}}}
	scopeDigest, err := region.FoundationInfrastructureScopeDigest(grant)
	if err != nil {
		t.Fatal(err)
	}
	grant.InfrastructureSpend = &region.InfrastructureSpendIntent{BudgetID: entityid.New(), Currency: "USD", MonthlyLimitMinor: 9000, ScopeSHA256: scopeDigest}
	payload, err := trust.EncodePayload(grant)
	if err != nil {
		t.Fatal(err)
	}
	envelope, err := trust.Sign(payload, trust.Scope{Domain: "terrascale.foundation.scope", DeploymentID: deployment, Cell: "GRU", Environment: "production", Role: "foundation", Slot: cluster}, now.Add(-time.Minute), now.Add(30*time.Minute), private)
	if err != nil {
		t.Fatal(err)
	}
	grantWire, err := trust.EncodeEnvelope(envelope)
	if err != nil {
		t.Fatal(err)
	}
	grantDigest := sha256.Sum256(grantWire)
	store := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.Method != http.MethodGet || r.Header.Get("Authorization") == "" || !strings.HasSuffix(r.URL.Path, "/bootstrap/foundation-scope-v1.json") {
			t.Errorf("unexpected or unsigned grant read: %s %s", r.Method, r.URL.Path)
			http.Error(w, "invalid grant request", http.StatusBadRequest)
			return
		}
		_, _ = w.Write(grantWire)
	}))
	defer store.Close()
	key, err := rsa.GenerateKey(rand.Reader, 2048)
	if err != nil {
		t.Fatal(err)
	}
	provider := common.NewRawConfigurationProvider(tenancy, "ocid1.user.oc1..integration", "sa-saopaulo-1", "integration",
		string(pem.EncodeToMemory(&pem.Block{Type: "RSA PRIVATE KEY", Bytes: x509.MarshalPKCS1PrivateKey(key)})), nil)
	factory, err := ociclient.New(provider, ociclient.Options{Region: "sa-saopaulo-1", Retry: ociclient.RetryOptions{MaxAttempts: 1}})
	if err != nil {
		t.Fatal(err)
	}
	objects, err := factory.ObjectStorage()
	if err != nil {
		t.Fatal(err)
	}
	objects.Host = store.URL
	domain := bootstrap.StorageDomain{Namespace: "integration", LedgerBucket: "ledger", HeadBucket: "heads", Prefix: "bootstrap",
		LedgerKMSKeyOCID: "ocid1.key.oc1.sa-saopaulo-1.ledger", HeadKMSKeyOCID: "ocid1.key.oc1.sa-saopaulo-1.head"}
	ledgerPublic, _, err := ed25519.GenerateKey(rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	ledgerKeyID, err := trust.KeyID(ledgerPublic)
	if err != nil {
		t.Fatal(err)
	}
	ledgerPublicWire, err := trust.EncodeDelegatedPublicKey(ledgerPublic)
	if err != nil {
		t.Fatal(err)
	}
	var capabilities []trust.Capability
	for _, name := range []string{"bootstrap-slot-head", "bootstrap-intent", "bootstrap-result", "bootstrap-candidate", "bootstrap-progress"} {
		capabilities = append(capabilities, trust.Capability{Domain: name, DeploymentID: deployment, Cell: "GRU", Environment: "production", Role: "controller", Slots: []string{"controller-a"}, Actions: []string{"sign"}})
	}
	ledgerGrant, err := trust.SignDelegation(trust.Delegation{SchemaVersion: trust.SchemaVersion, SubjectKeyID: ledgerKeyID, SubjectPublicKey: ledgerPublicWire, Capabilities: capabilities}, now.Add(-2*time.Minute), now.Add(2*time.Hour), private)
	if err != nil {
		t.Fatal(err)
	}
	ledgerWire, err := trust.EncodeEnvelope(ledgerGrant)
	if err != nil {
		t.Fatal(err)
	}
	intentWire, err := trust.EncodePayload(oci.RegionIntent{SchemaVersion: 1, Generation: 1, BootstrapRegion: oci.RegionGRU, Regions: []oci.RegionMapping{{Cell: oci.RegionGRU, OCIRegion: "sa-saopaulo-1"}}})
	if err != nil {
		t.Fatal(err)
	}
	intentDigest := sha256.Sum256(intentWire)
	anchor := bootstrap.BootstrapAnchor{SchemaVersion: bootstrap.BootstrapAnchorSchemaVersion, DeploymentID: deployment, Environment: "production", ClusterID: cluster,
		Cell: oci.RegionGRU, OCIRegion: "sa-saopaulo-1", StorageDomain: domain, ControllerSlots: []string{"controller-a"}, LedgerDelegationWire: ledgerWire,
		InitialRegionIntentGeneration: 1, InitialRegionIntentSHA256: hex.EncodeToString(intentDigest[:]), InitialRegionIntentWire: intentWire,
		FoundationScope: &bootstrap.FoundationScope{InstallationID: installation, DeploymentID: deployment, ClusterID: cluster, TenancyID: tenancy, OCIRegion: "sa-saopaulo-1", StorageDomain: domain, GrantGeneration: 1, GrantSHA256: hex.EncodeToString(grantDigest[:])}}
	signedAnchor, err := bootstrap.SignBootstrapAnchor(anchor, now.Add(-time.Minute), now.Add(time.Hour), private)
	if err != nil {
		t.Fatal(err)
	}
	verifiedAnchor, err := bootstrap.VerifyBootstrapAnchor(signedAnchor, roots, bootstrap.BootstrapAnchorExpectation{DeploymentID: deployment, Environment: "production", Cell: oci.RegionGRU}, now, bootstrap.BootstrapAnchorTrustPolicy())
	if err != nil {
		t.Fatal(err)
	}
	signed, err := region.NewSignedFootprint(&objects, verifiedAnchor, roots, tenancy)
	if err != nil {
		t.Fatal(err)
	}
	proof, err := signed.InfrastructureSpend(ctx)
	if err != nil || !proof.ValidAt(time.Now()) {
		t.Fatalf("signed infrastructure authority was not verified: %v", err)
	}
	inventory, err := capacityinventory.New(factory)
	if err != nil {
		t.Fatal(err)
	}
	observationCtx, stop := context.WithCancel(ctx)
	stop()
	snapshot, err := inventory.Read(observationCtx, proof.Footprint())
	if err != nil || len(snapshot.Pending) == 0 {
		t.Fatalf("canceled SDK observation must retain unknown cost: pending=%v err=%v", snapshot.Pending, err)
	}
	headroom, err := InfrastructureHeadroom(ctx, &writer.Reader, proof, snapshot, entityid.New(), time.Now())
	if err == nil || headroom != 0 || !strings.Contains(err.Error(), "incomplete") {
		t.Fatalf("signed authority with canceled observation admitted capacity: headroom=%d err=%v", headroom, err)
	}
	if _, found, err := ReadCapacity(ctx, &writer.Reader); err != nil || found {
		t.Fatalf("denied observation created a commitment: found=%v err=%v", found, err)
	}
	demand := []Region{{Cell: "gru", Nodes: 1, Want: 2, Pressure: .9, At: time.Now(), NodeMonthlyCents: 1, ProjectedCents: 0, Currency: "USD"}}
	held, err := AllocateInfrastructure(ctx, &writer.Reader, proof, snapshot, demand, nil, time.Now())
	if err == nil || !strings.Contains(err.Error(), "incomplete") || held.State != StateNone || held.Regions[0].Allowance != 1 || !held.Regions[0].GrantedAt.IsZero() {
		t.Fatalf("signed planning with canceled costs trusted regional prices: capacity=%+v err=%v", held, err)
	}
	if err := WriteCapacity(ctx, writer, epoch, held); err != nil {
		t.Fatal(err)
	}
	persisted, found, err := ReadCapacity(ctx, &writer.Reader)
	if err != nil || !found || persisted.Regions[0].Allowance != 1 || len(persisted.Reservations) != 0 {
		t.Fatalf("failed planning did not persist a hold: %+v found=%v err=%v", persisted, found, err)
	}
	monthly := Budget{Schema: Schema, ID: entityid.New(), MonthlyCapCents: 1000, Currency: "USD", SetBy: "integration", SetAt: time.Now()}
	if err := WriteBudget(ctx, writer, epoch, monthly); err != nil {
		t.Fatal(err)
	}
	held, err = AllocateInfrastructure(ctx, &writer.Reader, proof, snapshot, demand, &persisted, time.Now())
	if err == nil || held.Regions[0].Allowance != 1 || len(held.Reservations) != 0 {
		t.Fatalf("tenant budget bypassed incomplete infrastructure evidence: %+v err=%v", held, err)
	}
	held, err = AllocateInfrastructure(ctx, &writer.Reader, region.VerifiedInfrastructureSpend{}, capacityinventory.Snapshot{}, demand, &persisted, time.Now())
	if err == nil || !strings.Contains(err.Error(), "signed infrastructure") || held.State != StateNone || held.Regions[0].Allowance != 1 {
		t.Fatalf("tenant budget replaced missing signed spending authority: %+v err=%v", held, err)
	}
}

// This exercises persisted commitments, not spending admission: no fixture can
// manufacture the complete accounting evidence the production producer lacks.
func TestReservationLedgerSurvivesPeriodicWritesThroughHomeCAS(t *testing.T) {
	ctx, cancel := context.WithTimeout(t.Context(), 30*time.Second)
	defer cancel()
	writer, concurrent, epoch := reservationStoreHome(t, ctx)
	now := time.Now().UTC()
	monthly := Budget{Schema: Schema, ID: entityid.New(), MonthlyCapCents: 1000, Currency: "USD", SetBy: "integration", SetAt: now}
	if err := WriteBudget(ctx, writer, epoch, monthly); err != nil {
		t.Fatal(err)
	}
	regions := []Region{
		{Cell: "gru", Nodes: 1, Want: 2, Pressure: .9, NodeMonthlyCents: 300, ProjectedCents: 100, Currency: "USD", At: now},
		{Cell: "sfo", Nodes: 1, Want: 2, Pressure: .5, NodeMonthlyCents: 300, ProjectedCents: 100, Currency: "USD", At: now},
	}
	allocated := Allocate(&monthly, regions, nil, now)
	if err := WriteCapacity(ctx, writer, epoch, allocated); err != nil {
		t.Fatal(err)
	}
	persisted, found, err := ReadCapacity(ctx, &writer.Reader)
	if err != nil || !found || persisted.ProjectedCents != 800 || persisted.Headroom() != 200 || persisted.State != StateWarn {
		t.Fatalf("new grants must count in persisted headroom: %+v, found=%v, err=%v", persisted, found, err)
	}
	seed := Reservation{OperationID: entityid.New(), RecipeSHA256: strings.Repeat("a", 64), Cell: "gru", CompartmentID: "ocid1.compartment.oc1..integration",
		Shape: "VM.Standard.A1.Flex", OCPUs: 2, MemoryGB: 4, BootGB: 50, MonthlyCents: 300, BudgetID: monthly.ID,
		InfrastructureBudgetID: entityid.New(), GrantSHA256: strings.Repeat("b", 64), ScopeSHA256: strings.Repeat("c", 64),
		IssuedAt: now.Add(-time.Hour), LaunchExpiresAt: now.Add(-30 * time.Minute)}
	appendCommitment := func(reservation Reservation) error {
		for range 32 {
			current, found, err := ReadCapacity(ctx, &concurrent.Reader)
			if err != nil || !found {
				return errors.Join(err, errors.New("capacity ledger unavailable"))
			}
			expected, err := current.Encode()
			if err != nil {
				return err
			}
			current.Reservations = append(current.Reservations, reservation)
			slices.SortFunc(current.Reservations, func(a, b Reservation) int { return cmp.Compare(a.OperationID, b.OperationID) })
			var commitments uint64
			for _, receipt := range current.Reservations {
				commitments += receipt.MonthlyCents
			}
			current.Spending = &InfrastructureSpending{InfrastructureBudgetID: seed.InfrastructureBudgetID, GrantSHA256: seed.GrantSHA256, ScopeSHA256: seed.ScopeSHA256,
				Currency: "USD", MonthlyLimitCents: 1000, ProjectedCents: commitments, ObservedAt: now.Add(-time.Hour), ExpiresAt: now.Add(-59 * time.Minute)}
			payload, err := current.Encode()
			if err != nil {
				return err
			}
			_, err = concurrent.PutDocument(ctx, epoch, globalcontrol.KindCapacity, protocol.GlobalScope, payload, func(stored []byte) error {
				if !sameCapacity(stored, expected) {
					return globalcontrol.ErrConflict
				}
				return nil
			})
			if errors.Is(err, globalcontrol.ErrConflict) {
				continue
			}
			return err
		}
		return globalcontrol.ErrConflict
	}
	if err := appendCommitment(seed); err != nil {
		t.Fatal(err)
	}
	// The caller's stale allocation predates the stored, already-expired receipt.
	if err := WriteCapacity(ctx, writer, epoch, allocated); err != nil {
		t.Fatal(err)
	}
	start := make(chan struct{})
	results := make(chan error, 2)
	second := seed
	second.OperationID = entityid.New()
	go func() {
		<-start
		results <- appendCommitment(second)
	}()
	go func() {
		<-start
		for range 16 {
			if err := WriteCapacity(ctx, writer, epoch, allocated); err != nil {
				results <- err
				return
			}
		}
		results <- nil
	}()
	close(start)
	for range 2 {
		if err := <-results; err != nil {
			t.Fatal(err)
		}
	}
	persisted, found, err = ReadCapacity(ctx, &writer.Reader)
	if err != nil || !found || len(persisted.Reservations) != 2 {
		t.Fatalf("concurrent periodic write erased commitments: %+v, found=%v, err=%v", persisted, found, err)
	}
	for _, candidate := range []Capacity{
		Allocate(nil, regions, &persisted, now.Add(2*time.Hour)),
		Allocate(&monthly, regions, &persisted, now.Add(StatusMaxAge+time.Minute)),
	} {
		if err := WriteCapacity(ctx, writer, epoch, candidate); err != nil {
			t.Fatal(err)
		}
		stored, found, err := ReadCapacity(ctx, &writer.Reader)
		if err != nil || !found || len(stored.Reservations) != 2 || stored.Spending == nil || stored.Spending.ProjectedCents != 600 {
			t.Fatalf("unknown budget/spend or expired launch released commitments: %+v, found=%v, err=%v", stored, found, err)
		}
		for _, receipt := range stored.Reservations {
			if receipt.MonthlyCents != 300 || !receipt.RetiredAt.IsZero() || len(receipt.ResourceIDs) != 0 {
				t.Fatalf("unknown outcome was changed or retired: %+v", receipt)
			}
		}
	}
}

func reservationStoreHome(t *testing.T, ctx context.Context) (*globalcontrol.Writer, *globalcontrol.Writer, uint64) {
	t.Helper()
	broker, err := server.NewServer(&server.Options{Host: "127.0.0.1", Port: -1, JetStream: true, StoreDir: filepath.Join(t.TempDir(), "jetstream")})
	if err != nil {
		t.Fatal(err)
	}
	go broker.Start()
	if !broker.ReadyForConnections(5 * time.Second) {
		t.Fatal("NATS did not start")
	}
	t.Cleanup(func() { broker.Shutdown(); broker.WaitForShutdown() })
	conn, err := nats.Connect(broker.ClientURL())
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(conn.Close)
	js, err := jetstream.New(conn)
	if err != nil {
		t.Fatal(err)
	}
	runtime, err := authority.Start(ctx, js, authority.Config{DeploymentID: entityid.New(), Scope: protocol.GlobalScope, CandidateID: entityid.New(), Replicas: 1,
		LeaseDuration: 5 * time.Second, RenewInterval: 500 * time.Millisecond})
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = runtime.Close() })
	for !runtime.Current().CanMutate() {
		select {
		case <-ctx.Done():
			t.Fatal("global authority never became ready")
		case <-time.After(20 * time.Millisecond):
		}
	}
	writer, err := globalcontrol.OpenHome(ctx, js, "gru", nil, 1, runtime)
	if err != nil {
		t.Fatal(err)
	}
	concurrent, err := globalcontrol.OpenHome(ctx, js, "gru", nil, 1, runtime)
	if err != nil {
		t.Fatal(err)
	}
	return writer, concurrent, runtime.Current().Epoch
}
