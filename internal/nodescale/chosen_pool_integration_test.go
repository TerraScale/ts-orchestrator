package nodescale

import (
	"context"
	"crypto/ed25519"
	"crypto/rand"
	"crypto/x509"
	"encoding/base64"
	"encoding/json/v2"
	"encoding/pem"
	"errors"
	"math/big"
	"slices"
	"strings"
	"testing"
	"time"

	"github.com/nats-io/nkeys"
	"github.com/oracle/oci-go-sdk/v65/core"

	"github.com/TerraScale/ts-orchestrator/internal/authority"
	"github.com/TerraScale/ts-orchestrator/internal/budget"
	"github.com/TerraScale/ts-orchestrator/internal/decisionlog"
	"github.com/TerraScale/ts-orchestrator/internal/entityid"
	"github.com/TerraScale/ts-orchestrator/internal/hostboot"
	"github.com/TerraScale/ts-orchestrator/internal/hostenroll"
	"github.com/TerraScale/ts-orchestrator/internal/rootoci"
)

// This public enrollment bundle allows request preparation, never root admission.
func capacityEnrollmentRecipe(t *testing.T) Recipe {
	t.Helper()
	public, private, err := ed25519.GenerateKey(rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	now := time.Now()
	certificate := &x509.Certificate{SerialNumber: big.NewInt(1), IsCA: true, BasicConstraintsValid: true,
		KeyUsage: x509.KeyUsageCertSign, NotBefore: now.Add(-time.Hour), NotAfter: now.Add(time.Hour)}
	der, err := x509.CreateCertificate(rand.Reader, certificate, certificate, public, private)
	if err != nil {
		t.Fatal(err)
	}
	account, err := nkeys.CreateAccount()
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(account.Wipe)
	accountPublic, err := account.PublicKey()
	if err != nil {
		t.Fatal(err)
	}
	bundle := hostenroll.PublicBundle{SchemaVersion: 1, Cell: "gru", Region: "sa-saopaulo-1", Environment: "production",
		ControllerEndpoints:         []string{"10.0.0.1:8443", "10.0.0.2:8443", "10.0.0.3:8443"},
		NATSURLs:                    []string{"tls://10.0.0.1:4222", "tls://10.0.0.2:4222", "tls://10.0.0.3:4222"},
		CAPEM:                       string(pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE", Bytes: der})),
		ControllerResponsePublicKey: base64.StdEncoding.EncodeToString(public), CellAccountNKey: accountPublic,
		InstallRoot: hostenroll.ImageInstallRoot, StateRoot: hostenroll.ImageStateRoot, ManagedRuntimeRoot: hostenroll.ImageManagedRuntimeRoot,
		WorkloadUID: hostenroll.ImageWorkloadUID, WorkloadGID: hostenroll.ImageWorkloadGID}
	wire, err := json.Marshal(bundle)
	if err != nil {
		t.Fatal(err)
	}
	if _, err := hostenroll.ParsePublicBundle(wire); err != nil {
		t.Fatal(err)
	}
	recipe := capacityRecipe()
	recipe.Metadata[hostboot.EnrollmentMetadataKey] = string(wire)
	return recipe
}

// Finite request selectors are public DTOs and do not mint authenticated root authority.
func capacitySelectors(context.Context, Record) (rootoci.PoolChildExpectation, error) {
	return rootoci.PoolChildExpectation{Cell: "GRU", GrantSHA256: strings.Repeat("a", 64), Generation: 1, Epoch: 7}, nil
}

func chosenProtocolPool(t *testing.T, observed *OCIPool, store RecordStore,
	current func(context.Context, Record) (rootoci.PoolChildExpectation, error)) *ChosenPool {
	t.Helper()
	pool, err := NewChosenPool(observed, store, rootoci.NewClient(rootoci.Expectations{}), current)
	if err != nil {
		t.Fatal(err)
	}
	return pool
}

// This durable request fixture grants no signed spending or root mutation authority.
func capacityBirthRecord(recipe Recipe) Record {
	id := entityid.New()
	return Record{Action: &InFlight{ID: id, Kind: Up, Step: stepGrow, Started: time.Now().UTC()},
		Recipe: new(recipe), TargetFrom: new(0), Reservation: &budget.Reservation{OperationID: id, RecipeSHA256: recipe.SHA256()}}
}

func TestCapacityReservationPersistsBeforeOCIWrite(t *testing.T) {
	ctx := t.Context()
	js := capacityJetStream(t)
	store, err := OpenStore(ctx, js, 1)
	if err != nil {
		t.Fatal(err)
	}
	recipe := capacityEnrollmentRecipe(t)
	record := capacityBirthRecord(recipe)
	record.Reservation = nil
	if _, err := store.Save(ctx, record, 0); err != nil {
		t.Fatal(err)
	}
	cloud := newCapacityCloud()
	observed := protocolPool(t, cloud, recipe.Capacity)
	preparations := 0
	current := func(ctx context.Context, chosen Record) (rootoci.PoolChildExpectation, error) {
		stored, _, err := store.Load(ctx)
		if err != nil || stored.Reservation == nil || stored.Reservation.OperationID != record.Action.ID ||
			stored.Reservation.RecipeSHA256 != chosen.Recipe.SHA256() {
			t.Fatalf("selector preparation preceded durable reservation: record=%+v err=%v", stored, err)
		}
		preparations++
		return capacitySelectors(ctx, chosen)
	}
	pool := chosenProtocolPool(t, observed, store, current)
	hosts := newSwarmHosts(t)
	now := time.Now().UTC()
	reservations := 0
	scaler := &Scaler{Cell: "gru", Pool: pool, Store: store, Control: hosts.control,
		Leader: &capacityLeader{snapshot: authority.Snapshot{DeploymentID: entityid.New(), Leader: true, Ready: true, Epoch: 7, Revision: 3, ExpiresAt: now.Add(time.Hour)}},
		Now:    func() time.Time { return now }, Recipe: func(context.Context) (Recipe, error) { return recipe, nil },
		Reserve: func(_ context.Context, operation string, chosen Recipe) (budget.Reservation, error) {
			reservations++
			return budget.Reservation{OperationID: operation, RecipeSHA256: chosen.SHA256()}, nil
		},
		Allowance: func(time.Time) (int, bool) { return MaxNodes, true }, Loads: func() []NodeLoad { return nil },
		Journal: func(context.Context, decisionlog.Decision) {},
	}
	if err := scaler.Tick(ctx); err != nil {
		t.Fatal(err)
	}
	stored, _, err := store.Load(ctx)
	if err != nil || stored.Reservation == nil || stored.Reservation.OperationID != record.Action.ID || reservations != 1 || preparations != 0 || stored.Child != nil {
		t.Fatalf("reservation was not persisted before child preparation: record=%+v reservations=%d preparations=%d err=%v", stored, reservations, preparations, err)
	}
	reopened, err := OpenStore(ctx, js, 1)
	if err != nil {
		t.Fatal(err)
	}
	store = reopened
	scaler.Store, scaler.Pool = reopened, chosenProtocolPool(t, observed, reopened, current)
	if err := scaler.Tick(ctx); err != nil {
		t.Fatal(err)
	}
	stored, _, err = reopened.Load(ctx)
	if err != nil || stored.Child == nil || stored.Child.OperationID != record.Action.ID ||
		stored.Child.ReservationID != record.Action.ID || stored.Child.RecipeSHA256 != recipe.SHA256() ||
		!slices.Equal(stored.Child.AvailabilityDomains, recipe.AvailabilityDomains) || len(stored.Child.PublicCAPEM) == 0 ||
		stored.Action.Step != stepGrow || reservations != 1 || preparations != 1 || len(cloud.configs) != 0 || len(cloud.pools) != 0 {
		t.Fatalf("restart lost original reservation or crossed preparation into mutation: record=%+v reservations=%d preparations=%d err=%v", stored, reservations, preparations, err)
	}
}

func TestChosenFallbackKeepsExistingCapacityPools(t *testing.T) {
	ctx := t.Context()
	cloud := newCapacityCloud()
	base := capacityRecipe()
	first := seedCapacityPool(cloud, base, 1)
	old := cloud.launch("ts-gru-4", first.PoolID, "10.0.0.4", core.InstanceLifecycleStateRunning, launchTags(base, roleNode, entityid.New()))
	chosen := base
	chosen.Capacity.Shape = "VM.Standard.A2.Flex"
	second := seedCapacityPool(cloud, chosen, 0)
	store, err := OpenStore(ctx, capacityJetStream(t), 1)
	if err != nil {
		t.Fatal(err)
	}
	pool := chosenProtocolPool(t, protocolPool(t, cloud, base.Capacity), store, capacitySelectors)
	for range 2 {
		if err := pool.Grow(ctx, 1); !errors.Is(err, ErrCapacityPending) || !strings.Contains(err.Error(), "exact original root birth is not durable") {
			t.Fatalf("observed fallback granted growth without its original durable request: %v", err)
		}
	}
	for _, id := range []string{old, "ocid1.instance.oc1..outsider"} {
		if err := pool.Remove(ctx, id); !errors.Is(err, ErrCapacityPending) || !strings.Contains(err.Error(), "exact original root retirement is not durable") {
			t.Fatalf("observations granted retirement authority: %v", err)
		}
	}
	state, err := pool.observed.Observe(ctx)
	if err != nil || state.Size != 1 || len(state.Instances) != 1 || state.Instances[0].ID != old || state.Instances[0].Birth != nil ||
		state.PoolID != "" || deref(cloud.pools[first.PoolID].Size) != 1 || deref(cloud.pools[second.PoolID].Size) != 0 ||
		deref(cloud.instances[old].DisplayName) != "ts-gru-4" || len(cloud.pools) != 2 || len(cloud.configs) != 2 {
		t.Fatalf("fallback refusal hid or changed existing capacity: %+v err=%v", state, err)
	}
	if size, err := pool.TargetSize(ctx, chosen); err != nil || size != 0 {
		t.Fatalf("chosen starting size used regional aggregate: size=%d err=%v", size, err)
	}
}

func TestChosenCapacitySurvivesRestartAndFencesOCIChanges(t *testing.T) {
	ctx := t.Context()
	js := capacityJetStream(t)
	store, err := OpenStore(ctx, js, 1)
	if err != nil {
		t.Fatal(err)
	}
	recipe := capacityEnrollmentRecipe(t)
	record := capacityBirthRecord(recipe)
	cloud := newCapacityCloud()
	observed := protocolPool(t, cloud, recipe.Capacity)
	pool := chosenProtocolPool(t, observed, store, capacitySelectors)
	child, err := pool.PrepareGrowth(ctx, record)
	if err != nil {
		t.Fatal(err)
	}
	record.Child = new(child)
	revision, err := store.Save(ctx, record, 0)
	if err != nil {
		t.Fatal(err)
	}
	reopened, err := OpenStore(ctx, js, 1)
	if err != nil {
		t.Fatal(err)
	}
	restarted := chosenProtocolPool(t, observed, reopened, capacitySelectors)
	stored, storedRevision, err := reopened.Load(ctx)
	if err != nil || storedRevision != revision {
		t.Fatalf("reopen lost original record: %v", err)
	}
	prepared, err := restarted.PrepareGrowth(ctx, stored)
	if err != nil || prepared.OperationID != child.OperationID || prepared.RecipeSHA256 != child.RecipeSHA256 {
		t.Fatalf("reopen replaced original request: %+v %v", prepared, err)
	}
	for _, change := range []struct {
		name  string
		apply func(*Record)
	}{
		{"operation", func(r *Record) { r.Child.OperationID = entityid.New() }},
		{"reservation", func(r *Record) { r.Child.ReservationID = entityid.New() }},
		{"recipe", func(r *Record) { r.Child.RecipeSHA256 = strings.Repeat("b", 64) }},
		{"CA", func(r *Record) { r.Child.PublicCAPEM = []byte("replacement") }},
		{"placement", func(r *Record) { r.Child.AvailabilityDomains = []string{"unapproved-AD"} }},
	} {
		t.Run(change.name, func(t *testing.T) {
			changed := stored
			changed.Child = new(*stored.Child)
			change.apply(&changed)
			var saveErr error
			revision, saveErr = reopened.Save(ctx, changed, revision)
			if saveErr != nil {
				t.Fatal(saveErr)
			}
			if err := restarted.Grow(ctx, changed.From); err == nil || err.Error() != "durable root birth differs from its original recipe and reservation" {
				t.Fatalf("changed durable selector reached root IPC instead of local refusal: %v", err)
			}
		})
	}
	if len(cloud.configs) != 0 || len(cloud.pools) != 0 {
		t.Fatal("request preparation mutated OCI")
	}
}
