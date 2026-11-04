package nodescale

import (
	"context"
	"crypto/ed25519"
	"crypto/rand"
	"crypto/x509"
	"encoding/base64"
	"encoding/json/v2"
	"encoding/pem"
	"math/big"
	"strings"
	"testing"
	"time"

	"github.com/TerraScale/ts-orchestrator/internal/budget"
	"github.com/TerraScale/ts-orchestrator/internal/entityid"
	"github.com/TerraScale/ts-orchestrator/internal/hostboot"
	"github.com/TerraScale/ts-orchestrator/internal/hostenroll"
	"github.com/TerraScale/ts-orchestrator/internal/rootoci"
	"github.com/nats-io/nkeys"
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
	bundle := hostenroll.PublicBundle{SchemaVersion: 1, Cell: "gru", Region: "GRU", Environment: "production",
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
