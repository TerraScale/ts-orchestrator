package app

import (
	"crypto/sha256"
	"encoding/hex"
	"fmt"
	"io"
	"net/http"
	"net/http/httptest"
	"strings"
	"sync/atomic"
	"testing"
	"time"

	"github.com/nats-io/nats.go/jetstream"
	"github.com/oracle/oci-go-sdk/v65/common"
	"github.com/oracle/oci-go-sdk/v65/core"

	"github.com/TerraScale/ts-orchestrator/internal/budget"
	"github.com/TerraScale/ts-orchestrator/internal/entityid"
	"github.com/TerraScale/ts-orchestrator/internal/nodescale"
	"github.com/TerraScale/ts-orchestrator/internal/oci"
	"github.com/TerraScale/ts-orchestrator/internal/ociclient"
)

type capacityCheckpointSigner struct{}

func (capacityCheckpointSigner) Sign(*http.Request) error { return nil }

func TestCapacityCheckpointPrecedesActualSDKRequestAndRetainsOriginalReceipt(t *testing.T) {
	ctx := t.Context()
	js, err := jetstream.New(startEmbeddedNATS(t))
	if err != nil {
		t.Fatal(err)
	}
	store, err := nodescale.OpenStore(ctx, js, 1)
	if err != nil {
		t.Fatal(err)
	}
	journal, err := oci.OpenJournal(ctx, js, 1)
	if err != nil {
		t.Fatal(err)
	}
	const compartment = "ocid1.compartment.oc1..workers"
	const pool = "ocid1.instancepool.oc1..workers"
	recipe := nodescale.Recipe{Cell: "gru", Capacity: nodescale.Capacity{Role: nodescale.RoleWasm, Architecture: "arm64", Shape: "VM.Standard.A1.Flex"},
		SubnetID: "ocid1.subnet.oc1..workers", NSGIDs: []string{"ocid1.networksecuritygroup.oc1..workers"}, AvailabilityDomains: []string{"AD-1"},
		ImageID: "ocid1.image.oc1..worker", OCPUs: 2, MemoryGB: 12, Metadata: map[string]string{"public-worker-bundle": "fixture"}}
	action := &nodescale.InFlight{ID: entityid.New(), Kind: nodescale.Up, Started: time.Now().UTC()}
	// This boundary supplies the already verified home receipt; its authority has separate signed-producer cases.
	receipt := &budget.Reservation{OperationID: action.ID, RecipeSHA256: recipe.SHA256(), Cell: "GRU", CompartmentID: compartment,
		GrantSHA256: strings.Repeat("1", 64), ScopeSHA256: strings.Repeat("2", 64), ResolvedScopeSHA256: strings.Repeat("3", 64),
		BindingSHA256: strings.Repeat("4", 64), GrantGeneration: 7, QuoteSHA256: strings.Repeat("5", 64),
		TenancyID: "ocid1.tenancy.oc1..fixture", Currency: "USD", MonthlyCents: 2147}
	if _, err := store.Save(ctx, nodescale.Record{Action: action, Recipe: new(recipe), Reservation: receipt, TargetFrom: new(0)}, 0); err != nil {
		t.Fatal(err)
	}
	checkpoint := checkpointCapacityGrowth(compartment, store, journal)
	request := core.UpdateInstancePoolRequest{InstancePoolId: new(pool), IfMatch: new("original-etag"), OpcRetryToken: new("original-retry-token"),
		UpdateInstancePoolDetails: core.UpdateInstancePoolDetails{Size: new(1)}}
	prepared, err := checkpoint(ctx, recipe, request)
	if err != nil {
		t.Fatal(err)
	}
	var calls atomic.Int32
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, wire *http.Request) {
		calls.Add(1)
		stored, found, err := journal.GetCapacityRequest(ctx, action.ID)
		if err != nil || !found {
			t.Errorf("SDK wire preceded durable request: found=%v err=%v", found, err)
			w.WriteHeader(http.StatusConflict)
			return
		}
		body, err := io.ReadAll(wire.Body)
		if err != nil {
			t.Error(err)
		}
		digest := sha256.New()
		_, _ = fmt.Fprintf(digest, "%s\n%s\n%s\n%s\n%s\n", wire.Method, strings.TrimPrefix(wire.URL.EscapedPath(), "/20160918"),
			wire.Header.Get("Content-Type"), wire.Header.Get("if-match"), wire.Header.Get("opc-retry-token"))
		_, _ = digest.Write(body)
		if stored.RequestSHA256 != hex.EncodeToString(digest.Sum(nil)) || stored.QuoteSHA256 != receipt.QuoteSHA256 || stored.ReservedMonthlyCents != receipt.MonthlyCents {
			t.Errorf("checkpoint differs from actual SDK body/headers or original receipt: %+v", stored)
		}
		w.Header().Set("Content-Type", "application/json")
		_, _ = fmt.Fprintf(w, `{"id":%q,"size":1,"lifecycleState":"RUNNING"}`, pool)
	}))
	defer server.Close()
	policy := common.NoRetryPolicy()
	base := common.BaseClient{Host: server.URL, BasePath: "20160918", HTTPClient: server.Client(), Signer: capacityCheckpointSigner{},
		Configuration: common.CustomClientConfiguration{RetryPolicy: &policy}}
	ociclient.ConfigureRequestCancellation(&base)
	client := core.ComputeManagementClient{BaseClient: base}
	if _, err := client.UpdateInstancePool(ociclient.RequestContext(ctx), prepared); err != nil {
		t.Fatal(err)
	}
	reopened, err := oci.OpenJournal(ctx, js, 1)
	if err != nil {
		t.Fatal(err)
	}
	request.IfMatch, request.OpcRetryToken = new("refreshed-etag"), new("replacement-token")
	replayed, err := checkpointCapacityGrowth(compartment, store, reopened)(ctx, recipe, request)
	if err != nil || *replayed.IfMatch != "original-etag" || *replayed.OpcRetryToken != "original-retry-token" {
		t.Fatalf("restart refreshed an unknown request: %+v err=%v", replayed, err)
	}
	current, revision, err := store.Load(ctx)
	if err != nil {
		t.Fatal(err)
	}
	current.Reservation.QuoteSHA256 = strings.Repeat("6", 64)
	if _, err := store.Save(ctx, current, revision); err != nil {
		t.Fatal(err)
	}
	if _, err := checkpoint(ctx, recipe, request); err == nil || calls.Load() != 1 {
		t.Fatal("refreshed quote replaced the original request receipt")
	}
	if _, err := checkpointCapacityGrowth(compartment, store, nil)(ctx, recipe, request); err == nil {
		t.Fatal("missing durable journal admitted growth")
	}
}
