package oci

import (
	"path/filepath"
	"strings"
	"testing"
	"time"

	"github.com/TerraScale/ts-orchestrator/internal/entityid"
	"github.com/TerraScale/ts-orchestrator/internal/natscell"
)

func TestCapacityRequestSurvivesDiskRestartWithoutRenewingIdentity(t *testing.T) {
	config := natscell.Config{Cell: "lab", Instance: "capacity-request", Replicas: 1, Lab: true,
		Embedded: &natscell.Embedded{Host: "127.0.0.1", Port: -1, StoreDir: filepath.Join(t.TempDir(), "jetstream")}}
	runtime, err := natscell.Start(t.Context(), config)
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = runtime.Close() })
	journal, err := OpenJournal(t.Context(), runtime.JetStream(), 1)
	if err != nil {
		t.Fatal(err)
	}
	request := CapacityRequest{
		OperationID: entityid.New(), RecipeSHA256: strings.Repeat("a", 64),
		LogicalScopeSHA256: strings.Repeat("b", 64), ResolvedScopeSHA256: strings.Repeat("c", 64), BindingSHA256: strings.Repeat("d", 64),
		GrantSHA256: strings.Repeat("e", 64), GrantGeneration: 7,
		TenancyID: "ocid1.tenancy.oc1..test", Region: RegionGRU, CompartmentID: "ocid1.compartment.oc1..owned", PoolID: "ocid1.instancepool.oc1..owned",
		RequestSHA256: strings.Repeat("f", 64), RetryToken: entityid.New(), IfMatch: "original-pool-etag", Currency: "USD",
		ReservedMonthlyCents: 2147, QuoteSHA256: strings.Repeat("1", 64), TargetSize: 2, StartedAt: time.Now().UTC(),
	}
	if err := journal.RecordCapacityRequest(t.Context(), request); err != nil {
		t.Fatal(err)
	}
	if err := runtime.Close(); err != nil {
		t.Fatal(err)
	}
	runtime, err = natscell.Start(t.Context(), config)
	if err != nil {
		t.Fatal(err)
	}
	journal, err = OpenJournal(t.Context(), runtime.JetStream(), 1)
	if err != nil {
		t.Fatal(err)
	}
	got, found, err := journal.GetCapacityRequest(t.Context(), request.OperationID)
	if err != nil || !found || got != request {
		t.Fatalf("original request lost after disk restart: %+v found=%v err=%v", got, found, err)
	}
	if err := journal.RecordCapacityRequest(t.Context(), request); err != nil {
		t.Fatalf("exact durable replay failed: %v", err)
	}
	for _, change := range []struct {
		name string
		edit func(*CapacityRequest)
	}{
		{"request", func(r *CapacityRequest) { r.RequestSHA256 = strings.Repeat("2", 64) }},
		{"retry token", func(r *CapacityRequest) { r.RetryToken = entityid.New() }},
		{"precondition", func(r *CapacityRequest) { r.IfMatch = "refreshed-etag" }},
		{"target", func(r *CapacityRequest) { r.TargetSize++ }},
		{"quote", func(r *CapacityRequest) { r.QuoteSHA256 = strings.Repeat("3", 64) }},
		{"grant", func(r *CapacityRequest) { r.GrantGeneration++ }},
		{"amount", func(r *CapacityRequest) { r.ReservedMonthlyCents++ }},
		{"time", func(r *CapacityRequest) { r.StartedAt = r.StartedAt.Add(time.Minute) }},
	} {
		t.Run(change.name, func(t *testing.T) {
			altered := request
			change.edit(&altered)
			if err := journal.RecordCapacityRequest(t.Context(), altered); err == nil {
				t.Fatal("changed request replaced immutable original")
			}
		})
	}
	got, found, err = journal.GetCapacityRequest(t.Context(), request.OperationID)
	if err != nil || !found || got != request {
		t.Fatalf("conflicting replay damaged original: %+v found=%v err=%v", got, found, err)
	}
	if _, found, err := journal.GetCapacityRequest(t.Context(), entityid.New()); err != nil || found {
		t.Fatalf("missing request became evidence: found=%v err=%v", found, err)
	}
	invalid := request
	invalid.OperationID, invalid.BindingSHA256 = entityid.New(), ""
	if err := journal.RecordCapacityRequest(t.Context(), invalid); err == nil {
		t.Fatal("resolved scope was recorded without its verified binding")
	}
}
