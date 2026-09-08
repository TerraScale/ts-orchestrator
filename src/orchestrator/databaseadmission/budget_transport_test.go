package databaseadmission

import (
	"bytes"
	"io"
	"net/http"
	"os"
	"path/filepath"
	"testing"
	"time"

	"terrascale.tech/orchestrator/src/orchestrator/keylease"
	"terrascale.tech/orchestrator/src/orchestrator/writebudget"
)

func TestBudgetAllocationThroughAuthenticatedHost(t *testing.T) {
	cluster := newAdmissionJournalCluster(t)
	connection := cluster.connect(t)
	record := journalFixture(t)
	target := record.Targets[0]
	config := pipelineConfig(t, NewMemoryJournal())
	if err := keylease.InitializeCatalog(config.CatalogPath); err != nil {
		t.Fatal(err)
	}
	for _, mode := range []string{"installed", "conflict", "body", "holder", "region"} {
		t.Run(mode, func(t *testing.T) {
			socket := filepath.Join(filepath.Dir(config.CatalogPath), "budget-"+mode+".sock")
			listener, err := listenPrivate(socket)
			if err != nil {
				t.Fatal(err)
			}
			calls := make(chan []byte, 1)
			server := &http.Server{Handler: http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
				if r.Method != http.MethodPost || r.URL.Path != "/internal/v1/databases/usage/allocation" {
					t.Error("wrong engine route")
				}
				body, _ := io.ReadAll(r.Body)
				calls <- body
				if mode == "conflict" {
					w.WriteHeader(http.StatusConflict)
				} else if mode == "body" {
					_, _ = w.Write([]byte("pending"))
				}
			})}
			go server.Serve(listener)
			defer server.Close()
			host, err := StartHost(t.Context(), HostConfig{Connection: connection, ServerIdentity: target.ServerIdentity, CatalogPath: config.CatalogPath, EngineSocket: socket, EngineUID: uint32(os.Geteuid()), Environment: record.Request.Environment, Region: target.Region, MemberID: target.MemberID})
			if err != nil {
				t.Fatal(err)
			}
			defer host.Close()
			envelope := writebudget.AllocationEnvelope{SchemaVersion: 1, Grant: writebudget.Grant{HolderID: target.MemberID, Regions: []string{target.Region}}}
			if mode == "holder" {
				envelope.Grant.HolderID = "other"
			} else if mode == "region" {
				envelope.Grant.Regions = []string{"other"}
			}
			signed := writebudget.SignedAllocation{Payload: mustJSON(envelope), Signature: []byte("opaque-signature-verified-by-engine"), KeyID: "pinned-engine-key"}
			subject, _ := HostSubject(target.ServerIdentity)
			reply, err := connection.Request(subject, mustJSON(BudgetAllocationDelivery{Allocation: signed}), 5*time.Second)
			if err != nil {
				t.Fatal(err)
			}
			if (string(reply.Data) == "installed") != (mode == "installed") {
				t.Fatalf("reply=%s", reply.Data)
			}
			select {
			case received := <-calls:
				if mode == "holder" || mode == "region" {
					t.Fatal("wrong target reached engine")
				}
				if !bytes.Equal(received, mustJSON(signed)) {
					t.Fatal("signed bytes changed")
				}
			default:
				if mode != "holder" && mode != "region" {
					t.Fatal("allocation did not reach engine")
				}
			}
		})
	}
}
