package databaseadmission

import (
	"encoding/json/v2"
	"io"
	"net/http"
	"path/filepath"
	"sync/atomic"
	"testing"

	"github.com/nats-io/nats.go"
	"terrascale.tech/orchestrator/src/orchestrator/writebudget"
)

func TestPollPoolDeliversPersistedLowercaseRegion(t *testing.T) {
	cluster := newAdmissionJournalCluster(t)
	connection := cluster.connect(t)
	record := journalFixture(t)
	target := record.Targets[0]
	config := pipelineConfig(t, NewMemoryJournal())
	subject, err := PoolSubject(target.ServerIdentity)
	if err != nil {
		t.Fatal(err)
	}
	var attempts atomic.Int32
	sub, err := connection.Subscribe(subject, func(message *nats.Msg) {
		attempt := attempts.Add(1)
		var work PoolWork
		if err := json.Unmarshal(message.Data, &work, json.RejectUnknownMembers(true)); err != nil {
			t.Errorf("decode pool work: %v", err)
			return
		}
		if work.Request.Region != "gru" {
			t.Errorf("persisted region = %q, want gru", work.Request.Region)
		}
		state := "unknown"
		if attempt == 2 {
			state = "installed"
		}
		_ = message.Respond(mustJSON(PoolWorkReply{RefillOperationID: work.Request.RefillOperationID, State: state}))
	})
	if err != nil {
		t.Fatal(err)
	}
	defer sub.Unsubscribe()
	if err := connection.Flush(); err != nil {
		t.Fatal(err)
	}

	socket := filepath.Join(filepath.Dir(config.CatalogPath), "pool.sock")
	listener, err := listenPrivate(socket)
	if err != nil {
		t.Fatal(err)
	}
	var acked atomic.Bool
	server := &http.Server{Handler: http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		body, err := io.ReadAll(r.Body)
		if err != nil {
			t.Errorf("read %s: %v", r.URL.Path, err)
			return
		}
		switch r.URL.Path {
		case "/internal/v1/databases/usage/pool/work":
			_, _ = w.Write(mustJSON(struct {
				Next string    `json:"next_database"`
				Work *PoolWork `json:"work"`
			}{Next: "db-next", Work: &PoolWork{Request: writebudget.PoolRefillRequest{RefillOperationID: "refill-1", HolderID: target.MemberID, Region: "gru", DatabaseID: "db"}}}))
		case "/internal/v1/databases/usage/pool/ack":
			var ack struct {
				Database  string `json:"database_id"`
				Operation string `json:"refill_operation_id"`
			}
			if json.Unmarshal(body, &ack, json.RejectUnknownMembers(true)) == nil && ack.Database == "db" && ack.Operation == "refill-1" {
				acked.Store(true)
			}
		default:
			http.NotFound(w, r)
		}
	})}
	go server.Serve(listener)
	defer server.Close()
	client := unixTestClient(socket)
	defer client.CloseIdleConnections()

	hostConfig := HostConfig{Connection: connection, ServerIdentity: target.ServerIdentity, Region: "GRU", MemberID: target.MemberID}
	next, err := pollPool(t.Context(), hostConfig, client, "")
	if err == nil || next != "" {
		t.Fatalf("failed poll result next=%q err=%v", next, err)
	}
	next, err = pollPool(t.Context(), hostConfig, client, next)
	if err != nil {
		t.Fatal(err)
	}
	if next != "db-next" || !acked.Load() || attempts.Load() != 2 {
		t.Fatalf("poll result next=%q acked=%v attempts=%d", next, acked.Load(), attempts.Load())
	}
}

func TestPoolAuthorityRequestUsesForwardingEnvelope(t *testing.T) {
	request := PoolAuthorityRequest{
		ServerIdentity: "spiffe://terrascale.tech/production/terrabase-member/01ARZ3NDEKTSV4RRFFQ69G5FAD/01ARZ3NDEKTSV4RRFFQ69G5FAE",
		MemberID:       "01ARZ3NDEKTSV4RRFFQ69G5FAE",
		Work: PoolWork{Request: writebudget.PoolRefillRequest{
			RefillOperationID: "refill-1",
			HolderID:          "01ARZ3NDEKTSV4RRFFQ69G5FAE",
		}},
	}
	data, err := json.Marshal(request)
	if err != nil {
		t.Fatal(err)
	}
	var decoded PoolAuthorityRequest
	if err := json.Unmarshal(data, &decoded, json.RejectUnknownMembers(true)); err != nil {
		t.Fatal(err)
	}
	if decoded.ServerIdentity != request.ServerIdentity || decoded.MemberID != request.MemberID || decoded.Work.Request.RefillOperationID != request.Work.Request.RefillOperationID {
		t.Fatalf("forwarded request changed: got %#v", decoded)
	}
	var legacy PoolWork
	if err := json.Unmarshal(data, &legacy, json.RejectUnknownMembers(true)); err == nil {
		t.Fatal("authority envelope was accepted as an unwrapped pool work message")
	}
}
