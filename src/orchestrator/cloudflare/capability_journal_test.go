package cloudflare

import (
	"bytes"
	"encoding/json/v2"
	"errors"
	"strings"
	"sync"
	"testing"
	"time"

	natsserver "github.com/nats-io/nats-server/v2/server"
	"github.com/nats-io/nats.go"
	"terrascale.tech/orchestrator/src/orchestrator/security"
)

func TestCapabilityReceiptStrictMetadata(t *testing.T) {
	receipt := CapabilityReceipt{Generation: 2, Current: security.CapabilityKeyState{ID: "current", Reference: "vault/current", Version: 2}, Phase: "prepared", Digest: "digest", OperationID: "operation"}
	raw, err := json.Marshal(receipt)
	if err != nil {
		t.Fatal(err)
	}
	if _, err := decodeCapabilityReceipt(raw); err != nil {
		t.Fatal(err)
	}
	for name, invalid := range map[string][]byte{
		"unknown secret": []byte(strings.Replace(string(raw), `"Generation":2`, `"Generation":2,"Key":"secret"`, 1)),
		"duplicate":      []byte(strings.Replace(string(raw), `"Generation":2`, `"Generation":2,"Generation":3`, 1)),
		"nested secret":  []byte(strings.Replace(string(raw), `"ID":"current"`, `"ID":"current","Key":"secret"`, 1)),
		"trailing":       append(append([]byte{}, raw...), []byte(` {}`)...),
		"oversized":      []byte(strings.Repeat(" ", maximumCapabilityReceiptBytes+1)),
		"null":           []byte("null"),
	} {
		t.Run(name, func(t *testing.T) {
			if _, err := decodeCapabilityReceipt(invalid); err == nil {
				t.Fatal("accepted invalid receipt")
			}
		})
	}
}

// Exercise the wire contract against an embedded NATS server. The simulated
// JetStream leader advertises AllowDirect, but offers no DIRECT.GET handler.
func TestCapabilityJournalLeaderReadAndCAS(t *testing.T) {
	server, err := natsserver.NewServer(&natsserver.Options{Host: "127.0.0.1", Port: -1, NoLog: true, NoSigs: true})
	if err != nil {
		t.Fatal(err)
	}
	go server.Start()
	t.Cleanup(server.Shutdown)
	if !server.ReadyForConnections(5 * time.Second) {
		t.Fatal("server not ready")
	}
	connection, err := nats.Connect(server.ClientURL())
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(connection.Close)
	var mu sync.Mutex
	var raw []byte
	var revision uint64
	replicas := 3
	respond := func(m *nats.Msg, value any) {
		body, err := json.Marshal(value)
		if err == nil {
			_ = m.Respond(body)
		}
	}
	_, err = connection.Subscribe("$JS.API.STREAM.INFO.KV_receipts", func(m *nats.Msg) {
		mu.Lock()
		defer mu.Unlock()
		respond(m, map[string]any{"config": map[string]any{"name": "KV_receipts", "storage": "file", "num_replicas": replicas, "max_msgs": -1, "max_msgs_per_subject": 1, "discard": "new", "subjects": []string{"$KV.receipts.>"}, "allow_direct": true}})
	})
	if err != nil {
		t.Fatal(err)
	}
	_, err = connection.Subscribe("$JS.API.STREAM.MSG.GET.KV_receipts", func(m *nats.Msg) {
		mu.Lock()
		defer mu.Unlock()
		if revision == 0 {
			respond(m, map[string]any{"error": map[string]any{"code": 404, "err_code": 10037, "description": "missing"}})
			return
		}
		respond(m, map[string]any{"message": map[string]any{"subject": "$KV.receipts.capability", "seq": revision, "data": raw}})
	})
	if err != nil {
		t.Fatal(err)
	}
	_, err = connection.Subscribe("$KV.receipts.capability", func(m *nats.Msg) {
		mu.Lock()
		defer mu.Unlock()
		var expected uint64
		if json.Unmarshal([]byte(m.Header.Get("Nats-Expected-Last-Subject-Sequence")), &expected) != nil || expected != revision {
			respond(m, map[string]any{"error": map[string]any{"code": 400, "err_code": 10071, "description": "wrong last sequence"}})
			return
		}
		revision++
		raw = append([]byte(nil), m.Data...)
		respond(m, map[string]any{"stream": "KV_receipts", "seq": revision})
	})
	if err != nil {
		t.Fatal(err)
	}
	if err := connection.Flush(); err != nil {
		t.Fatal(err)
	}
	config := NATSCapabilityJournalConfig{Connection: connection, Bucket: "receipts", Key: "capability"}
	journal, err := NewNATSCapabilityJournal(t.Context(), config)
	if err != nil {
		t.Fatal(err)
	}
	if receipt, revision, err := journal.Load(t.Context()); err != nil || revision != 0 || receipt.Generation != 0 {
		t.Fatalf("missing: %v %d %v", receipt, revision, err)
	}
	receipt := CapabilityReceipt{Generation: 2, Current: security.CapabilityKeyState{ID: "current", Reference: "vault/current", Version: 2}, Phase: "prepared", Digest: "digest", OperationID: "operation"}
	if err := journal.Save(t.Context(), receipt, 0); err != nil {
		t.Fatal(err)
	}
	restarted, err := NewNATSCapabilityJournal(t.Context(), config)
	if err != nil {
		t.Fatal(err)
	}
	loaded, rev, err := restarted.Load(t.Context())
	loadedJSON, _ := json.Marshal(loaded)
	receiptJSON, _ := json.Marshal(receipt)
	if err != nil || !bytes.Equal(loadedJSON, receiptJSON) || rev != 1 {
		t.Fatalf("restart: %v %d %v", loaded, rev, err)
	}
	if err := restarted.Save(t.Context(), receipt, 0); !errors.Is(err, ErrCapabilityJournalConflict) {
		t.Fatalf("stale CAS: %v", err)
	}
	if err := restarted.Save(t.Context(), receipt, rev); err != nil {
		t.Fatal(err)
	}
	mu.Lock()
	replicas = 1
	mu.Unlock()
	if _, _, err := journal.Load(t.Context()); err == nil {
		t.Fatal("accepted reduced durability on load")
	}
	if err := journal.Save(t.Context(), receipt, 2); err == nil {
		t.Fatal("accepted reduced durability on save")
	}
	if _, err := NewNATSCapabilityJournal(t.Context(), config); err == nil {
		t.Fatal("accepted R1 bucket")
	}
}
