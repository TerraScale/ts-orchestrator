//go:build sandboxvm

package vmqual

import (
	"context"
	"encoding/json"
	"strings"
	"sync"
	"testing"
	"time"

	natsserver "github.com/nats-io/nats-server/v2/server"
	"github.com/nats-io/nats.go"
	"terrascale.tech/orchestrator/src/orchestrator/hostagent"
)

func TestFirecrackerDeliveryCordonUsesEmbeddedNATSAndObservedStatus(t *testing.T) {
	server := startDeliveryTestNATS(t)
	services := &qualificationRuntimeServices{nats: server, started: true}
	host := "gru-member-1"
	factory := &firecrackerFactory{
		active:   map[string]*sandboxVM{host: {id: host, guest: Guest{ID: host}}},
		services: services,
	}

	connection, err := nats.Connect(server.ClientURL(), nats.NoReconnect())
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(connection.Close)
	nodeID, err := hostagent.NewNodeId(host)
	if err != nil {
		t.Fatal(err)
	}
	drainSubject, err := hostagent.NodeDrainSubject(nodeID)
	if err != nil {
		t.Fatal(err)
	}
	statusSubject, err := hostagent.NodeDrainStatusSubject(nodeID)
	if err != nil {
		t.Fatal(err)
	}

	var mutex sync.Mutex
	draining := false
	commandIDs := make(map[string]struct{})
	drainSubscription, err := connection.Subscribe(drainSubject, func(message *nats.Msg) {
		var command hostagent.DrainCommand
		if json.Unmarshal(message.Data, &command) != nil {
			return
		}
		mutex.Lock()
		draining = command.Drain
		commandIDs[command.CommandId] = struct{}{}
		mutex.Unlock()
		receipt, receiptErr := hostagent.NewDrainReceipt(command.CommandId, host, command.Drain, command.Drain, "observed")
		if receiptErr != nil {
			return
		}
		data, _ := json.Marshal(receipt)
		_ = message.Respond(data)
	})
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = drainSubscription.Unsubscribe() })
	statusSubscription, err := connection.Subscribe(statusSubject, func(message *nats.Msg) {
		var request hostagent.NodeStatusRequest
		if json.Unmarshal(message.Data, &request) != nil {
			return
		}
		mutex.Lock()
		state := hostagent.NodeStateServing
		quiesced := false
		if draining {
			state, quiesced = hostagent.NodeStateDraining, true
		}
		commandIDs[request.CommandId] = struct{}{}
		mutex.Unlock()
		report, reportErr := hostagent.NewNodeStatusReport(request.CommandId, host, state, quiesced, hostagent.HostFacts{State: state, Components: []hostagent.ComponentFact{}})
		if reportErr != nil {
			return
		}
		data, _ := json.Marshal(report)
		_ = message.Respond(data)
	})
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = statusSubscription.Unsubscribe() })
	if err := connection.Flush(); err != nil {
		t.Fatal(err)
	}

	ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
	defer cancel()
	if err := factory.Cordon(ctx, host, true); err != nil {
		t.Fatalf("cordon: %v", err)
	}
	report, err := factory.DrainStatus(ctx, host)
	if err != nil {
		t.Fatalf("drain status: %v", err)
	}
	if !report.Cordoned || !report.Drained {
		t.Fatalf("drain report = %+v", report)
	}
	if err := factory.Cordon(ctx, host, false); err != nil {
		t.Fatalf("uncordon: %v", err)
	}
	report, err = factory.DrainStatus(ctx, host)
	if err != nil {
		t.Fatalf("released status: %v", err)
	}
	if report.Cordoned || report.Drained {
		t.Fatalf("released report = %+v", report)
	}

	mutex.Lock()
	defer mutex.Unlock()
	if len(commandIDs) != 6 {
		t.Fatalf("durable command IDs = %d, want six unique requests", len(commandIDs))
	}
	for id := range commandIDs {
		if !strings.HasPrefix(id, "vmq-") {
			t.Fatalf("command ID %q is not namespaced", id)
		}
		if _, err := hostagent.NewNodeStatusRequest(id); err != nil {
			t.Fatalf("command ID %q is not canonical: %v", id, err)
		}
	}
}

func TestDecodeDeliveryReplyRejectsNonCanonicalEvidence(t *testing.T) {
	valid := []byte(`{"commandId":"vmq-observe-123456789012345678901234","nodeId":"gru-member-1","state":"serving","quiesced":false,"facts":{"state":"serving","clockOffsetMillis":0,"clockMeasured":true,"clockUnhealthy":false,"disk":{"path":"/var/lib/terrascale","totalBytes":1,"availableBytes":1},"tsNodeVersion":"v1","components":[]}}`)
	var report hostagent.NodeStatusReport
	if err := decodeDeliveryReply(valid, &report); err != nil {
		t.Fatalf("canonical reply rejected: %v", err)
	}
	if report.NodeId != "gru-member-1" || report.State != hostagent.NodeStateServing {
		t.Fatalf("decoded report = %+v", report)
	}

	tests := [][]byte{
		[]byte(`{"commandId":"a","commandId":"b","nodeId":"gru-member-1","state":"serving","quiesced":false,"facts":{}}`),
		[]byte(`{"commandId":"a","nodeId":"gru-member-1","state":"serving","quiesced":false,"facts":{"state":"serving","state":"draining"}}`),
		[]byte(`{"commandId":"a","nodeId":"gru-member-1","state":"serving","quiesced":false,"facts":null}`),
		[]byte(`{"commandId":"a","nodeId":"gru-member-1","state":"serving","quiesced":false,"facts":{},"extra":true}`),
		append(append([]byte(nil), valid...), []byte(` {}`)...),
	}
	for _, data := range tests {
		var invalid hostagent.NodeStatusReport
		if err := decodeDeliveryReply(data, &invalid); err == nil {
			t.Fatalf("non-canonical reply accepted: %s", data)
		}
	}
}

func TestDeliveryCommandIDIsUniqueCanonicalAndBounded(t *testing.T) {
	seen := make(map[string]struct{})
	for range 128 {
		id, err := newDeliveryCommandID("deploy")
		if err != nil {
			t.Fatal(err)
		}
		if len(id) > 63 {
			t.Fatalf("command ID is too long: %q", id)
		}
		if _, duplicate := seen[id]; duplicate {
			t.Fatalf("duplicate command ID: %q", id)
		}
		seen[id] = struct{}{}
	}
	if _, err := newDeliveryCommandID("bad_kind"); err == nil {
		t.Fatal("invalid command kind accepted")
	}
}

func TestDeliveryDigestAdmissionIsExact(t *testing.T) {
	valid := "sha256:" + strings.Repeat("a", 64)
	if !canonicalDeliveryDigest(valid) {
		t.Fatal("canonical delivery digest rejected")
	}
	for _, invalid := range []string{
		strings.Repeat("a", 64),
		"sha256:" + strings.Repeat("A", 64),
		"sha256:" + strings.Repeat("a", 63),
		"sha256:" + strings.Repeat("g", 64),
	} {
		if canonicalDeliveryDigest(invalid) {
			t.Fatalf("invalid delivery digest accepted: %q", invalid)
		}
	}
}

func TestDeliveryFactoryRejectsUnownedGuestBeforeNATS(t *testing.T) {
	factory := &firecrackerFactory{active: make(map[string]*sandboxVM)}
	ctx, cancel := context.WithTimeout(context.Background(), time.Second)
	defer cancel()
	if err := factory.Cordon(ctx, "gru-member-1", true); err == nil || !strings.Contains(err.Error(), "not a participating guest") {
		t.Fatalf("unowned guest error = %v", err)
	}
}

func startDeliveryTestNATS(t *testing.T) *natsserver.Server {
	t.Helper()
	server, err := natsserver.NewServer(&natsserver.Options{
		Host: "127.0.0.1", Port: -1, NoLog: true, NoSigs: true,
	})
	if err != nil {
		t.Fatal(err)
	}
	server.Start()
	if !server.ReadyForConnections(5 * time.Second) {
		server.Shutdown()
		server.WaitForShutdown()
		t.Fatal("embedded NATS did not become ready")
	}
	t.Cleanup(func() {
		server.Shutdown()
		server.WaitForShutdown()
	})
	return server
}
