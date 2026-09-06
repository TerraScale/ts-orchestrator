package hostcontrol

import (
	"context"
	"encoding/json"
	"strings"
	"testing"
	"time"

	"github.com/nats-io/nats.go"
	"terrascale.tech/orchestrator/src/orchestrator/hostagent"
	runtimeplan "terrascale.tech/orchestrator/src/orchestrator/runtime"
)

func TestObserverAcceptsAuthenticatedFreshEngineFactsWithoutMutationKey(t *testing.T) {
	client, node := authenticatedConnections(t)
	nodeID, _ := hostagent.NewNodeId("gru-1")
	subject, _ := hostagent.NodeDrainStatusSubject(nodeID)
	_, err := node.Subscribe(subject, func(message *nats.Msg) {
		var request hostagent.NodeStatusRequest
		if json.Unmarshal(message.Data, &request) != nil {
			return
		}
		report := hostagent.NodeStatusReport{CommandId: request.CommandId, NodeId: "gru-1", State: hostagent.NodeStateServing, Facts: hostagent.HostFacts{State: hostagent.NodeStateServing, ManifestSha256: strings.Repeat("a", 64), Components: []hostagent.ComponentFact{}, Engine: hostagent.EngineFacts{Measured: true, Serving: true, ObservedAtUnixMS: time.Now().UnixMilli()}}}
		raw, _ := json.Marshal(report)
		_ = message.Respond(raw)
	})
	if err != nil {
		t.Fatal(err)
	}
	if err := node.Flush(); err != nil {
		t.Fatal(err)
	}
	observer, err := NewObserver("GRU", client, func(context.Context, string) (Host, error) {
		id, _ := hostagent.NewNodeId("gru-1")
		return Host{NodeID: id, Region: "GRU", Architecture: runtimeplan.HostArchitectureArm64}, nil
	}, time.Second)
	if err != nil {
		t.Fatal(err)
	}
	report, err := observer.Status(t.Context(), "gru-1")
	if err != nil || !report.Facts.Engine.Measured || !report.Facts.Engine.Serving {
		t.Fatalf("observation: %+v %v", report, err)
	}
}
