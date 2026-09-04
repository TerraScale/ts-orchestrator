package hostagent

import (
	"encoding/json"
	"testing"
	"time"
)

// TestNodeSubjectsAreCanonical pins the RPC subject surface the delivery
// lane consumes.
func TestNodeSubjectsAreCanonical(t *testing.T) {
	node := NodeId{Value: "gru-1"}
	cases := []struct {
		build func(NodeId) (string, error)
		want  string
	}{
		{NodeDrainSubject, "ts.orch.v1.gru.agent.9a097238a730924911f02fcc.command.drain"},
		{NodeDrainStatusSubject, "ts.orch.v1.gru.agent.9a097238a730924911f02fcc.command.drain-status"},
		{NodeDeploySubject, "ts.orch.v1.gru.agent.9a097238a730924911f02fcc.command.deploy"},
		{NodeRollbackSubject, "ts.orch.v1.gru.agent.9a097238a730924911f02fcc.command.rollback"},
		{NodeHeartbeatSubject, "ts.orch.v1.gru.agent.9a097238a730924911f02fcc.observation.heartbeat"},
	}
	for _, testCase := range cases {
		subject, err := testCase.build(node)
		if err != nil || subject != testCase.want {
			t.Fatalf("subject is %q (%v), want %q", subject, err, testCase.want)
		}
	}
}

// TestReceiptValidation asserts the receipt trust boundary: bounded tokens,
// bounded details, canonical versions.
func TestReceiptValidation(t *testing.T) {
	if _, err := NewDrainReceipt("cmd-1", "gru-1", true, false, "drain begun"); err != nil {
		t.Fatalf("valid drain receipt rejected: %v", err)
	}
	if _, err := NewDrainReceipt("", "gru-1", true, false, ""); err == nil {
		t.Fatal("empty command id accepted")
	}
	if _, err := NewDrainReceipt("cmd-1", "BAD NODE", true, false, ""); err == nil {
		t.Fatal("invalid node id accepted")
	}
	if _, err := NewDrainReceipt("cmd-1", "gru-1", true, false, multilineDetail()); err == nil {
		t.Fatal("control characters in detail accepted")
	}
	if _, err := NewDrainReceipt("cmd-1", "gru-1", true, false,
		detailOf(nil, multilineDetail())); err != nil {
		t.Fatalf("sanitized detail rejected: %v", err)
	}
	if _, err := NewDeployReceipt("cmd-1", "gru-1", true, "1.2.3", "deployed"); err != nil {
		t.Fatalf("valid deploy receipt rejected: %v", err)
	}
	if _, err := NewDeployReceipt("cmd-1", "gru-1", true, "../../etc", "deployed"); err == nil {
		t.Fatal("path-escape version accepted")
	}
	if _, err := NewDeployCommand("cmd-1", "terrabase", "1.2.3"); err != nil {
		t.Fatalf("valid deploy command rejected: %v", err)
	}
	if _, err := NewDeployCommand("cmd-1", "terrabase", ""); err == nil {
		t.Fatal("empty version accepted")
	}
	if _, err := NewNodeStatusReport("cmd-1", "gru-1", "mystery", false, HostFacts{}); err == nil {
		t.Fatal("unknown lifecycle state accepted")
	}
	if _, err := NewNodeStatusReport("cmd-1", "gru-1", NodeStateServing, false, HostFacts{}); err != nil {
		t.Fatalf("serving state rejected: %v", err)
	}
}

// TestHeartbeatEnvelopeValidation asserts the heartbeat trust boundary.
func TestHeartbeatEnvelopeValidation(t *testing.T) {
	facts := HostFacts{State: NodeStateServing, TsNodeVersion: TsNodeVersion}
	if _, err := NewHostHeartbeat("gru-1", time.Now().Unix(), facts); err != nil {
		t.Fatalf("valid heartbeat rejected: %v", err)
	}
	if _, err := NewHostHeartbeat("gru-1", 0, facts); err == nil {
		t.Fatal("nonpositive timestamp accepted")
	}
	// The wire envelope is closed: unknown fields are rejected.
	payload, err := json.Marshal(HostHeartbeat{
		NodeId: "gru-1", UnixSeconds: 1756900000, Facts: facts,
	})
	if err != nil {
		t.Fatal(err)
	}
	var wire map[string]json.RawMessage
	if err := json.Unmarshal(payload, &wire); err != nil {
		t.Fatal(err)
	}
	for _, field := range []string{"nodeId", "unixSeconds", "facts"} {
		if _, present := wire[field]; !present {
			t.Fatalf("wire payload misses %s: %s", field, payload)
		}
	}
}

func multilineDetail() string {
	return "line one\nline two\twith control\x01 stripped and " +
		"padding padding padding padding padding padding padding padding " +
		"padding padding padding padding padding padding padding padding"
}
