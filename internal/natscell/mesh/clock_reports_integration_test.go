package mesh

import (
	"encoding/json"
	"errors"
	"fmt"
	"testing"
	"time"

	"github.com/nats-io/nats.go"
	"github.com/nats-io/nats.go/jetstream"
)

func TestClockReportsReachReplicatedKVWithScopedTerraBaseToken(t *testing.T) {
	regions, nodes, _ := startMeshRegions(t, 0)
	node := nodes[regions[0]]
	client, err := nats.Connect(fmt.Sprintf("nats://127.0.0.1:%d", node.cfg.localPort), nats.Token(testTerraBaseToken))
	if err != nil {
		t.Fatal(err)
	}
	defer client.Close()
	skew := 100.0
	report, err := json.Marshal(clockReport{Node: "ts-gru-1", Region: "gru", SkewMilliseconds: &skew, SampledAt: time.Now().UTC()})
	if err != nil {
		t.Fatal(err)
	}
	waitFor(t, 30*time.Second, "clock report stored", func() error {
		message, err := client.RequestWithContext(t.Context(), ClockReportSubject, report)
		if err != nil {
			return err
		}
		if string(message.Data) != `{"stored":true}` {
			return errors.New("clock report not stored")
		}
		return nil
	})
	js, err := jetstream.New(nodes[regions[1]].fabric)
	if err != nil {
		t.Fatal(err)
	}
	kv, err := js.KeyValue(t.Context(), ClockReportBucket)
	if err != nil {
		t.Fatal(err)
	}
	entry, err := kv.Get(t.Context(), "ts-gru-1")
	if err != nil {
		t.Fatal(err)
	}
	var stored clockReport
	if err := json.Unmarshal(entry.Value(), &stored); err != nil {
		t.Fatal(err)
	}
	if stored.Node != "ts-gru-1" || stored.SkewMilliseconds == nil || *stored.SkewMilliseconds != 100 || stored.LocalWritesAllowed {
		t.Fatalf("unexpected clock report: %+v", stored)
	}
}
