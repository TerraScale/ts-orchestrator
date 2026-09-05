package candidatesync

import (
	"context"
	"github.com/nats-io/nats.go/jetstream"
	"terrascale.tech/orchestrator/src/orchestrator/preliminarytransfer"
	"testing"
)

func TestPrivateBrokerAccountIsolation(t *testing.T) {
	path := t.TempDir()
	b, err := startBroker(context.Background(), path, 16<<20, []preliminarytransfer.ObjectMapping{{Account: "GLOBAL", Stream: "SPEC"}, {Account: "REGIONAL", Stream: "EVENTS"}})
	if err != nil {
		t.Fatal(err)
	}
	if b.server.Addr() != nil {
		t.Fatal("private broker opened a client listener")
	}
	global, _ := jetstream.New(b.connections["GLOBAL"])
	regional, _ := jetstream.New(b.connections["REGIONAL"])
	if _, err := global.CreateStream(context.Background(), jetstream.StreamConfig{Name: "SPEC", Subjects: []string{"spec"}, Storage: jetstream.FileStorage, MaxBytes: 1 << 20}); err != nil {
		t.Fatal(err)
	}
	if _, err := regional.Stream(context.Background(), "SPEC"); err == nil {
		t.Fatal("account stream isolation failed")
	}
	b.close()
	if err := inspectTree(path, false); err != nil {
		t.Fatal(err)
	}
}
