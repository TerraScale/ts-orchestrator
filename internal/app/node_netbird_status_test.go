package app

import (
	"context"
	"encoding/json/v2"
	"strings"
	"testing"

	"github.com/nats-io/nats.go/jetstream"

	network "git.terrascale.tech/TerraScale/ts-orchestrator/internal/netbird/rollout"
)

type disappearingNetBirdStatusKV struct {
	jetstream.KeyValue
	key string
}

func (k disappearingNetBirdStatusKV) Get(ctx context.Context, key string) (jetstream.KeyValueEntry, error) {
	if key == k.key {
		if err := k.KeyValue.Delete(ctx, key); err != nil {
			return nil, err
		}
	}
	return k.KeyValue.Get(ctx, key)
}

func TestNodeStatusSkipsDisappearedNetBirdKeysAndReportsCorruption(t *testing.T) {
	kv := fenceKV(t)
	put := func(key string, value any) {
		t.Helper()
		wire, err := json.Marshal(value)
		if err != nil {
			t.Fatal(err)
		}
		if _, err := kv.Put(t.Context(), key, wire); err != nil {
			t.Fatal(err)
		}
	}
	put("netbird.status.present", network.Status{Version: "0.80.0"})
	put("netbird.status.gone", network.Status{Version: "0.79.0"})
	ops := nodeOps{fence: &releaseFence{kv: disappearingNetBirdStatusKV{KeyValue: kv, key: "netbird.status.gone"}, fencer: &fenceLease{}}}
	if err := saveNetBirdTestRecord(t.Context(), &netbirdRollout{fence: ops.fence}, 3, network.Record{ID: "7E5HKSCCJSQJGMM2DVVHCQDQFV", Node: "present"}); err != nil {
		t.Fatal(err)
	}
	status, err := ops.status(t.Context())
	if err != nil || status.NetBird == nil || status.NetBird.ID != "7E5HKSCCJSQJGMM2DVVHCQDQFV" || len(status.NetBirdNodes) != 1 || status.NetBirdNodes["present"].Version != "0.80.0" {
		t.Fatalf("disappearing node lost otherwise valid status: %+v %v", status, err)
	}
	if _, err := kv.Put(t.Context(), "netbird.status.present", []byte(`{"unexpected":true}`)); err != nil {
		t.Fatal(err)
	}
	if _, err := ops.status(t.Context()); err == nil || !strings.Contains(err.Error(), "unexpected") {
		t.Fatalf("status hid a corrupt node record: %v", err)
	}
}
