package app

import (
	"testing"

	"github.com/TerraScale/ts-orchestrator/internal/trust"

	"github.com/nats-io/nats.go/jetstream"
)

func publishFunctionRootHistory(t *testing.T, js jetstream.JetStream, roots *rootRegistry) {
	t.Helper()
	if err := roots.open(t.Context(), js, 1); err != nil {
		t.Fatal(err)
	}
	wire, err := trust.EncodeRootChain(roots.reply("").Chain)
	if err != nil {
		t.Fatal(err)
	}
	if _, err := roots.kv.Put(t.Context(), rootChainKey, wire); err != nil {
		t.Fatal(err)
	}
}
