package app

import (
	"context"
	"encoding/json"
	"log/slog"
	"strings"
	"testing"

	"git.terrascale.tech/TerraScale/ts-orchestrator/internal/natscell"
	"git.terrascale.tech/TerraScale/ts-orchestrator/internal/observability"
)

func TestRuntimeLogRedactionWithoutListener(t *testing.T) {
	original := slog.Default()
	t.Cleanup(func() { slog.SetDefault(original) })
	for _, role := range []string{"controller", "host"} {
		t.Run(role, func(t *testing.T) {
			ctx, cancel := context.WithCancel(t.Context())
			defer cancel()
			cfg := Config{NATS: natscell.Config{Cell: "lab"}, Observability: observability.Config{
				ListenAddress: observability.DisabledListenAddress, LogLevel: "error",
			}}
			runtime, err := startRuntimeObservability(ctx, cfg, role, "one")
			if err != nil {
				t.Fatal(err)
			}
			defer runtime.close()
			if runtime.server != nil {
				t.Fatal("disabled listener started")
			}
			// WARN still reaches the event ring under log_level=error.
			slog.Default().With(observability.ComponentKey, "logs").Warn(
				"request failed: Bearer fixture-bearer-ts718", "password", "fixture-password-ts718")
			events := runtime.events.Recent(1)
			if len(events) != 1 || events[0].Level != "WARN" || events[0].Component != "logs" {
				t.Fatalf("runtime event semantics changed: %+v", events)
			}
			data, err := json.Marshal(events)
			if err != nil {
				t.Fatal(err)
			}
			for _, secret := range []string{"fixture-bearer-ts718", "fixture-password-ts718"} {
				if strings.Contains(string(data), secret) {
					t.Fatal("credential reached runtime event ring")
				}
			}
			if !strings.Contains(events[0].Message, "request failed") {
				t.Fatal("redaction removed operational context")
			}
		})
	}
}
