//go:build ignore

package main

import (
	"bufio"
	"bytes"
	"context"
	"encoding/json/v2"
	"os"
	"os/exec"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"git.terrascale.tech/TerraScale/ts-orchestrator/internal/authority"
	"git.terrascale.tech/TerraScale/ts-orchestrator/internal/delivery"
	"git.terrascale.tech/TerraScale/ts-orchestrator/internal/natscell"
	"github.com/nats-io/nats.go/jetstream"
	"github.com/nats-io/nkeys"
)

func TestDiagnosticUsesAuthenticatedReplyInboxes(t *testing.T) {
	controllerPublic, controllerSeed := diagnosticIdentity(t, "controller")
	operatorPublic, operatorSeed := diagnosticIdentity(t, "operator")
	ctx, cancel := context.WithTimeout(t.Context(), 20*time.Second)
	defer cancel()
	regional, err := natscell.Start(ctx, natscell.Config{
		Cell: "lab", Instance: "controller", Replicas: 1, Lab: true, NKeySeedFile: controllerSeed,
		Embedded: &natscell.Embedded{Host: "127.0.0.1", Port: -1, StoreDir: t.TempDir(),
			Users: []natscell.NKeyGrant{{PublicKey: controllerPublic, Role: "controller"},
				{PublicKey: operatorPublic, Role: "operator"}}},
	})
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = regional.Close() })
	control, err := authority.Start(ctx, regional.JetStream(), authority.Config{
		Scope: "lab", CandidateID: "diagnostic", Replicas: 1,
	})
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = control.Close() })
	if _, err := regional.JetStream().CreateStream(ctx, jetstream.StreamConfig{
		Name: delivery.IntentStream, Subjects: []string{delivery.IntentSubject("lab")}, Replicas: 1,
	}); err != nil {
		t.Fatal(err)
	}
	if _, err := regional.JetStream().CreateConsumer(ctx, delivery.IntentStream, jetstream.ConsumerConfig{
		Durable: delivery.IntentConsumer, AckPolicy: jetstream.AckExplicitPolicy,
	}); err != nil {
		t.Fatal(err)
	}
	if _, err := regional.JetStream().CreateKeyValue(ctx, jetstream.KeyValueConfig{
		Bucket: "TS_HOST_STATE", Replicas: 1,
	}); err != nil {
		t.Fatal(err)
	}

	probeCtx, probeCancel := context.WithTimeout(t.Context(), 60*time.Second)
	defer probeCancel()
	command := exec.CommandContext(probeCtx, "go", "run", "natsdiag.go", "--seed", controllerSeed,
		"--operator-seed", operatorSeed, "--cell", "lab", "--urls", regional.URL())
	output, err := command.CombinedOutput()
	if err != nil {
		t.Fatalf("diagnostic command: %v: %s", err, output)
	}
	seen := make(map[string]bool)
	scanner := bufio.NewScanner(bytes.NewReader(output))
	for scanner.Scan() {
		var record map[string]any
		if err := json.Unmarshal(scanner.Bytes(), &record); err != nil {
			t.Fatalf("decode diagnostic record: %v", err)
		}
		role, ok := record["role"].(string)
		if !ok || seen[role] {
			t.Fatalf("unexpected diagnostic role: %v", record["role"])
		}
		seen[role] = true
		for key := range record {
			if strings.HasSuffix(key, "_error") {
				t.Fatalf("%s probe failed at %s: %v", role, key, record[key])
			}
		}
		for _, key := range []string{"account", "stream_TS_CONTROL_LOG", "stream_TS_DELIVERY_INTENTS",
			"stream_KV_TS_HOST_STATE", "authority"} {
			if _, ok := record[key]; !ok {
				t.Fatalf("%s diagnostic missing %s", role, key)
			}
		}
		_, consumer := record["delivery_consumer"]
		if consumer != (role == "controller") {
			t.Fatalf("%s consumer probe visibility = %t", role, consumer)
		}
	}
	if err := scanner.Err(); err != nil {
		t.Fatal(err)
	}
	if len(seen) != 2 || !seen["controller"] || !seen["operator"] {
		t.Fatalf("diagnostic roles = %v", seen)
	}
}

func diagnosticIdentity(t *testing.T, name string) (string, string) {
	t.Helper()
	pair, err := nkeys.CreateUser()
	if err != nil {
		t.Fatal(err)
	}
	defer pair.Wipe()
	public, err := pair.PublicKey()
	if err != nil {
		t.Fatal(err)
	}
	seed, err := pair.Seed()
	if err != nil {
		t.Fatal(err)
	}
	defer clear(seed)
	path := filepath.Join(t.TempDir(), name+".nk")
	if err := os.WriteFile(path, seed, 0o600); err != nil {
		t.Fatal(err)
	}
	return public, path
}
