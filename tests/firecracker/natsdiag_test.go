//go:build ignore

package main

import (
	"bufio"
	"bytes"
	"context"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json/v2"

	"fmt"
	"net"
	"os"
	"os/exec"
	"path/filepath"

	"strings"
	"testing"
	"time"

	"github.com/TerraScale/ts-orchestrator/internal/authority"
	"github.com/TerraScale/ts-orchestrator/internal/delivery"
	"github.com/TerraScale/ts-orchestrator/internal/natscell"

	"github.com/nats-io/nats.go/jetstream"
	"github.com/nats-io/nkeys"
)

func TestDiagnosticReadsLiveReplicatedCluster(t *testing.T) {
	controllerPublic, controllerSeed := diagnosticIdentity(t, "controller")
	operatorPublic, operatorSeed := diagnosticIdentity(t, "operator")
	ctx, cancel := context.WithTimeout(t.Context(), 60*time.Second)
	defer cancel()
	ports := make([]int, 3)
	for index := range ports {
		listener, err := net.Listen("tcp", "127.0.0.1:0")
		if err != nil {
			t.Fatal(err)
		}
		ports[index] = listener.Addr().(*net.TCPAddr).Port
		listener.Close()
	}
	routes := make([]string, len(ports))
	for index, port := range ports {
		routes[index] = fmt.Sprintf("nats-route://127.0.0.1:%d", port)
	}
	runtimes := make([]*natscell.Runtime, len(ports))
	for index := range runtimes {
		runtime, err := natscell.Start(ctx, natscell.Config{
			Cell: "lab", Instance: fmt.Sprintf("c%d", index+1), Replicas: 3, Lab: true,
			NKeySeedFile: controllerSeed,
			Embedded: &natscell.Embedded{Host: "127.0.0.1", Port: -1,
				RouteHost: "127.0.0.1", RoutePort: ports[index], Routes: routes,
				StoreDir: filepath.Join(t.TempDir(), "jetstream"),
				Users: []natscell.NKeyGrant{{PublicKey: controllerPublic, Role: "controller"},
					{PublicKey: operatorPublic, Role: "operator"}}},
		})
		if err != nil {
			t.Fatal(err)
		}
		runtimes[index] = runtime
		t.Cleanup(func() { _ = runtime.Close() })
	}
	for _, runtime := range runtimes {
		if err := runtime.WaitForCluster(ctx, 3); err != nil {
			t.Fatal(err)
		}
	}
	js := runtimes[0].JetStream()
	control, err := authority.Start(ctx, js, authority.Config{DeploymentID: "01ARZ3NDEKTSV4RRFFQ69G5FAV",
		Scope: "lab", CandidateID: "0000000000XTGQJSECWR54430J", Replicas: 3,
	})
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = control.Close() })
	if _, err := js.CreateStream(ctx, jetstream.StreamConfig{
		Name: delivery.IntentStream, Subjects: []string{delivery.IntentSubject("lab")}, Replicas: 3,
	}); err != nil {
		t.Fatal(err)
	}
	if _, err := js.CreateConsumer(ctx, delivery.IntentStream, jetstream.ConsumerConfig{
		Durable: delivery.IntentConsumer, AckPolicy: jetstream.AckExplicitPolicy,
	}); err != nil {
		t.Fatal(err)
	}
	if _, err := js.CreateObjectStore(ctx, jetstream.ObjectStoreConfig{Bucket: "TS_ARTIFACTS", Replicas: 3}); err != nil {
		t.Fatal(err)
	}
	if _, err := js.CreateKeyValue(ctx, jetstream.KeyValueConfig{Bucket: "TS_DELIVERY_ADMISSIONS", Replicas: 3}); err != nil {
		t.Fatal(err)
	}
	if _, err := js.CreateKeyValue(ctx, jetstream.KeyValueConfig{
		Bucket: "TS_HOST_STATE", Replicas: 3,
	}); err != nil {
		t.Fatal(err)
	}
	operations, err := js.CreateKeyValue(ctx, jetstream.KeyValueConfig{
		Bucket: delivery.OperationBucket, Replicas: 3,
	})
	if err != nil {
		t.Fatal(err)
	}
	sum := sha256.Sum256([]byte("fc-one-node-loss-2"))
	if _, err := operations.Put(ctx, "o_"+hex.EncodeToString(sum[:]), []byte(
		`{"intent":{"operationId":"fc-one-node-loss-2","generation":2,"authorityEpoch":1},"plan":[{}]}`)); err != nil {
		t.Fatal(err)
	}
	urls := make([]string, len(runtimes))
	for index, runtime := range runtimes {
		urls[index] = runtime.URL()
	}
	command := exec.CommandContext(ctx, "go", "run", "natsdiag.go", "--seed", controllerSeed,
		"--operator-seed", operatorSeed, "--cell", "lab", "--replicas", "3",
		"--members", "lab-c1,lab-c2,lab-c3", "--urls", strings.Join(urls, ","),
		"--operation-id", "fc-one-node-loss-2")
	output, err := command.CombinedOutput()
	if err != nil {
		t.Fatalf("replicated diagnostic command: %v: %s", err, output)
	}
	roles := map[string]int{}
	scanner := bufio.NewScanner(bytes.NewReader(output))
	for scanner.Scan() {
		var record map[string]any
		if err := json.Unmarshal(scanner.Bytes(), &record); err != nil {
			t.Fatalf("replicated diagnostic JSON: %v: %s", err, scanner.Bytes())
		}
		role := record["role"].(string)
		roles[role]++
		for key := range record {
			if strings.HasSuffix(key, "_error") {
				t.Fatalf("%s query %s failed: %v", role, key, record[key])
			}
		}
		stream := record["stream_TS_DELIVERY_INTENTS"].(map[string]any)
		cluster := stream["cluster"].(map[string]any)
		if cluster["leader"] == "" || len(cluster["replicas"].([]any)) != 2 {
			t.Fatalf("%s stream cluster metadata incomplete: %v", role, cluster)
		}
		if role == "controller" {
			consumer := record["delivery_consumer"].(map[string]any)
			if consumer["cluster"] == nil {
				t.Fatal("replicated consumer cluster metadata is missing")
			}
		}
		if record["formation_ready"] != true {
			t.Fatalf("%s formation readiness = %v", role, record["formation_ready"])
		}
		operation := record["delivery_operation"].(map[string]any)
		if operation["state"] != "claimed" || operation["plan_count"] != float64(1) {
			t.Fatalf("%s replicated operation metadata incomplete: %v", role, operation)
		}
	}
	if err := scanner.Err(); err != nil {
		t.Fatal(err)
	}
	if roles["controller"] != 3 || roles["operator"] != 1 {
		t.Fatalf("replicated probe roles = %v", roles)
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
