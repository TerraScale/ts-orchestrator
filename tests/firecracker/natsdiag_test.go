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
	operations, err := regional.JetStream().CreateKeyValue(ctx, jetstream.KeyValueConfig{
		Bucket: delivery.OperationBucket, Replicas: 1,
	})
	if err != nil {
		t.Fatal(err)
	}

	probeCtx, probeCancel := context.WithTimeout(t.Context(), 60*time.Second)
	defer probeCancel()
	command := exec.CommandContext(probeCtx, "go", "run", "natsdiag.go", "--seed", controllerSeed,
		"--operator-seed", operatorSeed, "--cell", "lab", "--urls", regional.URL(),
		"--operation-id", "fc-diagnostic-2")
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
		operation := record["delivery_operation"].(map[string]any)
		if operation["state"] != "unclaimed" {
			t.Fatalf("%s unclaimed operation = %v", role, operation)
		}
	}
	if err := scanner.Err(); err != nil {
		t.Fatal(err)
	}
	if len(seen) != 2 || !seen["controller"] || !seen["operator"] {
		t.Fatalf("diagnostic roles = %v", seen)
	}
	if err := regional.JetStream().DeleteKeyValue(ctx, "TS_HOST_STATE"); err != nil {
		t.Fatal(err)
	}
	sum := sha256.Sum256([]byte("fc-diagnostic-2"))
	if _, err := operations.Put(ctx, "o_"+hex.EncodeToString(sum[:]), []byte(
		`{"intent":{"operationId":"fc-diagnostic-2","generation":2,"authorityEpoch":3},"plan":[{}]}`)); err != nil {
		t.Fatal(err)
	}
	command = exec.CommandContext(probeCtx, "go", "run", "natsdiag.go", "--seed", controllerSeed,
		"--operator-seed", operatorSeed, "--cell", "lab", "--urls", regional.URL(),
		"--operation-id", "fc-diagnostic-2")
	output, err = command.CombinedOutput()
	if err != nil {
		t.Fatalf("diagnostic command with absent host stream: %v: %s", err, output)
	}
	scanner = bufio.NewScanner(bytes.NewReader(output))
	partialRecords := 0
	for scanner.Scan() {
		partialRecords++
		var record map[string]any
		if err := json.Unmarshal(scanner.Bytes(), &record); err != nil {
			t.Fatalf("decode partial diagnostic record: %v", err)
		}
		if _, ok := record["stream_KV_TS_HOST_STATE_error"]; !ok {
			t.Fatalf("missing query error was lost: %v", record)
		}
		if _, ok := record["stream_TS_CONTROL_LOG"]; !ok {
			t.Fatalf("successful stream query was lost: %v", record)
		}
		operation := record["delivery_operation"].(map[string]any)
		if operation["state"] != "claimed" || operation["plan_count"] != float64(1) ||
			operation["authority_epoch"] != float64(3) {
			t.Fatalf("claimed operation metadata was lost: %v", operation)
		}
	}
	if err := scanner.Err(); err != nil {
		t.Fatal(err)
	}
	if partialRecords != 2 {
		t.Fatalf("partial diagnostic records = %d, want 2", partialRecords)
	}
}

func TestDiagnosticMarshalsReplicatedClusterMetadata(t *testing.T) {
	leaderSince := time.Date(2026, time.September, 24, 12, 0, 0, 0, time.UTC)
	lastActive := leaderSince.Add(5 * time.Second)
	cluster := &jetstream.ClusterInfo{
		Name: "lab", RaftGroup: "S-R3", Leader: "c1", LeaderSince: &leaderSince,
		Replicas: []*jetstream.PeerInfo{{Name: "c2", Peer: "peer-2", Current: true,
			Active: 1500 * time.Millisecond, Lag: 3},
			{Name: "c3", Peer: "peer-3", Offline: true, Active: 10 * time.Second, Lag: 7}},
		Desired: &jetstream.DesiredClusterInfo{Name: "lab", Created: leaderSince,
			Replicas: []*jetstream.DesiredPeerInfo{{Name: "c1", Peer: "peer-1"},
				{Name: "c2", Peer: "peer-2"}},
			Status: &jetstream.DesiredClusterInfoStatus{Type: jetstream.MigrationStatusCatchup,
				Description: "waiting for catchup"}},
	}
	value := map[string]any{
		"account": accountDiagnostic(&jetstream.AccountInfo{API: jetstream.APIStats{Level: 1, Total: 9},
			Tiers: map[string]jetstream.Tier{"R3": {Streams: 2, Consumers: 1}}}),
		"stream_TS_CONTROL_LOG": streamDiagnostic(&jetstream.StreamInfo{Cluster: cluster,
			State: jetstream.StreamState{Msgs: 8, FirstSeq: 1, LastSeq: 8}}),
		"delivery_consumer": consumerDiagnostic(&jetstream.ConsumerInfo{Cluster: cluster,
			Delivered:     jetstream.SequenceInfo{Consumer: 2, Stream: 3, Last: &lastActive},
			NumAckPending: 1, NumPending: 4}),
	}
	encoded, err := json.Marshal(value)
	if err != nil {
		t.Fatalf("replicated diagnostic metadata did not marshal: %v", err)
	}
	var decoded map[string]any
	if err := json.Unmarshal(encoded, &decoded); err != nil {
		t.Fatal(err)
	}
	stream := decoded["stream_TS_CONTROL_LOG"].(map[string]any)
	streamCluster := stream["cluster"].(map[string]any)
	peers := streamCluster["replicas"].([]any)
	if streamCluster["leader"] != "c1" || len(peers) != 2 {
		t.Fatalf("stream cluster lost leader or replicas: %v", streamCluster)
	}
	first := peers[0].(map[string]any)
	if first["active_ns"] != float64((1500*time.Millisecond).Nanoseconds()) || first["lag"] != float64(3) {
		t.Fatalf("replica activity was not encoded as nanoseconds: %v", first)
	}
	consumer := decoded["delivery_consumer"].(map[string]any)
	consumerCluster := consumer["cluster"].(map[string]any)
	if consumerCluster["leader"] != "c1" || consumer["pending"] != float64(4) {
		t.Fatalf("consumer metadata missing from diagnostic: %v", consumer)
	}
}

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
	control, err := authority.Start(ctx, js, authority.Config{
		Scope: "lab", CandidateID: "diagnostic", Replicas: 3,
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
		"--operator-seed", operatorSeed, "--cell", "lab", "--urls", strings.Join(urls, ","),
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
