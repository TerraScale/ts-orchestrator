package host

import (
	"crypto/ed25519"
	"crypto/sha256"
	"encoding/hex"
	"fmt"
	"net"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
	"time"

	"github.com/TerraScale/ts-orchestrator/internal/terrabase"
)

func TestTerraBaseDigestSwapStopsWhenBackupzIsNotOK(t *testing.T) {
	backup := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.URL.Path != "/backupz" {
			http.NotFound(w, r)
			return
		}
		w.WriteHeader(http.StatusServiceUnavailable)
	}))
	t.Cleanup(backup.Close)
	adminPort := backup.Listener.Addr().(*net.TCPAddr).Port

	c, conn, store, _, controllerKey := testController(t)
	hostKey := registerTestHost(t, c)
	put := func(body []byte) string {
		t.Helper()
		hash := sha256.Sum256(body)
		digest := hex.EncodeToString(hash[:])
		if _, err := store.PutBytes(t.Context(), "sha256-"+digest, body); err != nil {
			t.Fatal(err)
		}
		return digest
	}
	first := put([]byte("#!/bin/sh\nsleep 30\n"))
	next := put([]byte("#!/bin/sh\nsleep 31\n"))
	desired := Desired{Cell: "gru", Node: "node-a", Environment: "production", Role: terrabase.Role, Digest: first, Generation: 1, AuthorityEpoch: 1}
	if _, err := c.ApplyDesired(t.Context(), desired); err != nil {
		t.Fatal(err)
	}
	ctx := t.Context()
	controllerDone := make(chan error, 1)
	go func() { controllerDone <- c.Run(ctx) }()
	select {
	case <-c.Ready():
	case err := <-controllerDone:
		t.Fatalf("host controller failed before ready: %v", err)
	case <-ctx.Done():
		t.Fatal(ctx.Err())
	}
	runner := &memoryRunner{observed: make(map[string]Observation)}
	agent, err := NewAgent(AgentConfig{NATSUserPublicKey: testNATSUserKey("node-a"), ClockCheck: func() error { return nil }, WorkloadIdentity: testAgentIdentity(), Cell: "gru", Node: "node-a", Environment: "production", Roles: []string{terrabase.Role}, Conn: conn, Identity: hostKey, ControllerPublicKey: controllerKey.Public().(ed25519.PublicKey), Runner: runner, InstallRoot: testAgentInstallRoot(t), StateRoot: testAgentStateRoot(t), PollInterval: 100 * time.Millisecond})
	if err != nil {
		t.Fatal(err)
	}
	agentDone := make(chan error, 1)
	go func() { agentDone <- agent.Run(ctx) }()
	deadline := time.Now().Add(8 * time.Second)
	for {
		runner.mu.Lock()
		applied := runner.applied
		runner.mu.Unlock()
		if applied == 1 {
			break
		}
		if time.Now().After(deadline) {
			t.Fatal("first digest did not start")
		}
		time.Sleep(25 * time.Millisecond)
	}
	desired.Digest = next
	desired.Generation = 2
	desired.Env = map[string]string{
		terrabase.EnvAdminPort: fmt.Sprint(adminPort),
		terrabase.EnvPeerPort:  "9470",
		terrabase.EnvPeers:     "node-a=127.0.0.1:9470",
	}
	if _, err := c.ApplyDesired(ctx, desired); err != nil {
		t.Fatal(err)
	}
	deadline = time.Now().Add(8 * time.Second)
	var detail string
	for {
		hosts, err := c.ListHosts(ctx)
		if err == nil && len(hosts) == 1 && len(hosts[0].Reports) == 1 && hosts[0].Reports[0].Generation == 2 && hosts[0].Reports[0].State == "failed" {
			detail = hosts[0].Reports[0].Error
			if detail != "" {
				break
			}
		}
		select {
		case err := <-agentDone:
			t.Fatalf("agent exited: %v", err)
		default:
		}
		if time.Now().After(deadline) {
			t.Fatalf("swap did not fail closed, last error %q", detail)
		}
		time.Sleep(25 * time.Millisecond)
	}
	runner.mu.Lock()
	applied := runner.applied
	runner.mu.Unlock()
	if applied != 1 {
		t.Fatalf("backupz 503 applied the new digest %d times", applied)
	}
	if !strings.Contains(detail, "HTTP 503") {
		t.Fatalf("failure %q does not name the backupz status", detail)
	}
}
