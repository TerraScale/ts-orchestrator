package main

import (
	"bytes"
	"context"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"fmt"
	"os"
	"os/exec"
	"path/filepath"
	"strings"
	"syscall"
	"time"

	"github.com/TerraScale/ts-orchestrator/internal/releasepush"
	"github.com/nats-io/nats-server/v2/server"
	"github.com/nats-io/nats.go"
)

func stamped(data []byte, sha, mode string) []byte {
	before := []byte("vcs.revision=" + releasepush.Revision())
	require(bytes.Contains(data, before), "journey helper must have a clean build revision")
	return append(bytes.ReplaceAll(data, before, []byte("vcs.revision="+sha)), []byte("\nCANDIDATE:"+mode)...)
}

func digest(data []byte) string {
	sum := sha256.Sum256(data)
	return hex.EncodeToString(sum[:])
}

func rows(path string) []map[string]any {
	data, err := os.ReadFile(path)
	if os.IsNotExist(err) {
		return nil
	}
	must(err)
	var records []map[string]any
	must(json.Unmarshal(data, &records))
	return records
}

func active(path string, data []byte) map[string]any {
	sum := digest(data)
	for _, row := range rows(path) {
		if row["sha256"] == sum {
			return row
		}
	}
	return nil
}

func listener(h *releasepush.Handler) (*nats.Conn, func()) {
	srv, err := server.NewServer(&server.Options{Host: "127.0.0.1", Port: -1, NoSigs: true, NoLog: true})
	must(err)
	go srv.Start()
	require(srv.ReadyForConnections(5*time.Second), "release listener must listen")
	conn, err := nats.Connect(srv.ClientURL())
	must(err)
	must(h.Serve(conn))
	return conn, func() { conn.Close(); srv.Shutdown() }
}

func preparedHost(work string) (*releasepush.Handler, []byte, []byte) {
	must(os.MkdirAll(filepath.Join(work, "nats"), 0o700))
	helper, err := os.Executable()
	must(err)
	data, err := os.ReadFile(helper)
	must(err)
	original := stamped(data, strings.Repeat("a", 40), "original")
	candidate := stamped(data, strings.Repeat("b", 40), "pass")
	binary := filepath.Join(work, "installed")
	if _, err := os.Stat(binary); os.IsNotExist(err) {
		must(os.WriteFile(binary, original, 0o755))
		write(binary+".prev-obsolete", "superseded")
		must(os.WriteFile(filepath.Join(work, "asset"), candidate, 0o755))
		record, err := json.Marshal([]any{map[string]any{"sha": strings.Repeat("a", 40), "sha256": digest(original), "run_id": "1"}})
		must(err)
		write(filepath.Join(work, "nats/release-run-id"), string(record))
	}
	h, err := releasepush.NewHandler(work)
	must(err)
	h.Binary, h.Revision = binary, strings.Repeat("a", 40)
	return h, original, candidate
}

func installRequest(ctx context.Context, h *releasepush.Handler, conn *nats.Conn, work, sha, run string) releasepush.Reply {
	release, verifier, client, closeProvider := signedRelease(ctx, filepath.Join(work, "asset"), sha, run, "1")
	defer closeProvider()
	h.Verifier, h.Client = verifier, client
	payload, err := json.Marshal(release)
	must(err)
	return request(ctx, conn, releasepush.SubjectOrch, payload)
}

func commitCase(ctx context.Context, work, outcome string) {
	h, original, candidate := preparedHost(work)
	if outcome == "persistent" {
		write(filepath.Join(work, "armed"), "ready")
		must(syscall.Exec(h.Binary, []string{h.Binary, "self-update", work, "postcommit-failures"}, os.Environ()))
	}
	conn, closeListener := listener(h)
	defer closeListener()
	relays := 0
	h.Relay = func(context.Context, []byte) []releasepush.HostVersion { relays++; return nil }
	write(filepath.Join(work, "armed"), "ready")
	reply := releasepush.Reply{State: "installed"}
	if outcome != "committed" {
		reply = installRequest(ctx, h, conn, work, strings.Repeat("b", 40), "2")
	}
	current, err := os.ReadFile(h.Binary)
	must(err)
	preflightRelays := 0
	if reply.Refusal != nil && reply.Refusal.Preflight {
		preflightRelays = 1
	}
	if outcome == "rejected" {
		require(reply.State == "rejected" && reply.Refusal != nil && reply.Refusal.Kind == releasepush.RefusalHost, "precommit failure must be a host refusal")
		require(bytes.Equal(current, original), "precommit failure must keep installed bytes")
		fence := active(h.RunIDFile, original)
		require(fence != nil && fence["run_id"] == "1", "abandoned attempt must preserve installed run fence")
		require(active(h.TrialFile, original) == nil, "abandoned trial must be inert")
		require(relays == preflightRelays && len(h.Installed) == 0, "precommit failure must not restart; only preflight refusals collect worker evidence")
		reply = installRequest(ctx, h, conn, work, strings.Repeat("b", 40), "2")
		require(reply.State == "installed", "same run must succeed after precommit failure")
	} else {
		require(reply.State == "installed", fmt.Sprintf("postcommit failure must stay installed: %+v", reply))
	}
	current, err = os.ReadFile(h.Binary)
	must(err)
	require(bytes.Equal(current, candidate), "candidate bytes must be installed")
	require(active(h.RunIDFile, candidate)["run_id"] == "2", "installed run must name candidate bytes")
	require(active(h.TrialFile, candidate)["sha"] == strings.Repeat("b", 40), "trial must name candidate revision and digest")
	require(active(h.RollbackFile, candidate)["sha"] == strings.Repeat("b", 40), "rollback marker must name candidate")
	require(active(h.RefusalFile, candidate) != nil, "attempt must exist before commit even if later writes fail")
	if outcome != "committed" {
		require(relays == 1+preflightRelays, "installed release must relay once")
		select {
		case <-h.Installed:
		case <-ctx.Done():
			panic("installed release must request restart")
		}
	}
	write(filepath.Join(work, "disarmed"), "ready")
	command := exec.CommandContext(ctx, h.Binary, "recover-state", work, "confirm")
	output, err := command.CombinedOutput()
	require(err == nil && strings.Contains(string(output), "recovered candidate"), fmt.Sprintf("real startup sequence must confirm: %v: %s", err, output))
	require(active(h.TrialFile, candidate) == nil, "confirmation must clear only installed trial")
	if outcome != "committed" && outcome != "twice" {
		fmt.Println("ok commit", outcome, ": same run, binary-tagged records and real shared startup verified")
		return
	}
	helper, err := os.Executable()
	must(err)
	data, err := os.ReadFile(helper)
	must(err)
	second := stamped(data, strings.Repeat("c", 40), "pass")
	must(os.WriteFile(filepath.Join(work, "asset"), second, 0o755))
	next, err := releasepush.NewHandler(work)
	must(err)
	next.Binary, next.Revision = h.Binary, strings.Repeat("b", 40)
	nextConn, closeNext := listener(next)
	defer closeNext()
	reply = installRequest(ctx, next, nextConn, work, strings.Repeat("c", 40), "3")
	require(reply.State == "installed", "second release must install after restart")
	require(active(next.TrialFile, second)["run_id"] == "3" && active(next.RunIDFile, second)["run_id"] == "3", "second release probation and run must be correct")
	command = exec.CommandContext(ctx, h.Binary, "recover-state", work, "inspect")
	output, err = command.CombinedOutput()
	require(err == nil && strings.Contains(string(output), "on probation"), fmt.Sprintf("second release must recover probation: %v: %s", err, output))
	fmt.Println("ok commit", outcome, ": restart, shared recovery, second release on probation; records correct")
}

func recoverCase(ctx context.Context, work, mode string) {
	probation, err := releasepush.Probe(work, os.Stderr)
	if mode == "rolled-back" {
		require(err != nil && strings.Contains(err.Error(), "rolled back"), "rollback must restart previous binary")
		fmt.Println("rolled back")
		return
	}
	must(err)
	h, err := releasepush.NewHandler(work)
	must(err)
	current, err := os.ReadFile(h.Binary)
	must(err)
	record := active(h.TrialFile, current)
	require(probation != nil && record != nil, "installed candidate must be on probation")
	require(record["starts"] == float64(1) || mode == "missing-previous", "Probe and NewHandler must share exactly one recovery")
	if mode == "missing-previous" {
		require(!probation.Served(), "missing rollback must stay unconfirmed after serving")
		conn, closeListener := listener(h)
		defer closeListener()
		version := request(ctx, conn, releasepush.SubjectVersion, nil)
		health := request(ctx, conn, releasepush.SubjectHealth, nil)
		require(version.State == "unconfirmed" && strings.Contains(version.Error, "rollback unavailable") && strings.Contains(health.Health, "unconfirmed"), "agent and release must see unconfirmed rollback failure")
		require(active(h.TrialFile, current) != nil && active(h.RollbackFile, current) != nil, "impossible rollback must retain both markers")
		unconfirmedPush(ctx, work, h, current)
		fmt.Println("candidate unconfirmed; version=unconfirmed; health=release probation unconfirmed; rollout=failed on unconfirmed health")
		return
	}
	if mode == "inspect" {
		fmt.Println("candidate on probation; one shared recovery")
		return
	}
	if mode == "slow" {
		<-time.NewTimer(100 * time.Second).C
	}
	require(probation.Served(), "healthy candidate must confirm")
	fmt.Println("recovered candidate")
}
