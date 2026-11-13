package main

import (
	"bytes"
	"context"
	"encoding/json"
	"fmt"
	"os"
	"os/exec"
	"path/filepath"
	"strings"
	"time"

	"github.com/TerraScale/ts-orchestrator/internal/releasepush"
	"github.com/nats-io/nats-server/v2/server"
	"github.com/nats-io/nats.go"
)

func commitCase(ctx context.Context, work, outcome string) {
	must(os.MkdirAll(filepath.Join(work, "nats"), 0o700))
	helper, err := os.Executable()
	must(err)
	data, err := os.ReadFile(helper)
	must(err)
	candidate := filepath.Join(work, "asset")
	must(os.WriteFile(candidate, append(append([]byte{}, data...), []byte("\nCANDIDATE:pass")...), 0o755))
	h, err := releasepush.NewHandler(work)
	must(err)
	h.Binary, h.Revision = filepath.Join(work, "installed"), strings.Repeat("a", 40)
	must(os.WriteFile(h.Binary, data, 0o755))
	write(h.Binary+".prev", "old previous")
	write(h.RunIDFile, "1")
	write(h.TrialFile, `{"sha":"old trial"}`)
	write(h.RollbackFile, `{"sha":"old rollback"}`)
	release, verifier, client, closeProvider := signedRelease(ctx, candidate, releasepush.Revision(), "2", "1")
	defer closeProvider()
	h.Verifier, h.Client = verifier, client
	relays := 0
	h.Relay = func(context.Context, []byte) []releasepush.HostVersion { relays++; return nil }
	listener, err := server.NewServer(&server.Options{Host: "127.0.0.1", Port: -1, NoSigs: true, NoLog: true})
	must(err)
	go listener.Start()
	require(listener.ReadyForConnections(5*time.Second), "commit listener must listen")
	defer listener.Shutdown()
	conn, err := nats.Connect(listener.ClientURL())
	must(err)
	defer conn.Close()
	must(h.Serve(conn))
	payload, err := json.Marshal(release)
	must(err)
	write(filepath.Join(work, "armed"), "ready")
	reply := request(ctx, conn, releasepush.SubjectOrch, payload)
	current, err := os.ReadFile(h.Binary)
	must(err)
	if outcome == "rejected" {
		require(reply.State == "rejected" && reply.Refusal != nil && reply.Refusal.Kind == releasepush.RefusalHost, "precommit failure must refuse with host kind")
		require(bytes.Equal(current, data), "precommit failure must keep binary")
		for path, want := range map[string]string{h.Binary + ".prev": "old previous", h.RunIDFile: "1", h.TrialFile: `{"sha":"old trial"}`, h.RollbackFile: `{"sha":"old rollback"}`} {
			got, err := os.ReadFile(path)
			must(err)
			require(string(got) == want, "precommit failure changed "+path)
		}
		require(relays == 0 && len(h.Installed) == 0, "precommit failure must not relay or restart")
	} else {
		require(reply.State == "installed" && reply.Refusal == nil, "postcommit failure must stay installed")
		require(!bytes.Equal(current, data), "postcommit failure must keep candidate")
		select {
		case <-h.Installed:
		case <-ctx.Done():
			panic("installed release must restart")
		}
		require(relays == 1, "installed release must relay")
		trial, err := os.ReadFile(h.TrialFile)
		must(err)
		var record map[string]any
		must(json.Unmarshal(trial, &record))
		require(record["sha"] == release.SHA, "committed trial must be retained")
		stamp := record["installed"]
		reply = request(ctx, conn, releasepush.SubjectOrch, payload)
		select {
		case <-h.Installed:
		case <-ctx.Done():
			panic("duplicate reply must finish")
		}
		require(reply.State == "installed", "duplicate must stay installed")
		trial, err = os.ReadFile(h.TrialFile)
		must(err)
		must(json.Unmarshal(trial, &record))
		require(stamp == "0001-01-01T00:00:00Z" || stamp == record["installed"], "first activation stamp must win")
		run, err := os.ReadFile(h.RunIDFile)
		must(err)
		require(string(run) == "2", "installed run must be authoritative")
		_, err = os.Stat(h.RollbackFile)
		require(os.IsNotExist(err), "installed release must hide old rollback")
		cmdData, err := os.ReadFile(candidate)
		must(err)
		require(bytes.Equal(current, cmdData), "candidate bytes must remain")
		command := exec.CommandContext(ctx, h.Binary, "recover-state", work)
		output, err := command.CombinedOutput()
		require(err == nil && strings.Contains(string(output), "recovered candidate"), fmt.Sprintf("candidate startup must recover committed records: %v: %s", err, output))
		recoveredRun, err := os.ReadFile(filepath.Join(work, "nats/release-run-id"))
		must(err)
		require(string(recoveredRun) == "2", "startup must publish candidate run")
		_, err = os.Stat(filepath.Join(work, "nats/release-trial"))
		require(os.IsNotExist(err), "served candidate must clear trial")
		_, err = os.Stat(filepath.Join(work, "nats/release-rolled-back"))
		require(os.IsNotExist(err), "startup must clear obsolete rollback")
		fmt.Println("ok duplicate activation: first stamp wins; startup recovers candidate records")
	}
	fmt.Println("ok commit case:", outcome, "binary, records, relay and restart verified")
}
