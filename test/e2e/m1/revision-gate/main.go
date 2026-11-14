package main

import (
	"context"
	"encoding/json"
	"fmt"
	"os"
	"os/exec"
	"path/filepath"
	"strings"
	"time"

	"github.com/TerraScale/ts-orchestrator/internal/natscell/mesh"
	"github.com/TerraScale/ts-orchestrator/internal/protocol"
	"github.com/TerraScale/ts-orchestrator/internal/regionhealth"
	"github.com/TerraScale/ts-orchestrator/internal/releasepush"
	"github.com/nats-io/nats-server/v2/server"
	"github.com/nats-io/nats.go"
)

func must(err error) {
	if err != nil {
		panic(err)
	}
}

func main() {
	ctx, cancel := context.WithTimeout(context.Background(), time.Minute)
	defer cancel()
	must(os.MkdirAll("/var/lib/ts-orch/mesh", 0o700))
	must(os.WriteFile(filepath.Join("/var/lib/ts-orch/mesh", "client.token"), []byte("lane"), 0o600))
	listener, err := server.NewServer(&server.Options{Host: "127.0.0.1", Port: mesh.LocalPort, ServerName: "gru.revision", NoSigs: true, NoLog: true})
	must(err)
	go listener.Start()
	if !listener.ReadyForConnections(5 * time.Second) {
		panic("revision listener must listen")
	}
	defer listener.Shutdown()
	conn, err := nats.Connect(listener.ClientURL())
	must(err)
	defer conn.Close()
	expected := strings.Repeat("a", 40)
	for _, mode := range []string{"all-current", "old", "missing", "refused", "inventory-error", "empty", "unreachable"} {
		reports := map[string]regionhealth.Report{}
		for _, region := range mesh.Regions() {
			reports[region] = regionhealth.Report{Region: region, State: regionhealth.StateOK, Hosts: []releasepush.HostVersion{{ID: region + "-node", Host: region + "-host", Version: expected}}}
		}
		target := mesh.Regions()[0]
		report := reports[target]
		switch mode {
		case "old":
			report.Hosts[0].Version = strings.Repeat("b", 40)
		case "missing":
			report.Hosts[0].Version = ""
			report.Hosts[0].Error = "host reports no running revision"
		case "refused":
			report.Hosts[0].Refusal = &releasepush.Refusal{Kind: releasepush.RefusalHost, SHA: expected, Reason: "disk unavailable"}
		case "inventory-error":
			report.HostError = "node inventory unavailable"
		case "empty":
			report.Hosts = nil
		}
		reports[target] = report
		if mode == "unreachable" {
			delete(reports, target)
		}
		sub, err := conn.Subscribe(protocol.MeshHealthSubject, func(message *nats.Msg) {
			for _, report := range reports {
				data, err := json.Marshal(report)
				must(err)
				must(message.Respond(data))
			}
		})
		must(err)
		must(conn.Flush())
		command := exec.CommandContext(ctx, os.Args[1], "status", "revision", expected)
		output, err := command.CombinedOutput()
		code := command.ProcessState.ExitCode()
		if (mode == "all-current" && (err != nil || code != 0)) || (mode != "all-current" && (err == nil || code == 0)) {
			panic(fmt.Sprintf("%s: exit=%d err=%v output=%s", mode, code, err, output))
		}
		if mode != "all-current" && !strings.Contains(string(output), target+" host ") {
			panic("gate must name failing host or region inventory")
		}
		must(sub.Unsubscribe())
		must(conn.Flush())
		fmt.Printf("ok revision gate %s: exit=%d\n", mode, code)
	}
	fmt.Println("revision-gate e2e: PASS")
}
