// Package regionhealth reports each region's host memory and disk pressure
// and SwarmKit state before tasks get OOM-killed: single-host checks every
// 10 s, logs every state change and answers protocol.MeshHealthSubject on the
// cross-region mesh, which `ts-orch status` asks.
package regionhealth

import (
	"context"
	"fmt"
	"strings"
	"time"

	"github.com/TerraScale/ts-orchestrator/internal/observability"
	"github.com/TerraScale/ts-orchestrator/internal/swarmruntime"
	"github.com/moby/swarmkit/v2/api"
)

const (
	StateOK       = "ok"
	StateDegraded = "degraded"
	StateDown     = "down"

	// A host is degraded below 10% available memory or above 10% memory
	// stall (PSI some avg10), and below 10% or 5 GiB free on either disk.
	memoryMinPercent = 10
	memoryMaxStall   = 10.0
	diskMinPercent   = 10
	diskMinBytes     = 5 << 30

	containerdRoot = "/var/lib/containerd"
)

// Input is one health reading of this host.
type Input struct {
	System observability.SystemView
	// Node is why the SwarmKit node is not ready ("" when it is).
	Node string
	// Lagging names the services running fewer replicas than desired.
	Lagging []string
	// Failures are readings that could not be taken.
	Failures []string
}

// Report is one region's health, the MeshHealthSubject reply.
type Report struct {
	Region  string    `json:"region"`
	Server  string    `json:"server"`
	State   string    `json:"state"`
	Reasons []string  `json:"reasons,omitempty"`
	At      time.Time `json:"at"`
}

// Classify maps one reading to ok, degraded or down with its reasons.
func Classify(in Input) (string, []string) {
	if in.Node != "" {
		return StateDown, []string{in.Node}
	}
	reasons := append([]string{}, in.Failures...)
	if total := in.System.MemTotalBytes; total > 0 {
		available := in.System.MemAvailBytes
		if percent := available * 100 / total; percent < memoryMinPercent {
			reasons = append(reasons, fmt.Sprintf("memory %s available, %d%%", gib(available), percent))
		}
	}
	if stall := in.System.Pressure["memory"].SomeAvg10; stall > memoryMaxStall {
		reasons = append(reasons, fmt.Sprintf("memory pressure %.1f%% stalled", stall))
	}
	for _, disk := range in.System.Filesystems {
		if disk.SizeBytes == 0 {
			reasons = append(reasons, "disk "+disk.Path+" unreadable")
		} else if percent := disk.AvailBytes * 100 / disk.SizeBytes; percent < diskMinPercent || disk.AvailBytes < diskMinBytes {
			reasons = append(reasons, fmt.Sprintf("disk %s %s free, %d%%", disk.Path, gib(disk.AvailBytes), percent))
		}
	}
	if len(in.Lagging) != 0 {
		reasons = append(reasons, fmt.Sprintf("%d services below desired replicas: %s", len(in.Lagging), strings.Join(in.Lagging, ", ")))
	}
	if len(reasons) != 0 {
		return StateDegraded, reasons
	}
	return StateOK, nil
}

func gib(bytes uint64) string { return fmt.Sprintf("%.1f GiB", float64(bytes)/(1<<30)) }

// check reads and classifies this host now.
func check(ctx context.Context, state string) Report {
	status, reasons := Classify(read(ctx, state))
	return Report{State: status, Reasons: reasons, At: time.Now().UTC()}
}

// read takes one Input from /proc, statfs and the single-host control socket.
func read(ctx context.Context, state string) Input {
	var in Input
	system, err := observability.ReadSystem([]observability.FilesystemRole{{Role: "containerd", Path: containerdRoot}, {Role: "state", Path: state}})
	if err != nil {
		in.Failures = append(in.Failures, "memory unreadable")
	}
	in.System = system
	ctx, cancel := context.WithTimeout(ctx, 5*time.Second)
	defer cancel()
	client, conn, err := swarmruntime.DialSingleHost(state)
	if err != nil {
		in.Node = "swarm node unreachable"
		return in
	}
	defer conn.Close()
	nodes, err := client.ListNodes(ctx, &api.ListNodesRequest{})
	if err != nil || len(nodes.Nodes) == 0 {
		in.Node = "swarm node unreachable"
		return in
	}
	for _, node := range nodes.Nodes {
		if node.Status.State != api.NodeStatus_READY {
			in.Node = "swarm node " + strings.ToLower(node.Status.State.String())
			return in
		}
	}
	services, err := swarmruntime.ListServiceSpecs(ctx, client)
	if err != nil {
		in.Failures = append(in.Failures, "services unreadable")
	}
	for _, service := range services {
		if service.Running < service.Replicas {
			in.Lagging = append(in.Lagging, service.Name)
		}
	}
	return in
}
