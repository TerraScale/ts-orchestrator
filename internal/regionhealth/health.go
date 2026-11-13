// Package regionhealth reports each region's host memory and disk pressure
// and SwarmKit state before tasks get OOM-killed: single-host checks every
// 10 s, logs every state change and answers protocol.MeshHealthSubject on the
// cross-region mesh, which `ts-orch status` asks.
package regionhealth

import (
	"context"
	"errors"
	"fmt"
	"maps"
	"slices"
	"strings"
	"time"

	"github.com/TerraScale/ts-orchestrator/internal/nodelist"
	"github.com/TerraScale/ts-orchestrator/internal/observability"
	"github.com/TerraScale/ts-orchestrator/internal/swarmruntime"
	containerd "github.com/containerd/containerd/v2/client"
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
	Region   string          `json:"region"`
	Server   string          `json:"server"`
	State    string          `json:"state"`
	Reasons  []string        `json:"reasons,omitempty"`
	At       time.Time       `json:"at"`
	NodeList nodelist.Status `json:"node_list"`
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

func Serving(ctx context.Context, state, service string) error {
	in := read(ctx, state)
	var health error
	if in.Node != "" {
		health = errors.New(in.Node)
	}
	if slices.Contains(in.Failures, "services unreadable") {
		health = errors.Join(health, errors.New("services unreadable"))
	}
	if health != nil || service == "" {
		return health
	}
	client, conn, err := swarmruntime.DialSingleHost(state)
	if err != nil {
		return err
	}
	defer conn.Close()
	return swarmruntime.ServingService(ctx, client, service)
}

func gib(bytes uint64) string { return fmt.Sprintf("%.1f GiB", float64(bytes)/(1<<30)) }

// Check reads and classifies this host now.
func Check(ctx context.Context, state string) Report { return check(ctx, state) }

// check reads and classifies this host now.
func check(ctx context.Context, state string) Report {
	status, reasons := Classify(read(ctx, state))
	return Report{State: status, Reasons: reasons, At: time.Now().UTC(), NodeList: nodelist.StatusAt(state)}
}

// read takes one Input from /proc, statfs and the single-host control socket.
func read(ctx context.Context, state string) Input {
	ctx, cancel := context.WithTimeout(ctx, 5*time.Second)
	defer cancel()
	type reading struct {
		check string
		input Input
	}
	results := make(chan reading, 4)
	go func() {
		system, err := observability.ReadSystem([]observability.FilesystemRole{{Role: "containerd", Path: containerdRoot}, {Role: "state", Path: state}})
		part := Input{System: system}
		if err != nil {
			part.Failures = []string{"memory unreadable"}
		}
		results <- reading{check: "memory unreadable", input: part}
	}()
	go func() {
		runtime, err := containerd.New(swarmruntime.HostContainerdSocket)
		if err == nil {
			_, err = runtime.Version(ctx)
			runtime.Close()
		}
		part := Input{}
		if err != nil {
			part.Node = "container runtime unreachable"
		}
		results <- reading{check: "container runtime unreachable", input: part}
	}()
	go func() {
		part := Input{}
		client, conn, err := swarmruntime.DialSingleHost(state)
		if err != nil {
			part.Node = "swarm node unreachable"
			results <- reading{check: "swarm node unreachable", input: part}
			return
		}
		defer conn.Close()
		nodes, err := client.ListNodes(ctx, &api.ListNodesRequest{})
		if err != nil || len(nodes.Nodes) == 0 {
			part.Node = "swarm node unreachable"
		} else {
			for _, node := range nodes.Nodes {
				if node.Status.State != api.NodeStatus_READY {
					part.Node = "swarm node " + strings.ToLower(node.Status.State.String())
					break
				}
			}
		}
		results <- reading{check: "swarm node unreachable", input: part}
	}()
	go func() {
		part := Input{}
		client, conn, err := swarmruntime.DialSingleHost(state)
		if err != nil {
			part.Failures = []string{"services unreadable"}
			results <- reading{check: "services unreadable", input: part}
			return
		}
		defer conn.Close()
		services, err := swarmruntime.ListServiceSpecs(ctx, client)
		if err != nil {
			part.Failures = []string{"services unreadable"}
		}
		for _, service := range services {
			if service.Running < service.Replicas {
				part.Lagging = append(part.Lagging, service.Name)
			}
		}
		results <- reading{check: "services unreadable", input: part}
	}()
	var in Input
	pending := map[string]bool{"memory unreadable": true, "container runtime unreachable": true, "swarm node unreachable": true, "services unreadable": true}
	merge := func(result reading) {
		delete(pending, result.check)
		part := result.input
		if part.System.MemTotalBytes != 0 {
			in.System = part.System
		}
		if part.Node != "" {
			in.Node = strings.TrimSpace(in.Node + " " + part.Node)
		}
		in.Failures = append(in.Failures, part.Failures...)
		in.Lagging = append(in.Lagging, part.Lagging...)
	}
	for len(pending) != 0 {
		select {
		case part := <-results:
			merge(part)
		case <-ctx.Done():
			for len(pending) != 0 {
				select {
				case part := <-results:
					merge(part)
				default:
					in.Node = strings.TrimSpace(in.Node + " " + strings.Join(slices.Sorted(maps.Keys(pending)), ", ") + ": health check deadline exceeded")
					return in
				}
			}
		}
	}
	return in
}
