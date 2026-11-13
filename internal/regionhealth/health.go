// Package regionhealth reports each region's host memory and disk pressure
// and SwarmKit state before tasks get OOM-killed: single-host checks every
// 10 s, logs every state change and answers protocol.MeshHealthSubject on the
// cross-region mesh, which `ts-orch status` asks.
package regionhealth

import (
	"context"
	"errors"
	"fmt"
	"github.com/moby/swarmkit/v2/ca"
	"maps"
	"os"
	"path/filepath"
	"slices"
	"strings"
	"sync"
	"time"

	"github.com/TerraScale/ts-orchestrator/internal/nodelist"
	"github.com/TerraScale/ts-orchestrator/internal/observability"
	"github.com/TerraScale/ts-orchestrator/internal/releasepush"
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
	rootCA []byte
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
	Region    string                    `json:"region"`
	Server    string                    `json:"server"`
	State     string                    `json:"state"`
	Reasons   []string                  `json:"reasons,omitempty"`
	At        time.Time                 `json:"at"`
	NodeList  nodelist.Status           `json:"node_list"`
	Hosts     []releasepush.HostVersion `json:"hosts,omitempty"`
	HostError string                    `json:"host_error,omitempty"`
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
	if len(in.Failures) != 0 {
		health = errors.Join(health, errors.New(strings.Join(in.Failures, ", ")))
	}
	if health != nil || service == "" {
		return health
	}
	client, conn, err := swarmruntime.DialSingleHostWithCA(state, in.rootCA)
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

func read(ctx context.Context, state string) Input {
	ctx, cancel := context.WithTimeout(ctx, 5*time.Second)
	defer cancel()
	type reading struct {
		check string
		input Input
	}
	host := sampleHost(ctx, state)
	results := make(chan reading, 4)
	results <- reading{check: "memory unreadable", input: host}
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
		client, conn, err := swarmruntime.DialSingleHostWithCA(state, host.rootCA)
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
		client, conn, err := swarmruntime.DialSingleHostWithCA(state, host.rootCA)
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
	in := Input{rootCA: host.rootCA}
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

const hostSampleBound = 5 * time.Second

const maxAbandonedHostSamples = 2

type hostObservation struct {
	started time.Time
	done    chan struct{}
}

var hostSampler struct {
	sync.Mutex
	state     string
	at        time.Time
	input     Input
	current   *hostObservation
	abandoned int
}

func sampleHost(ctx context.Context, state string) Input {
	hostSampler.Lock()
	if hostSampler.state == state && !hostSampler.at.IsZero() && time.Since(hostSampler.at) <= hostSampleBound {
		part := hostSampler.input
		hostSampler.Unlock()
		return part
	}
	if current := hostSampler.current; current != nil && time.Since(current.started) >= hostSampleBound {
		hostSampler.current = nil
		hostSampler.abandoned++
	}
	if hostSampler.current == nil && hostSampler.abandoned < maxAbandonedHostSamples {
		observation := &hostObservation{started: time.Now(), done: make(chan struct{})}
		hostSampler.current = observation
		go func() {
			system, sampleErr := observability.ReadSystem([]observability.FilesystemRole{{Role: "containerd", Path: containerdRoot}, {Role: "state", Path: state}})
			part := Input{System: system}
			root, err := os.ReadFile(ca.NewConfigPaths(filepath.Join(swarmruntime.SingleHostSwarmDir(state), "certificates")).RootCA.Cert)
			part.rootCA = root
			if err != nil {
				part.Failures = append(part.Failures, "swarm root CA unreadable")
			}
			if sampleErr != nil {
				part.Failures = append(part.Failures, "memory unreadable")
			}
			if system.MemTotalBytes == 0 {
				part.Failures = append(part.Failures, "memory unreadable")
			}
			for _, filesystem := range system.Filesystems {
				if filesystem.SizeBytes == 0 {
					part.Failures = append(part.Failures, "disk "+filesystem.Path+" unreadable")
				}
			}
			hostSampler.Lock()
			if hostSampler.current == observation {
				hostSampler.current = nil
				if time.Since(observation.started) <= hostSampleBound {
					hostSampler.state, hostSampler.at, hostSampler.input = state, observation.started, part
				}
			} else {
				hostSampler.abandoned--
			}
			close(observation.done)
			hostSampler.Unlock()
		}()
	}
	current := hostSampler.current
	hostSampler.Unlock()
	if current == nil {
		return Input{Node: "host observation abandoned-read limit reached"}
	}
	bound := time.NewTimer(max(hostSampleBound-time.Since(current.started), 0))
	defer bound.Stop()
	select {
	case <-current.done:
		hostSampler.Lock()
		defer hostSampler.Unlock()
		if hostSampler.state == state && time.Since(hostSampler.at) <= hostSampleBound {
			return hostSampler.input
		}
	case <-bound.C:
	case <-ctx.Done():
	}
	return Input{Node: "host observation unavailable or stale"}
}
