package swarmruntime

import (
	"context"
	"encoding/json"
	"errors"
	"io"
	"maps"
	"net"
	"net/http"
	"net/netip"
	"slices"
	"strings"
	"time"

	"github.com/TerraScale/ts-orchestrator/internal/autoscale"
	"github.com/moby/swarmkit/v2/api"
)

type replicaCounter struct {
	at    time.Time
	count uint64
	nodes string
}

type replicaSource struct {
	client    api.ControlClient
	local     string
	address   func(*api.Node) (string, error)
	executor  *Executor
	windows   map[autoscale.Target]*autoscale.WindowStore
	previous  map[string]replicaCounter
	available map[autoscale.Target]bool
	loads     map[string]ReplicaTelemetry
	warm      map[autoscale.Target]time.Time
}

func (s *replicaSource) Reset() {
	s.windows = make(map[autoscale.Target]*autoscale.WindowStore)
	s.previous = make(map[string]replicaCounter)
	s.available = make(map[autoscale.Target]bool)
	s.loads = nil
	s.warm = make(map[autoscale.Target]time.Time)
}

func (s *replicaSource) Observe(ctx context.Context, service *api.Service, target autoscale.Target, now time.Time) error {
	s.available[target] = false
	tasks, err := s.client.ListTasks(ctx, &api.ListTasksRequest{Filters: &api.ListTasksRequest_Filters{ServiceIDs: []string{service.ID}}})
	if err != nil {
		return err
	}
	loads := s.loads
	if loads == nil {
		nodes, err := s.client.ListNodes(ctx, &api.ListNodesRequest{})
		if err != nil {
			return err
		}
		loads = make(map[string]ReplicaTelemetry)
		for _, node := range nodes.Nodes {
			if node.Status.State != api.NodeStatus_READY || node.Spec.Availability != api.NodeAvailabilityActive {
				continue
			}
			var load ReplicaTelemetry
			if node.ID == s.local {
				load, err = s.executor.ReplicaLoad(ctx)
			} else {
				var address string
				address, err = s.address(node)
				if err == nil {
					load, err = readReplicaLoad(ctx, address)
				}
			}
			if err != nil || load.NodeID != node.ID {
				return errors.New("replica telemetry unavailable for current regional membership")
			}
			loads[node.ID] = load
		}
		s.loads = loads
	}
	requests := uint64(0)
	for _, load := range loads {
		requests += load.Requests[target.Role]
	}
	cpu, memory, count := 0.0, 0.0, 0
	for _, task := range tasks.Tasks {
		if task.DesiredState != api.TaskStateRunning {
			continue
		}
		usage, ok := loads[task.NodeID].Tasks[task.ID]
		resources := task.Spec.Resources
		if !ok || task.Status.State != api.TaskStateRunning || usage.CPUCores == nil || usage.MemoryBytes == nil || resources == nil || resources.Reservations == nil || resources.Reservations.NanoCPUs <= 0 || resources.Reservations.MemoryBytes <= 0 {
			return errors.New("replica telemetry does not cover the running service")
		}
		cpu += *usage.CPUCores * 1e9 / float64(resources.Reservations.NanoCPUs)
		memory += float64(*usage.MemoryBytes) / float64(resources.Reservations.MemoryBytes)
		count++
	}
	if count == 0 || uint64(count) != service.Spec.GetReplicated().Replicas {
		return errors.New("replica telemetry awaits convergence")
	}
	members := slices.Sorted(maps.Keys(loads))
	membership := strings.Join(members, ",")
	previous := s.previous[service.ID]
	s.previous[service.ID] = replicaCounter{at: now, count: requests, nodes: membership}
	if previous.nodes != membership || previous.at.IsZero() || requests < previous.count || now.Sub(previous.at) > 15*time.Second || count != int(service.Spec.GetReplicated().Replicas) {
		return errors.New("request counters require a continuous current replica window")
	}
	rate := float64(requests-previous.count) / now.Sub(previous.at).Seconds() / float64(count)
	for signal, value := range map[autoscale.SignalName]float64{autoscale.SignalCPUUtilization: cpu / float64(count), autoscale.SignalMemoryUtilization: memory / float64(count), autoscale.SignalRequestRatePerReplica: rate} {
		if s.windows[target] == nil {
			s.windows[target] = autoscale.NewWindowStore(time.Minute, 64)
		}
		s.windows[target].Record(target, signal, autoscale.Sample{At: now, Value: value})
	}
	if s.warm[target].IsZero() {
		s.warm[target] = now
	}
	s.available[target] = true
	return nil
}

func (s *replicaSource) Read(ctx context.Context, target autoscale.Target, signal autoscale.Signal, now time.Time) (autoscale.Reading, error) {
	if !s.available[target] || now.Sub(s.warm[target]) < time.Minute {
		return autoscale.Reading{}, nil
	}
	reading, err := s.windows[target].Read(ctx, target, signal, now)
	if reading.Samples < 4 {
		return autoscale.Reading{}, err
	}
	return reading, err
}

func readReplicaLoad(ctx context.Context, host string) (ReplicaTelemetry, error) {
	var result ReplicaTelemetry
	address, err := netip.ParseAddr(host)
	if err != nil || !address.Is4() || !address.IsPrivate() {
		return result, errors.New("replica telemetry requires a private regional address")
	}
	transport := &http.Transport{DialContext: (&net.Dialer{Timeout: time.Second}).DialContext, DisableKeepAlives: true}
	defer transport.CloseIdleConnections()
	client := &http.Client{Transport: transport, Timeout: 2 * time.Second, CheckRedirect: func(*http.Request, []*http.Request) error { return http.ErrUseLastResponse }}
	request, err := http.NewRequestWithContext(ctx, http.MethodGet, "http://"+net.JoinHostPort(address.String(), "9108")+"/replica-load", nil)
	if err != nil {
		return result, err
	}
	response, err := client.Do(request)
	if err != nil {
		return result, err
	}
	defer response.Body.Close()
	if response.StatusCode != http.StatusOK {
		return result, errors.New("replica telemetry endpoint unavailable")
	}
	err = json.NewDecoder(io.LimitReader(response.Body, 1<<20)).Decode(&result)
	return result, err
}

func (s *replicaSource) retain(active map[autoscale.Target]bool, services map[string]bool) {
	for target := range s.available {
		if !active[target] {
			delete(s.windows, target)
			delete(s.warm, target)
			delete(s.available, target)
		}
	}
	for id := range s.previous {
		if !services[id] {
			delete(s.previous, id)
		}
	}
}
