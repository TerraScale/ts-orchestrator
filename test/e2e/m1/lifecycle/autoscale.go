package main

import (
	"context"
	"crypto/tls"
	"crypto/x509"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"net"
	"net/http"
	"os"
	"path/filepath"
	"strconv"
	"sync"
	"syscall"
	"time"

	"github.com/TerraScale/ts-orchestrator/internal/autoscale"
	"github.com/TerraScale/ts-orchestrator/internal/edge"
	"github.com/TerraScale/ts-orchestrator/internal/swarmruntime"
	containerd "github.com/containerd/containerd/v2/client"
	"github.com/containerd/containerd/v2/pkg/namespaces"
	"github.com/gogo/protobuf/types"
	"github.com/moby/swarmkit/v2/api"
	"github.com/moby/swarmkit/v2/manager/scheduler"
)

func (j *journey) autoscaleUp(image string) error {
	workloads, err := j.create(image, "c11-load", "10.231.0.2", 18089, false, 1, &autoscale.Bounds{Min: 1, Max: 2})
	if err != nil {
		return err
	}
	initial := workloads[0]
	service, err := j.control.GetService(j.ctx, &api.GetServiceRequest{ServiceID: initial.task.ServiceID})
	if err != nil {
		return err
	}
	if service.Service.Spec.Annotations.Labels[swarmruntime.LabelReplicaBounds] == "" {
		return errors.New("scaling service did not declare replica bounds")
	}
	fixed, err := j.create(image, "c11-fixed", "10.231.0.2", 18090, false, 1, nil)
	if err != nil {
		return err
	}
	fixedService, err := j.control.GetService(j.ctx, &api.GetServiceRequest{ServiceID: fixed[0].task.ServiceID})
	if err != nil {
		return err
	}
	if fixedService.Service.Spec.Annotations.Labels[swarmruntime.LabelReplicaBounds] != "" {
		return errors.New("a service without replicaBounds must keep its declared count")
	}
	client, closeClient, err := autoscaleEdgeClient(j.root)
	if err != nil {
		return err
	}
	defer closeClient()
	nodes, err := j.control.ListNodes(j.ctx, &api.ListNodesRequest{})
	if err != nil {
		return err
	}
	tasks, err := j.control.ListTasks(j.ctx, &api.ListTasksRequest{})
	if err != nil {
		return err
	}
	if slots := scheduler.ReplicaCapacity(service.Service, nodes.Nodes, tasks.Tasks, 1); slots != 1 {
		return fmt.Errorf("expected one additional schedulable replica, got %d", slots)
	}
	if slots := scheduler.ReplicaCapacity(service.Service, nodes.Nodes, tasks.Tasks, 0); slots != 0 {
		return fmt.Errorf("capacity must exclude existing replicas, got %d", slots)
	}
	started := time.Now()
	load, stop := context.WithCancel(j.ctx)
	var requests sync.WaitGroup
	failures := make(chan error, 4)
	for _, host := range []string{"c11.e2e.test", "fixed.c11.e2e.test"} {
		for range 2 {
			requests.Go(func() {
				for load.Err() == nil {
					if err := edgeLoad(load, client, host); err != nil && load.Err() == nil {
						failures <- err
						return
					}
				}
			})
		}
	}
	defer func() { stop(); requests.Wait() }()
	var scaled []*workload
	var loadFailure error
	if err := until(j.ctx, func() error {
		response, err := j.control.GetService(j.ctx, &api.GetServiceRequest{ServiceID: initial.task.ServiceID})
		if err != nil {
			return err
		}
		select {
		case loadFailure = <-failures:
			return nil
		default:
		}
		if response.Service.Spec.GetReplicated().Replicas > 2 {
			loadFailure = errors.New("autoscaler exceeded its service replica bound")
			return nil
		}
		if response.Service.Spec.GetReplicated().Replicas < 2 {
			return errors.New("load has not increased service replicas: " + strconv.FormatUint(response.Service.Spec.GetReplicated().Replicas, 10))
		}
		scaled, err = j.running(initial.task.ServiceID, initial.host, initial.runtime)
		if err != nil {
			return err
		}
		if len(scaled) < 2 {
			return errors.New("scaled tasks are not serving")
		}
		return nil
	}); err != nil {
		return err
	}
	if loadFailure != nil {
		return loadFailure
	}
	if err := j.fixedService(fixed[0].task.ServiceID); err != nil {
		return err
	}
	loadResponse, err := http.Get("http://10.231.0.2:9108/replica-load")
	if err != nil {
		return err
	}
	var telemetry swarmruntime.ReplicaTelemetry
	err = json.NewDecoder(loadResponse.Body).Decode(&telemetry)
	loadResponse.Body.Close()
	if err != nil {
		return err
	}
	if telemetry.Requests["c11-load"] == 0 || telemetry.Requests["c11-fixed"] == 0 {
		return errors.New("edge admission counters did not observe the service load")
	}
	fmt.Printf("C11 admitted edge requests: scaled=%d, fixed=%d; service without bounds remains 1\n", telemetry.Requests["c11-load"], telemetry.Requests["c11-fixed"])
	fmt.Printf("C11 sustained CPU: replicas 1 -> %d in %.0fs\n", len(scaled), time.Since(started).Seconds())
	stop()
	requests.Wait()
	select {
	case err := <-failures:
		return err
	default:
	}
	killed := scaled[0]
	if err := killed.process.Kill(namespaces.WithNamespace(j.ctx, "terrascale"), syscall.SIGKILL, containerd.WithKillAll); err != nil {
		return err
	}
	if err := until(j.ctx, func() error {
		current, err := j.running(initial.task.ServiceID, initial.host, initial.runtime)
		if err != nil {
			return err
		}
		if len(current) != 2 {
			return errors.New("waiting for two serving replicas after task replacement")
		}
		var replacement *workload
		for _, task := range current {
			if task.task.ID == killed.task.ID {
				return errors.New("waiting for SwarmKit to replace the killed task")
			}
			if task.task.ID != scaled[1].task.ID {
				replacement = task
			}
		}
		if replacement == nil {
			return errors.New("waiting for a new task identity")
		}
		fmt.Printf("C11 SwarmKit replacement: %s -> %s; replicas remain 2\n", killed.task.ID, replacement.task.ID)
		return nil
	}); err != nil {
		return err
	}
	if err := j.fixedService(fixed[0].task.ServiceID); err != nil {
		return err
	}
	_, err = j.control.RemoveService(j.ctx, &api.RemoveServiceRequest{ServiceID: initial.task.ServiceID})
	return err
}

func (j *journey) autoscaleDown(image string) error {
	workloads, err := j.create(image, "c11-load", "10.231.0.2", 18089, false, 2, &autoscale.Bounds{Min: 1, Max: 2})
	if err != nil {
		return err
	}
	initial := workloads[0]
	service, err := j.control.GetService(j.ctx, &api.GetServiceRequest{ServiceID: initial.task.ServiceID})
	if err != nil {
		return err
	}
	started, err := types.TimestampFromProto(service.Service.Meta.UpdatedAt)
	if err != nil {
		return err
	}
	if service.Service.Spec.GetReplicated().Replicas != 2 {
		return errors.New("idle service did not start with two replicas")
	}
	fmt.Println("C11 idle service: started at 2 replicas with bounds 1..2")
	var violation error
	if err := until(j.ctx, func() error {
		response, err := j.control.GetService(j.ctx, &api.GetServiceRequest{ServiceID: initial.task.ServiceID})
		if err != nil {
			return err
		}
		replicas := response.Service.Spec.GetReplicated().Replicas
		if replicas < 1 || replicas > 2 {
			violation = errors.New("idle service exceeded its bounds")
			return nil
		}
		if replicas == 2 {
			return errors.New("waiting for idle cooldown and scale down")
		}
		changed, err := types.TimestampFromProto(response.Service.Meta.UpdatedAt)
		if err != nil {
			return err
		}
		if changed.Before(started.Add(180 * time.Second)) {
			violation = errors.New("idle service scaled down before the 180-second cooldown")
			return nil
		}
		current, err := j.running(initial.task.ServiceID, initial.host, initial.runtime)
		if err != nil {
			return err
		}
		if len(current) != 1 {
			return errors.New("waiting for one serving idle replica")
		}
		fmt.Printf("C11 idle cooldown: held 2 replicas for %.0fs, then 2 -> 1; down cooldown 180s, stabilization 120s\n", changed.Sub(started).Seconds())
		return nil
	}); err != nil {
		return err
	}
	if violation != nil {
		return violation
	}
	_, err = j.control.RemoveService(j.ctx, &api.RemoveServiceRequest{ServiceID: initial.task.ServiceID})
	return err
}

func startAutoscaleEdge(ctx context.Context, state string) error {
	public := edge.New(state)
	public.SetServiceRoutes(map[string]int{"c11.e2e.test": 18089, "fixed.c11.e2e.test": 18090}, nil,
		map[string]string{"c11.e2e.test": "c11-load", "fixed.c11.e2e.test": "c11-fixed"}, nil)
	failed := make(chan error, 1)
	go func() { failed <- public.Run(ctx) }()
	return until(ctx, func() error {
		select {
		case err := <-failed:
			return err
		default:
		}
		conn, err := net.DialTimeout("tcp", "127.0.0.1:443", time.Second)
		if err == nil {
			conn.Close()
		}
		return err
	})
}

func autoscaleEdgeClient(root string) (*http.Client, func(), error) {
	pem, err := os.ReadFile(filepath.Join(root, "ca.pem"))
	if err != nil {
		return nil, nil, err
	}
	roots := x509.NewCertPool()
	if !roots.AppendCertsFromPEM(pem) {
		return nil, nil, errors.New("missing autoscale journey CA")
	}
	transport := &http.Transport{TLSClientConfig: &tls.Config{RootCAs: roots},
		DialContext: func(ctx context.Context, _, _ string) (net.Conn, error) {
			return (&net.Dialer{}).DialContext(ctx, "tcp", "10.231.0.2:443")
		}}
	return &http.Client{Transport: transport, Timeout: 5 * time.Second}, transport.CloseIdleConnections, nil
}

func edgeLoad(ctx context.Context, client *http.Client, host string) error {
	request, err := http.NewRequestWithContext(ctx, http.MethodGet, "https://"+host+"/load", nil)
	if err != nil {
		return err
	}
	response, err := client.Do(request)
	if err != nil {
		return err
	}
	defer response.Body.Close()
	if response.StatusCode != http.StatusOK {
		return fmt.Errorf("edge load returned HTTP %d", response.StatusCode)
	}
	_, err = io.Copy(io.Discard, response.Body)
	return err
}

func (j *journey) fixedService(id string) error {
	response, err := j.control.GetService(j.ctx, &api.GetServiceRequest{ServiceID: id})
	if err != nil {
		return err
	}
	if response.Service.Spec.GetReplicated().Replicas != 1 {
		return errors.New("service without replicaBounds changed its replica count under load")
	}
	return nil
}
