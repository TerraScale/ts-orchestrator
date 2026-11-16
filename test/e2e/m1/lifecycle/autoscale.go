package main

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"net/http"
	"path/filepath"
	"strconv"
	"sync"
	"syscall"
	"time"

	"github.com/TerraScale/ts-orchestrator/internal/autoscale"
	"github.com/TerraScale/ts-orchestrator/internal/swarmruntime"
	containerd "github.com/containerd/containerd/v2/client"
	"github.com/containerd/containerd/v2/pkg/namespaces"
	"github.com/gogo/protobuf/types"
	"github.com/moby/swarmkit/v2/api"
	"github.com/moby/swarmkit/v2/manager/scheduler"
)

func (j *journey) autoscale(image string) error {
	workloads, err := j.create(image, "c11-load", "10.231.0.2", 18089, false, 1)
	if err != nil {
		return err
	}
	initial := workloads[0]
	service, err := j.control.GetService(j.ctx, &api.GetServiceRequest{ServiceID: initial.task.ServiceID})
	if err != nil {
		return err
	}
	bounds, err := json.Marshal(autoscale.Bounds{Min: 1, Max: 2})
	if err != nil {
		return err
	}
	spec := service.Service.Spec.Copy()
	spec.Annotations.Labels[swarmruntime.LabelReplicaBounds] = string(bounds)
	if _, err := j.control.UpdateService(j.ctx, &api.UpdateServiceRequest{ServiceID: initial.task.ServiceID, ServiceVersion: &service.Service.Meta.Version, Spec: spec}); err != nil {
		return err
	}
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
	for range 4 {
		requests.Go(func() {
			for load.Err() == nil {
				if err := request(load, initial.address, "/load", http.StatusOK); err != nil && load.Err() == nil {
					failures <- err
					return
				}
			}
		})
	}
	defer func() { stop(); requests.Wait() }()
	var scaled []*workload
	var scaledAt time.Time
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
		scaledAt, err = types.TimestampFromProto(response.Service.Meta.UpdatedAt)
		if err != nil {
			return err
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
	fmt.Printf("C11 sustained CPU: replicas 1 -> %d in %.0fs\n", len(scaled), time.Since(started).Seconds())
	stop()
	requests.Wait()
	select {
	case err := <-failures:
		return err
	default:
	}
	removed := time.Now()
	var premature error
	if err := until(j.ctx, func() error {
		response, err := j.control.GetService(j.ctx, &api.GetServiceRequest{ServiceID: initial.task.ServiceID})
		if err != nil {
			return err
		}
		if response.Service.Spec.GetReplicated().Replicas < uint64(len(scaled)) && time.Now().Before(scaledAt.Add(180*time.Second)) {
			premature = errors.New("service scaled down before the cooldown")
			return nil
		}
		if response.Service.Spec.GetReplicated().Replicas != 1 {
			return errors.New("waiting for cooldown and scale down")
		}
		return nil
	}); err != nil {
		return err
	}
	if premature != nil {
		return premature
	}
	fmt.Printf("C11 removed load: replicas %d -> 1 in %.0fs; down cooldown 180s, stabilization 120s\n", len(scaled), time.Since(removed).Seconds())
	var survivor []*workload
	if err := until(j.ctx, func() error {
		var err error
		survivor, err = j.running(initial.task.ServiceID, initial.host, initial.runtime)
		if err != nil {
			return err
		}
		if len(survivor) != 1 {
			return errors.New("waiting for one serving replica")
		}
		return nil
	}); err != nil {
		return err
	}
	killed := survivor[0]
	if err := killed.process.Kill(namespaces.WithNamespace(j.ctx, "terrascale"), syscall.SIGKILL, containerd.WithKillAll); err != nil {
		return err
	}
	if err := until(j.ctx, func() error {
		current, err := j.running(initial.task.ServiceID, initial.host, initial.runtime)
		if err != nil {
			return err
		}
		if len(current) != 1 || current[0].task.ID == killed.task.ID {
			return errors.New("waiting for SwarmKit to replace the killed task")
		}
		fmt.Printf("C11 SwarmKit replacement: %s -> %s; replicas remain 1\n", killed.task.ID, current[0].task.ID)
		return nil
	}); err != nil {
		return err
	}
	_, err = j.control.RemoveService(j.ctx, &api.RemoveServiceRequest{ServiceID: initial.task.ServiceID})
	return err
}

func capacityProof(ctx context.Context, root string) error {
	client, conn, err := swarmruntime.DialControl(filepath.Join(root, "c18a"))
	if err != nil {
		return err
	}
	defer conn.Close()
	services, err := client.ListServices(ctx, &api.ListServicesRequest{Filters: &api.ListServicesRequest_Filters{Names: []string{"c11-load"}}})
	if err != nil {
		return err
	}
	if len(services.Services) != 1 {
		return errors.New("expected the live scaling service")
	}
	nodes, err := client.ListNodes(ctx, &api.ListNodesRequest{})
	if err != nil {
		return err
	}
	tasks, err := client.ListTasks(ctx, &api.ListTasksRequest{})
	if err != nil {
		return err
	}
	for _, budget := range []int{0, 1} {
		if got := scheduler.ReplicaCapacity(services.Services[0], nodes.Nodes, tasks.Tasks, budget); got != budget {
			return fmt.Errorf("additional placement budget %d: got %d", budget, got)
		}
	}
	fmt.Println("C11 live regional capacity: zero additional placements for budget 0; one additional placement for budget 1; existing replicas excluded")
	return nil
}
