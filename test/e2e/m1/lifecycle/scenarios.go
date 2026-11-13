package main

import (
	"errors"
	"fmt"
	"io"
	"net/http"
	"os"
	"path/filepath"
	"strings"
	"time"

	"github.com/TerraScale/ts-orchestrator/internal/swarmruntime"
	"github.com/moby/swarmkit/v2/api"
)

func (j *journey) slowLookup(w *workload) error {
	if err := request(j.ctx, w.address, "/slow-ready", http.StatusOK); err != nil {
		return err
	}
	path := filepath.Join(j.root, "c18a", "slow-lookup")
	if err := os.WriteFile(path, []byte("ts-"+w.task.ID), 0600); err != nil {
		return err
	}
	if err := until(j.ctx, func() error {
		if err := j.retained(w); err != nil {
			return err
		}
		if err := request(j.ctx, w.address, "/healthy", http.StatusOK); err != nil {
			return err
		}
		gauge, err := j.metric(w, "task_unresponsive_seconds")
		if err != nil || gauge != 0 {
			return fmt.Errorf("slow lookup produced failing observation: %g: %w", gauge, err)
		}
		count, err := j.metric(w, "task_readiness_unobserved_total")
		if err != nil || count < 2 {
			return errors.New("waiting for two bounded slow lookups")
		}
		return nil
	}); err != nil {
		return err
	}
	if err := os.Remove(path); err != nil {
		return err
	}
	if err := request(j.ctx, w.address, "/fast-ready", http.StatusOK); err != nil {
		return err
	}
	fmt.Println("12-second runtime endpoint lookup bounded at five seconds: healthy four-second readiness handler retained, two unobserved rounds, no failing observation")
	return nil
}

func (j *journey) setReplacement(w *workload, replace bool) (*workload, error) {
	current, err := j.control.GetService(j.ctx, &api.GetServiceRequest{ServiceID: w.task.ServiceID})
	if err != nil {
		return nil, err
	}
	inspection, err := swarmruntime.InspectService(current.Service)
	if err != nil {
		return nil, err
	}
	inspection.Spec.Readiness.ReplaceWhenUnresponsive = replace
	spec, err := inspection.Spec.SwarmSpec()
	if err != nil {
		return nil, err
	}
	spec.Task.Placement = current.Service.Spec.Task.Placement
	if _, err := j.control.UpdateService(j.ctx, &api.UpdateServiceRequest{ServiceID: current.Service.ID, ServiceVersion: &current.Service.Meta.Version, Spec: spec}); err != nil {
		return nil, err
	}
	var next *workload
	if err := until(j.ctx, func() error {
		result, err := j.running(w.task.ServiceID, w.host, 0, w.runtime)
		if err != nil {
			return err
		}
		if len(result) != 1 || result[0].task.ID == w.task.ID {
			return errors.New("waiting for declaration configuration roll")
		}
		service, err := j.control.GetService(j.ctx, &api.GetServiceRequest{ServiceID: w.task.ServiceID})
		if err != nil {
			return err
		}
		roundtrip, err := swarmruntime.InspectService(service.Service)
		if err != nil {
			return err
		}
		if roundtrip.Spec.Readiness.ReplaceWhenUnresponsive != replace {
			return errors.New("inspection lost readiness replacement configuration")
		}
		next = result[0]
		return nil
	}); err != nil {
		return nil, err
	}
	j.workloads = append(j.workloads, next)
	fmt.Printf("readiness.replaceWhenUnresponsive=%t preserved through inspection and configuration roll\n", replace)
	return next, nil
}

func (j *journey) recoveryWitness(a, b *workload, before, clearBefore int) (*workload, error) {
	if err := j.reported("not replaced: no witness answered", map[*workload]int{b: before}, b); err != nil {
		return nil, err
	}
	if err := j.recover(b); err != nil {
		return nil, err
	}
	count, err := j.logCount(b, "task readiness unresponsive window cleared")
	if err != nil || count != clearBefore+1 {
		return nil, fmt.Errorf("B did not clear its unwitnessed reporting clock: %d: %w", count, err)
	}
	fmt.Println("A and B frozen without a witness; B thawed and its gauge cleared on its first answering round")
	next, err := j.replacement(a)
	if err != nil {
		return nil, err
	}
	if err := j.retained(b); err != nil {
		return nil, err
	}
	count, err = j.logCount(a, "not replaced: correlated")
	if err != nil || count != 0 {
		return nil, fmt.Errorf("old unwitnessed failure permanently vetoed A: %d: %w", count, err)
	}
	fmt.Printf("A replaced after its own witnessed five-minute window; B PID %d retained; no old-clock correlation veto\n", b.process.Pid())
	return next, nil
}

func (j *journey) replacementCount(services ...string) error {
	all, err := j.control.ListTasks(j.ctx, &api.ListTasksRequest{Filters: &api.ListTasksRequest_Filters{ServiceIDs: services}})
	if err != nil {
		return err
	}
	failures := 0
	for _, task := range all.Tasks {
		if task.Status.State == api.TaskStateFailed && strings.Contains(task.Status.Err, "consecutive readiness probes") {
			failures++
		}
	}
	if failures != len(services) {
		return fmt.Errorf("expected exactly %d readiness replacements, got %d", len(services), failures)
	}
	return nil
}

func (j *journey) oneFailure(w *workload) error {
	req, err := http.NewRequestWithContext(j.ctx, http.MethodGet, "http://"+w.address+"/failures", nil)
	if err != nil {
		return err
	}
	response, err := (&http.Client{Timeout: 3 * time.Second}).Do(req)
	if err != nil {
		return err
	}
	defer response.Body.Close()
	body, err := io.ReadAll(io.LimitReader(response.Body, 64))
	if err != nil {
		return err
	}
	if string(body) != "1" {
		return fmt.Errorf("sibling failed %s probes, expected one", body)
	}
	return nil
}
