package main

import (
	"context"
	"errors"
	"fmt"
	"github.com/moby/swarmkit/v2/api"
	"strings"
	"time"
)

func (j *journey) reporting(first, second, owner *workload, twins []*workload) error {
	frozen := []*workload{first, twins[0], twins[1]}
	started := time.Now()
	if err := j.freeze(frozen...); err != nil {
		return err
	}
	identity := make(chan error, 1)
	go func() { identity <- qualifiedIdentity(j.ctx) }()
	if err := j.slowLookup(second); err != nil {
		return err
	}
	if value, err := j.metric(first, "task_unresponsive_seconds"); err != nil || value <= 0 || value >= 240 {
		return fmt.Errorf("gauge must rise before warning threshold: %g: %w", value, err)
	}
	if err := <-identity; err != nil {
		return err
	}
	period, cancel := context.WithTimeout(j.ctx, 4*time.Minute+50*time.Second-time.Since(started))
	defer cancel()
	original := j.ctx
	j.ctx = period
	err := j.reported("WARN task unresponsive ", map[*workload]int{}, frozen...)
	j.ctx = original
	if err != nil {
		return err
	}
	if err := j.peerInfo(first, 1); err != nil {
		return err
	}
	for _, w := range twins {
		if err := j.peerInfo(w, 0); err != nil {
			return err
		}
	}
	ticker := time.NewTicker(time.Second)
	defer ticker.Stop()
	for time.Since(started) < 6*time.Minute+15*time.Second {
		if err := j.retained(j.workloads...); err != nil {
			return err
		}
		for _, w := range frozen {
			count, err := j.logCount(w, "WARN task unresponsive ")
			if err != nil || count != 1 {
				return fmt.Errorf("expected one warning throughout freeze, got %d: %w", count, err)
			}
		}
		select {
		case <-j.ctx.Done():
			return j.ctx.Err()
		case <-ticker.C:
		}
	}
	if err := j.retained(owner, second); err != nil {
		return err
	}
	if err := j.recover(frozen...); err != nil {
		return err
	}
	for _, w := range frozen {
		count, err := j.logCount(w, "task readiness unresponsive window cleared")
		if err != nil || count != 1 {
			return fmt.Errorf("expected one clear, got %d: %w", count, err)
		}
	}
	fmt.Println("reporting: gauge and exactly one warning within 4m50s; other tasks answered=1 and nothing answered=0; all PIDs retained beyond 6m15s; thaw cleared on first answering round")
	if err := j.nonSuccess(first); err != nil {
		return err
	}
	return j.removeWatch(second)
}

func (j *journey) peerInfo(w *workload, want float64) error {
	value, err := j.metric(w, "task_readiness_others_answered")
	if err != nil || value != want {
		return fmt.Errorf("other tasks answered %g, want %g: %w", value, want, err)
	}
	return nil
}

func (j *journey) nonSuccess(w *workload) error {
	if err := request(j.ctx, w.address, "/not-ready", 200); err != nil {
		return err
	}
	before, err := j.metric(w, "task_readiness_unobserved_total")
	if err != nil {
		return err
	}
	deadline := time.NewTimer(30 * time.Second)
	defer deadline.Stop()
	ticker := time.NewTicker(time.Second)
	defer ticker.Stop()
	for {
		value, err := j.metric(w, "task_unresponsive_seconds")
		if err != nil || value != 0 {
			return fmt.Errorf("non-success answer counted as unresponsive: %g: %w", value, err)
		}
		missing, err := j.metric(w, "task_readiness_unobserved_total")
		if err != nil || missing != before {
			return errors.New("non-success answer counted as unobserved")
		}
		select {
		case <-j.ctx.Done():
			return j.ctx.Err()
		case <-deadline.C:
			fmt.Println("HTTP 503 answers keep the liveness gauge clear")
			return nil
		case <-ticker.C:
		}
	}
}

func (j *journey) removeWatch(w *workload) error {
	if _, err := j.control.RemoveService(j.ctx, &api.RemoveServiceRequest{ServiceID: w.task.ServiceID}); err != nil {
		return err
	}
	if err := until(j.ctx, func() error {
		for _, name := range []string{"task_unresponsive_seconds", "task_readiness_others_answered", "task_readiness_unobserved_total"} {
			_, err := j.metric(w, name)
			if err == nil || !strings.Contains(err.Error(), "missing "+name) {
				return fmt.Errorf("obsolete series %s is still registered: %v", name, err)
			}
		}
		return nil
	}); err != nil {
		return err
	}
	fmt.Println("watch close unregisters unresponsive, peer-answer, and unobserved series")
	return nil
}
