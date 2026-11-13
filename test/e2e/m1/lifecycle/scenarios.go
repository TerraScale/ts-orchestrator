package main

import (
	"errors"
	"fmt"
	"net/http"
	"os"
	"path/filepath"
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
