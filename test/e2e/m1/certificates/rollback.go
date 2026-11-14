package main

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"os"
	"syscall"
	"time"
)

const rollbackName = "fenced.e2e.test"

func snapshotWithheld(cfg configuration) error {
	if err := os.MkdirAll(cfg.Work+"/rollback", 0700); err != nil {
		return err
	}
	for _, file := range []string{rollbackName, ".state-" + rollbackName} {
		data, err := os.ReadFile(cfg.Work + "/a/edge-certs/" + file)
		if err != nil {
			return err
		}
		if err := os.WriteFile(cfg.Work+"/rollback/"+file, data, 0600); err != nil {
			return err
		}
	}
	return nil
}

func rollbackJourney(ctx context.Context, cfg configuration, current, store *process, startNode func(string, string, string, string) (*process, error)) error {
	if err := store.cmd.Process.Signal(syscall.SIGCONT); err != nil {
		return err
	}
	withheld, err := fileFingerprint(cfg.Work + "/rollback/" + rollbackName)
	if err != nil {
		return err
	}
	stateData, err := os.ReadFile(cfg.Work + "/rollback/.state-" + rollbackName)
	if err != nil {
		return err
	}
	var receipt struct {
		Withheld   string
		Generation string
	}
	if err := json.Unmarshal(stateData, &receipt); err != nil {
		return err
	}
	if receipt.Withheld != withheld || receipt.Generation == "" {
		return errors.New("issuance receipt of the withheld certificate is not in the state sidecar")
	}
	data, err := os.ReadFile(cfg.Work + "/rollback/" + rollbackName)
	if err != nil {
		return err
	}
	before, err := fetchCounts()
	if err != nil {
		return err
	}
	current.stop()
	if err := os.WriteFile(cfg.Work+"/a/edge-certs/"+rollbackName, data, 0600); err != nil {
		return err
	}
	previous, err := startNode("a", cfg.MainBinary, "rollback-a", "oracle")
	if err != nil {
		return err
	}
	defer previous.stop()
	bounded, cancel := context.WithTimeout(ctx, 30*time.Second)
	defer cancel()
	tick := time.NewTicker(200 * time.Millisecond)
	defer tick.Stop()
	for {
		served, err := fingerprint(cfg, "10.77.0.2", rollbackName, false)
		if err == nil && served == withheld {
			break
		}
		select {
		case <-bounded.Done():
			return fmt.Errorf("previous binary did not serve the withheld certificate written by this binary: served=%s handshake=%v", served, err)
		case <-tick.C:
		}
	}
	after, err := fetchCounts()
	if err != nil {
		return err
	}
	if after[rollbackName] != before[rollbackName] {
		return fmt.Errorf("previous binary ordered %s again: %d -> %d", rollbackName, before[rollbackName], after[rollbackName])
	}
	fmt.Println("PASS rollback: the previous binary serves the withheld certificate this binary wrote, receipt in the state sidecar, zero authority orders")
	return nil
}
