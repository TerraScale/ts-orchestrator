package main

import (
	"context"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"os"
	"syscall"
	"time"

	"github.com/nats-io/nats.go"
)

const rollbackName = "fenced.e2e.test"

func snapshotWithheld(cfg configuration, envelope laneEnvelope) error {
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
	data, err := json.Marshal(envelope)
	if err != nil {
		return err
	}
	return os.WriteFile(cfg.Work+"/rollback/shared.json", data, 0600)
}

func rollbackJourney(ctx context.Context, cfg configuration, current, peer, store *process, js nats.JetStreamContext, startNode func(string, string, string, string) (*process, error)) error {
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
	peer.stop()
	if err := os.WriteFile(cfg.Work+"/a/edge-certs/"+rollbackName, data, 0600); err != nil {
		return err
	}
	if err := os.WriteFile(cfg.Work+"/a/edge-certs/.state-"+rollbackName, stateData, 0600); err != nil {
		return err
	}
	shared, err := os.ReadFile(cfg.Work + "/rollback/shared.json")
	if err != nil {
		return err
	}
	_, revision, err := readEnvelope(ctx, js, rollbackName)
	if err != nil {
		return err
	}
	if _, err := js.Publish("$KV.edge-certs."+hex.EncodeToString([]byte(rollbackName)), shared, nats.ExpectLastSequencePerSubject(revision), nats.Context(ctx)); err != nil {
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
