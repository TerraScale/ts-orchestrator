package main

import (
	"encoding/json"
	"errors"
	"fmt"
	"github.com/TerraScale/ts-orchestrator/internal/protocol"
	"github.com/TerraScale/ts-orchestrator/internal/swarmruntime"
	"os"
	"path/filepath"
	"strconv"
	"time"
)

type bakeRecord struct {
	Generation int64           `json:"generation"`
	Image      string          `json:"image"`
	Identity   [32]byte        `json:"identity"`
	Rollout    bakeRuntime     `json:"runtime"`
	Bake       mainBakeVerdict `json:"bake"`
}
type bakeRuntime struct {
	Running, Ready int64
	Tasks          []swarmruntime.ServiceTaskEvidence
	Revision       string
	StopFirst      bool `json:",omitzero"`
}
type mainBakeVerdict struct {
	Started         time.Time         `json:"started"`
	Finished        time.Time         `json:"finished"`
	Samples         int               `json:"samples"`
	Checks          map[string]string `json:"checks"`
	Reason          string            `json:"reason,omitempty"`
	HealthySince    time.Time         `json:"healthySince"`
	RecoverySamples int               `json:"recoverySamples,omitempty"`
	RecoveryChecks  map[string]string `json:"recoveryChecks,omitempty"`

	DependencyOnly bool `json:"dependencyOnly,omitempty"`
}

func writeBake(key string, record bakeRecord) error {
	data, err := protocol.EncodeJSON(record)
	if err == nil {
		err = writePrivate(key, data)
	}
	return err
}
func writePrivate(path string, data []byte) error {
	temp := path + ".tmp" + strconv.Itoa(os.Getpid())
	file, err := os.OpenFile(temp, os.O_WRONLY|os.O_CREATE|os.O_TRUNC, 0o600)
	if err != nil {
		return err
	}
	_, err = file.Write(data)
	err = errors.Join(err, file.Sync(), file.Close())
	if err != nil {
		_ = os.Remove(temp)
		return err
	}
	if err := os.Rename(temp, path); err != nil {
		_ = os.Remove(temp)
		return err
	}
	dir, err := os.Open(filepath.Dir(path))
	if err != nil {
		return err
	}
	defer dir.Close()
	return dir.Sync()
}
func olderHoldReceipt(root string, generation int64) {
	path := filepath.Join(root, "mesh", fmt.Sprintf("bake-terrabase-%d.json", generation))
	data, err := os.ReadFile(path)
	must(err)
	var record bakeRecord
	must(json.Unmarshal(data, &record))
	must(writeBake(path, record))
}
