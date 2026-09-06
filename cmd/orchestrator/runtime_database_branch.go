package main

import (
	"crypto/ed25519"
	"github.com/nats-io/nats.go"
	"terrascale.tech/orchestrator/src/orchestrator/bootstrapcredentials"
	"terrascale.tech/orchestrator/src/orchestrator/databaseadmission"
)

func productionBranchRestore(keys map[string]databaseadmission.ReadinessKey, connection *nats.Conn) *databaseadmission.BranchRestoreConfig {
	if len(keys) == 0 {
		return nil
	}
	return &databaseadmission.BranchRestoreConfig{Keys: keys, Capture: databaseadmission.RemoteBranchSource(connection), Restore: databaseadmission.RemoteBranchRestore(connection)}
}

type databaseBranchKeyFile struct {
	KeyID         string `json:"keyId"`
	PublicKeyFile string `json:"publicKeyFile"`
}

func loadDatabaseBranchKeys(files map[string]databaseBranchKeyFile, hosts map[string]string) (map[string]databaseadmission.ReadinessKey, error) {
	if len(files) != len(hosts) {
		return nil, databaseadmission.ErrInvalid
	}
	keys := make(map[string]databaseadmission.ReadinessKey, len(files))
	seen := map[string]bool{}
	for host, config := range files {
		if hosts[host] == "" || config.KeyID == "" || seen[config.KeyID] {
			return nil, databaseadmission.ErrInvalid
		}
		key, err := bootstrapcredentials.ReadFile(config.PublicKeyFile, false, ed25519.PublicKeySize)
		if err != nil {
			return nil, err
		}
		if len(key) != ed25519.PublicKeySize {
			return nil, databaseadmission.ErrInvalid
		}
		keys[host] = databaseadmission.ReadinessKey{KeyID: config.KeyID, PublicKey: key}
		seen[config.KeyID] = true
	}
	return keys, nil
}
