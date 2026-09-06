package main

import (
	"github.com/nats-io/nats.go"
	"terrascale.tech/orchestrator/src/orchestrator/databaseadmission"
)

func productionBranchRestore(keys map[string]databaseadmission.ReadinessKey, connection *nats.Conn) *databaseadmission.BranchRestoreConfig {
	if len(keys) == 0 {
		return nil
	}
	return &databaseadmission.BranchRestoreConfig{Keys: keys, Restore: databaseadmission.RemoteBranchRestore(connection)}
}
