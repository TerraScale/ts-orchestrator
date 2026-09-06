package main

import (
	"context"
	"errors"
	"os"
	"strconv"
	"strings"

	"terrascale.tech/orchestrator/src/orchestrator/control"
	"terrascale.tech/orchestrator/src/orchestrator/keylease"
)

const (
	keyLeaseSocketEnvironment  = "TS_ORCH_KEY_LEASE_SOCKET_FILE"
	keyLeaseCatalogEnvironment = "TS_ORCH_KEY_LEASE_CATALOG_FILE"
	keyLeaseEnvironment        = "TS_ORCH_KEY_LEASE_ENVIRONMENT"
	keyLeaseUIDEnvironment     = "TS_ORCH_KEY_LEASE_PEER_UID"
)

func startConfiguredKeyLease(ctx context.Context, options *control.OrchestratorOptions, lookup envLookup) (*keylease.Server, error) {
	if options.Cell == "local" {
		return nil, nil
	}
	socket, _ := lookup(keyLeaseSocketEnvironment)
	catalog, _ := lookup(keyLeaseCatalogEnvironment)
	environment, _ := lookup(keyLeaseEnvironment)
	peer, _ := lookup(keyLeaseUIDEnvironment)
	uid, err := strconv.ParseUint(peer, 10, 32)
	if err != nil || strconv.FormatUint(uid, 10) != peer || uid != uint64(os.Geteuid()) || socket == "" || catalog == "" || environment == "" {
		return nil, errors.New("orchestrator: local Vault key lease configuration unavailable")
	}
	service, err := keylease.Start(ctx, keylease.Config{SocketPath: socket, CatalogPath: catalog, Environment: environment, Region: strings.ToUpper(options.Cell), AllowedUID: uint32(uid)})
	if err != nil {
		return nil, errors.New("orchestrator: local Vault key lease service unavailable")
	}
	return service, nil
}
