package app

import (
	"context"
	"encoding/json"
	"log/slog"
	"os"
	"path/filepath"
	"time"

	"github.com/TerraScale/ts-orchestrator/internal/swarmruntime"
	"github.com/moby/swarmkit/v2/api"
)

// Keep discovery outside the private state tree. Only loopback addresses and
// bounded service/process labels are readable by the Prometheus service user.
const sloTargetsFile = "/run/ts-orch-observability/targets.json"

func syncSLOTargets(ctx context.Context, state, region string, executor *swarmruntime.Executor) {
	tick := time.NewTicker(5 * time.Second)
	defer tick.Stop()
	for {
		if err := refreshSLOTargets(ctx, state, region, executor); err != nil && ctx.Err() == nil {
			slog.WarnContext(ctx, "SLO target discovery failed", "error", err)
		}
		select {
		case <-ctx.Done():
			return
		case <-tick.C:
		}
	}
}

func refreshSLOTargets(ctx context.Context, state, region string, executor *swarmruntime.Executor) error {
	ctx, cancel := context.WithTimeout(ctx, 4*time.Second)
	defer cancel()
	client, conn, err := swarmruntime.DialSingleHost(state)
	if err != nil {
		return err
	}
	defer conn.Close()
	services, err := client.ListServices(ctx, &api.ListServicesRequest{})
	if err != nil {
		return err
	}
	targets, err := executor.SLOTargets(ctx, services.Services, region)
	if err != nil {
		return err
	}
	return writeSLOTargets(sloTargetsFile, targets)
}

func writeSLOTargets(path string, targets []swarmruntime.SLOTarget) error {
	data, err := json.Marshal(targets)
	if err != nil {
		return err
	}
	if err := os.MkdirAll(filepath.Dir(path), 0755); err != nil {
		return err
	}
	// The root runtime uses umask 0077; Prometheus must traverse this owned
	// directory even on a restart after an older 0700 directory was created.
	if err := os.Chmod(filepath.Dir(path), 0755); err != nil {
		return err
	}
	file, err := os.CreateTemp(filepath.Dir(path), ".targets-")
	if err != nil {
		return err
	}
	defer os.Remove(file.Name())
	if err := file.Chmod(0644); err != nil {
		file.Close()
		return err
	}
	_, err = file.Write(data)
	closeErr := file.Close()
	if err != nil {
		return err
	}
	if closeErr != nil {
		return closeErr
	}
	return os.Rename(file.Name(), path)
}
