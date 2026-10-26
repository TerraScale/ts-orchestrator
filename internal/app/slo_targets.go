package app

import (
	"context"
	"encoding/json"
	"errors"
	"log/slog"
	"net"
	"os"
	"os/exec"
	"path/filepath"
	"strings"
	"time"

	"github.com/TerraScale/ts-orchestrator/internal/ociregion/catalog"
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
		if err := refreshStorageTargets(ctx, "/run/ts-orch-observability/storage.json"); err != nil && ctx.Err() == nil {
			slog.WarnContext(ctx, "Host storage target discovery failed", "error", err)
		}
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

// NetBird membership includes every host, including workers in the same region.
func refreshStorageTargets(ctx context.Context, path string) error {
	ctx, cancel := context.WithTimeout(ctx, 4*time.Second)
	defer cancel()
	data, err := exec.CommandContext(ctx, "/usr/local/bin/netbird", "status", "--json").Output()
	if err != nil {
		return err
	}
	targets, err := storageTargets(data)
	if err != nil {
		return err
	}
	return writeSLOTargets(path, targets)
}

func storageTargets(data []byte) ([]swarmruntime.SLOTarget, error) {
	type peer struct {
		FQDN string `json:"fqdn"`
		IP   string `json:"netbirdIp"`
	}
	var status struct {
		peer
		Peers struct {
			Details []peer `json:"details"`
		} `json:"peers"`
	}
	if err := json.Unmarshal(data, &status); err != nil {
		return nil, err
	}
	if status.FQDN == "" || status.IP == "" {
		return nil, errors.New("missing local NetBird identity")
	}
	// The local status uses address/prefix; peer details use bare addresses.
	if ip, _, err := net.ParseCIDR(status.IP); err == nil {
		status.IP = ip.String()
	}
	targets := []swarmruntime.SLOTarget{}
	seen := map[string]bool{}
	for _, at := range append(status.Peers.Details, status.peer) {
		host, _, _ := strings.Cut(at.FQDN, ".")
		region, _, _ := strings.Cut(strings.TrimPrefix(host, "ts-"), "-")
		if _, known := catalog.LookupName(region); !known {
			continue
		}
		ip := net.ParseIP(at.IP)
		if !swarmruntime.NodeName.MatchString(host) || ip == nil || !ip.IsPrivate() || ip.To4() == nil {
			return nil, errors.New("invalid NetBird storage host")
		}
		if seen[at.IP] {
			continue
		}
		seen[at.IP] = true
		targets = append(targets, swarmruntime.SLOTarget{Targets: []string{net.JoinHostPort(ip.String(), "9108")},
			Labels: map[string]string{"host": host, "region": region, "service": "host-storage", "instance": host}})
	}
	if len(targets) == 0 || len(targets) > 128 {
		return nil, errors.New("invalid storage inventory size")
	}
	return targets, nil
}
