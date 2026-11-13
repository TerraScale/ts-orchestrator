package vaultsecret

import (
	"context"
	"encoding/json/v2"
	"errors"
	"fmt"
	"os"
	"os/exec"
	"slices"
	"strings"
	"time"

	"github.com/TerraScale/ts-orchestrator/deploy/m1"
	"github.com/TerraScale/ts-orchestrator/internal/ociregion/catalog"
)

func checkServiceSecrets(ctx context.Context) error {
	if os.Geteuid() != 0 {
		return errors.New("service secret preflight requires host root")
	}
	ctx, cancel := context.WithTimeout(ctx, time.Minute)
	defer cancel()
	if err := checkRelayUnit(ctx); err != nil {
		return err
	}
	asset, err := os.ReadFile("/sys/class/dmi/id/chassis_asset_tag")
	if err != nil && !errors.Is(err, os.ErrNotExist) {
		return fmt.Errorf("service secret preflight host identity: %w", err)
	}
	if strings.TrimSpace(string(asset)) != "OracleCloud.com" {
		return nil
	}
	metadata, err := instanceMetadata(ctx)
	if err != nil {
		return err
	}
	region, ok := catalog.CellForOCIRegion(metadata.Region)
	if !ok {
		return errors.New("service secret preflight found no supported host region")
	}
	entries, err := m1.Files.ReadDir("services")
	if err != nil {
		return err
	}
	for _, entry := range entries {
		if !strings.HasSuffix(entry.Name(), ".json") {
			continue
		}
		body, err := m1.Files.ReadFile("services/" + entry.Name())
		if err != nil {
			return err
		}
		var manifest struct {
			Name    string         `json:"name"`
			Regions []string       `json:"regions"`
			Secrets map[string]Ref `json:"secrets"`
		}
		if err := json.Unmarshal(body, &manifest); err != nil {
			return err
		}
		if len(manifest.Regions) != 0 && !slices.Contains(manifest.Regions, region.Name()) {
			continue
		}
		for _, ref := range manifest.Secrets {
			if err := checkSecretRead(ctx, manifest.Name, ref); err != nil {
				return fmt.Errorf("release refused: service %s cannot read Vault secret %s; run region add before releasing changed secret references", manifest.Name, ref.Name)
			}
		}
	}
	return nil
}

func checkRelayUnit(ctx context.Context) error {
	if _, err := os.Stat("/run/systemd/system"); errors.Is(err, os.ErrNotExist) {
		return nil
	} else if err != nil {
		return errors.New("release refused: cannot inspect installed ts-alert-delivery.service")
	}
	output, err := exec.CommandContext(ctx, "systemctl", "show", "ts-alert-delivery.service", "--property=LoadState", "--value").Output()
	if err != nil {
		return errors.New("release refused: cannot inspect installed ts-alert-delivery.service")
	}
	if strings.TrimSpace(string(output)) == "not-found" {
		return nil
	}
	output, err = exec.CommandContext(ctx, "systemctl", "show", "ts-alert-delivery.service", "--property=ExecStartPreEx", "--value").Output()
	if err == nil {
		for _, command := range strings.Split(string(output), "} {") {
			if strings.Contains(command, "argv[]=/usr/local/bin/ts-orch alert-delivery prepare ;") && strings.Contains(command, "flags=full-privileges ;") {
				return nil
			}
		}
	}
	return errors.New("release refused: install ts-alert-delivery.service with ExecStartPre=+/usr/local/bin/ts-orch alert-delivery prepare before releasing")
}

func checkSecretRead(ctx context.Context, service string, ref Ref) error {
	for {
		values, err := ReadInstanceSecrets(ctx, service, map[string]Ref{"PREFLIGHT_FILE": ref})
		clear(values)
		if err == nil {
			return nil
		}
		timer := time.NewTimer(250 * time.Millisecond)
		select {
		case <-ctx.Done():
			timer.Stop()
			return ctx.Err()
		case <-timer.C:
		}
	}
}
