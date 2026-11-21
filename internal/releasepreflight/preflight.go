package releasepreflight

import (
	"context"
	"fmt"

	"github.com/TerraScale/ts-orchestrator/internal/natscell/mesh"
	"github.com/TerraScale/ts-orchestrator/internal/vaultsecret"
)

func Run(ctx context.Context) error {
	if err := vaultsecret.CheckServiceSecrets(ctx); err != nil {
		return err
	}
	if err := meshRecords(ctx); err != nil {
		return err
	}
	return pairUnit(ctx)
}

func Secrets(ctx context.Context) error {
	if err := vaultsecret.CheckRegionalSecrets(ctx); err != nil {
		return err
	}
	return meshRecords(ctx)
}

func meshRecords(ctx context.Context) error {
	region, err := vaultsecret.OracleRegion(ctx)
	if err != nil || region == "" {
		return err
	}
	records := mesh.VaultRecords()
	names := []string{mesh.FounderRecord}
	for _, member := range mesh.Regions(region) {
		names = append(names, mesh.SeedRecord(member))
	}
	for _, name := range names {
		if _, _, err := records.Read(ctx, name); err != nil {
			return fmt.Errorf("release refused: this host cannot read mesh Vault record %s; run region add before releasing: %w", name, err)
		}
	}
	return nil
}
