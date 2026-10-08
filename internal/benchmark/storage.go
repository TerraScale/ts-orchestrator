package benchmark

import (
	"context"
	"errors"
	"fmt"

	"git.terrascale.tech/TerraScale/ts-orchestrator/internal/capacity"
	v1 "terrascale.tech/sdk/v1"
)

// SDKRepository stores each entity in the public SDK's benchmark database.
// The data-plane key is a dedicated Vault credential, separate from load clients.
type SDKRepository struct{ Database *v1.Database }

func NewRepository(ctx context.Context, origin, project, key string) (*SDKRepository, error) {
	client, err := v1.New(v1.Config{BaseURL: origin, Token: key, MaxRetries: -1})
	if err != nil {
		return nil, err
	}
	if !idPattern.MatchString(project) {
		return nil, errors.New("benchmark storage project must be a plain ULID")
	}
	db := client.Database(project, "benchmark")
	if _, err := db.Create(ctx); err != nil {
		return nil, fmt.Errorf("SDK_BLOCKED: benchmark storage requires public SDK support for plain ULID projects: %w", err)
	}
	for _, name := range []string{"runs", "results", "usage"} {
		if _, err := db.CreateCollection(ctx, name); err != nil {
			return nil, err
		}
	}
	return &SDKRepository{Database: db}, nil
}

func (s *SDKRepository) SaveRun(ctx context.Context, run Run) error {
	run.Stages = append([]Stage(nil), run.Stages...)
	for i := range run.Stages {
		run.Stages[i].Samples = nil
	}
	_, err := s.Database.Collection("runs").Put(ctx, run.ID, run)
	return err
}
func (s *SDKRepository) SaveResult(ctx context.Context, runID string, stage int, sample Sample) error {
	id := newID()
	_, err := s.Database.Collection("results").Put(ctx, id, map[string]any{"id": id, "run_id": runID, "stage": stage, "result": sample})
	return err
}
func (s *SDKRepository) SaveUsage(ctx context.Context, runID string, stage int, usage capacity.Usage) error {
	id := newID()
	_, err := s.Database.Collection("usage").Put(ctx, id, map[string]any{"id": id, "run_id": runID, "stage": stage, "usage": usage})
	return err
}
