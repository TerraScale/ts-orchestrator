// Package controlcandidatecli runs the admitted control-candidate preparation process.
package controlcandidatecli

import (
	"context"
	"encoding/json"
	"errors"
	"io"
	"time"

	"terrascale.tech/orchestrator/src/orchestrator/candidatesync"
	"terrascale.tech/orchestrator/src/orchestrator/initialgrant"
	"terrascale.tech/orchestrator/src/orchestrator/nodeauthority"
	"terrascale.tech/orchestrator/src/orchestrator/transitiongrant"
)

// Run keeps the admitted candidate process available while optionally verifying preliminary snapshots in isolated temporary brokers.
// It never elects an authority or reports ordinary runtime readiness.
func Run(ctx context.Context, path string, output io.Writer) error {
	raw, err := initialgrant.ReadMaterialFile(path, transitiongrant.MaximumBytes, false)
	if err != nil {
		return err
	}
	config, err := transitiongrant.ParseConfig(raw)
	if err != nil {
		return err
	}
	if err := waitControlCandidate(ctx, config, output, nodeauthority.ValidatePublishedPreparation); err != nil {
		return err
	}
	return nil
}

func waitControlCandidate(ctx context.Context, config transitiongrant.Config, output io.Writer, validate func(context.Context, transitiongrant.Config) (nodeauthority.CandidatePreparationReceipt, error)) error {
	if ctx == nil || output == nil || validate == nil {
		return errors.New("candidate preparation requires context, output and admission")
	}
	if err := ctx.Err(); err != nil {
		return err
	}
	if err := config.Validate(); err != nil {
		return err
	}
	receipt, err := validate(ctx, config)
	if err != nil {
		return err
	}
	if !receipt.ExpiresAt.After(time.Now()) {
		return errors.New("candidate preparation admission has expired")
	}
	if err := json.NewEncoder(output).Encode(receipt); err != nil {
		return errors.New("candidate preparation receipt could not be written")
	}
	poll := time.NewTicker(250 * time.Millisecond)
	defer poll.Stop()
	return watchCandidate(ctx, config, output, receipt, validate, productionSyncDependencies(), poll.C)
}

func productionSyncDependencies() syncDependencies {
	return syncDependencies{initialgrant.ReadPreliminaryUpload, nodeauthority.VerifyPublishedCandidateRequest, nodeauthority.WithinPublishedCandidateMutation, candidatesync.Run}
}
