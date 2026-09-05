package main

import (
	"context"
	"errors"

	"terrascale.tech/orchestrator/src/orchestrator/initialcontrol"
	"terrascale.tech/orchestrator/src/orchestrator/initialgrant"
)

func runInitialGRUR1(ctx context.Context, path string) error {
	raw, err := initialgrant.ReadConfiguration(path)
	if err != nil {
		return commandFailure(initialgrant.Mode, err)
	}
	admission, err := initialgrant.AdmitConfiguration(ctx, raw)
	if err != nil {
		return commandFailure(initialgrant.Mode, err)
	}
	runtime, err := initialcontrol.Start(ctx, admission)
	if err != nil {
		return commandFailure(initialgrant.Mode, err)
	}
	select {
	case <-ctx.Done():
	case <-runtime.Completion():
	}
	err = errors.Join(runtime.Close(), runtime.Err())
	if err != nil {
		return commandFailure(initialgrant.Mode, err)
	}
	return nil
}
