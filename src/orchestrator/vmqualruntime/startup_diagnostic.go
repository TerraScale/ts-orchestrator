package vmqualruntime

import (
	"bytes"
	"context"
	"encoding/json"
	"errors"
	"io"
	"time"

	"terrascale.tech/orchestrator/src/orchestrator/guestdiagnostic"
	"terrascale.tech/orchestrator/src/orchestrator/sandboxvm"
)

const startupStatusProperties = "--property=MainPID,ActiveState,SubState,Result,ExecMainCode,ExecMainStatus"

type startupFailure struct {
	cause    error
	services []guestdiagnostic.Service
}

func (failure *startupFailure) Error() string {
	encoded, _ := json.Marshal(failure.services)
	return failure.cause.Error() + "; guestStartupDiagnostics=" + string(encoded)
}
func (failure *startupFailure) Unwrap() error { return failure.cause }

func (v *sandboxVM) failStartup(ctx context.Context, cause error) error {
	return retainStartupFailure(ctx, v.executor, cause, func(stopCtx context.Context) error { return v.provider.Stop(stopCtx, v.id) })
}
func retainStartupFailure(ctx context.Context, runner sandboxvm.CommandRunner, cause error, stop func(context.Context) error) error {
	diagnosticCtx, cancel := context.WithTimeout(context.WithoutCancel(ctx), 3*time.Second)
	services := collectStartupServices(diagnosticCtx, runner)
	cancel()
	stopCtx, stopCancel := context.WithTimeout(context.WithoutCancel(ctx), 15*time.Second)
	defer stopCancel()
	return errors.Join(&startupFailure{cause: cause, services: services}, stop(stopCtx))
}

type startupBoundedOutput struct{ buffer bytes.Buffer }

func (buffer *startupBoundedOutput) Len() int      { return buffer.buffer.Len() }
func (buffer *startupBoundedOutput) Bytes() []byte { return buffer.buffer.Bytes() }

func (buffer *startupBoundedOutput) Write(data []byte) (int, error) {
	const maximum = 64 << 10
	remaining := maximum - buffer.Len()
	if len(data) > remaining {
		_, _ = buffer.buffer.Write(data[:remaining])
		return remaining, errors.New("startup diagnostic output exceeded bound")
	}
	return buffer.buffer.Write(data)
}
func startupCommand(ctx context.Context, runner sandboxvm.CommandRunner, path string, args ...string) ([]byte, error) {
	var output startupBoundedOutput
	err := runner.Run(ctx, sandboxvm.Command{Path: path, Args: args, Stdout: &output, Stderr: io.Discard})
	if err != nil {
		return nil, errors.New("guest diagnostic unavailable")
	}
	return output.Bytes(), nil
}
func collectStartupServices(ctx context.Context, runner sandboxvm.CommandRunner) []guestdiagnostic.Service {
	units := []string{"terrascale-ts-node.service", "terrascale-orchestrator.service", "terrascale-terrabase.service"}
	reports := make([]guestdiagnostic.Service, 0, len(units))
	unavailable := runner == nil
	for _, unit := range units {
		report := guestdiagnostic.Service{Unit: unit, Observation: "unavailable"}
		if unavailable || ctx.Err() != nil {
			reports = append(reports, report)
			continue
		}
		status, err := startupCommand(ctx, runner, "/usr/bin/systemctl", "show", unit, startupStatusProperties)
		if err != nil {
			unavailable = true
			reports = append(reports, report)
			continue
		}
		report.Observation = "observed"
		guestdiagnostic.ParseStatus(&report, status)
		journal, err := startupCommand(ctx, runner, "/usr/bin/journalctl", "--unit", unit, "--lines=20", "--no-pager", "--output=json", "--output-fields=MESSAGE,PRIORITY", "--boot")
		if err != nil {
			report.JournalUnavailable = true
		} else {
			guestdiagnostic.ParseJournal(&report, journal)
		}
		reports = append(reports, report)
	}
	return reports
}
