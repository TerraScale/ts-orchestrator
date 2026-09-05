package vmqualruntime

import (
	"context"
	"errors"
	"fmt"
	"io"
	"strings"
	"testing"
	"time"

	"terrascale.tech/orchestrator/src/orchestrator/sandboxvm"
	"terrascale.tech/orchestrator/src/orchestrator/vmguest"
)

type startupDiagnosticRunner func(context.Context, sandboxvm.Command) error

func (runner startupDiagnosticRunner) Run(ctx context.Context, command sandboxvm.Command) error {
	return runner(ctx, command)
}

func TestStartupDiagnosticsCaptureBeforeStopAndNeverRetainRawText(t *testing.T) {
	events := []string{}
	runner := startupDiagnosticRunner(func(ctx context.Context, command sandboxvm.Command) error {
		if ctx.Err() != nil {
			t.Fatal("diagnostics inherited startup cancellation")
		}
		if err := (vmguest.Request{SchemaVersion: vmguest.SchemaVersion, Operation: vmguest.OperationExecute, Path: command.Path, Args: command.Args}).Validate(); err != nil {
			t.Fatal(err)
		}
		events = append(events, command.Path)
		fmt.Fprint(command.Stderr, "secret stderr token=abc")
		if command.Path == "/usr/bin/systemctl" {
			fmt.Fprint(command.Stdout, "MainPID=123\nActiveState=failed\nSubState=SECRET_STATUS\nResult=exit-code\nExecMainCode=1\nExecMainStatus=2\nUnexpected=SECRET_FIELD\n")
		} else {
			fmt.Fprintln(command.Stdout, `{"MESSAGE":"SECRET_TOKEN no durable orchestrator membership source is configured","PRIORITY":"3"}`)
			fmt.Fprintln(command.Stdout, `{"MESSAGE":"SECRET_UNKNOWN","PRIORITY":"6"}`)
		}
		return nil
	})
	ctx, cancel := context.WithCancel(context.Background())
	cancel()
	cause := errors.New("startup failed")
	err := retainStartupFailure(ctx, runner, cause, func(stopCtx context.Context) error {
		if stopCtx.Err() != nil {
			t.Fatal("stop inherited cancellation")
		}
		if len(events) != 6 {
			t.Fatalf("stop before capture: %v", events)
		}
		events = append(events, "stop")
		return nil
	})
	if !errors.Is(err, cause) {
		t.Fatal("lost cause")
	}
	if strings.Contains(strings.ToLower(err.Error()), "secret") {
		t.Fatalf("leaked diagnostic text: %s", err)
	}
	var failure *startupFailure
	if !errors.As(err, &failure) || len(failure.services) != 3 {
		t.Fatalf("missing diagnostic: %v", err)
	}
	for _, report := range failure.services {
		if report.MainPID != 123 || report.SubState != "unknown" || report.ExecMainStatus != 2 || report.JournalEntries != 2 || report.SeverityCounts[3] != 1 || len(report.Categories) != 1 || report.Categories[0] != "membership-source-missing" {
			t.Fatalf("wrong sanitized diagnostic: %+v", report)
		}
	}
}

func TestStartupDiagnosticsUnavailableStillStops(t *testing.T) {
	for _, missing := range []bool{false, true} {
		t.Run(fmt.Sprint(missing), func(t *testing.T) {
			calls := 0
			var runner sandboxvm.CommandRunner
			if !missing {
				runner = startupDiagnosticRunner(func(context.Context, sandboxvm.Command) error { calls++; return errors.New("SECRET_SSH_AUTH_FAILURE") })
			}
			stopped := false
			started := time.Now()
			err := retainStartupFailure(context.Background(), runner, errors.New("not ready"), func(context.Context) error { stopped = true; return nil })
			if !stopped || calls > 1 || time.Since(started) > time.Second {
				t.Fatal("unavailable channel blocked cleanup")
			}
			if strings.Contains(err.Error(), "SECRET") || strings.Count(err.Error(), `"observation":"unavailable"`) != 3 {
				t.Fatalf("unsafe unavailable observation: %v", err)
			}
		})
	}
}

func TestStartupDiagnosticTimeoutStillStops(t *testing.T) {
	stopped := false
	runner := startupDiagnosticRunner(func(ctx context.Context, _ sandboxvm.Command) error { <-ctx.Done(); return ctx.Err() })
	started := time.Now()
	_ = retainStartupFailure(context.Background(), runner, errors.New("not ready"), func(ctx context.Context) error { stopped = true; return ctx.Err() })
	elapsed := time.Since(started)
	if !stopped || elapsed > 4*time.Second {
		t.Fatalf("diagnostics exceeded cleanup delay bound: %s", elapsed)
	}
}

func TestStartupJournalLimitsAndCategories(t *testing.T) {
	var composition startupServiceDiagnostic
	parseStartupJournal(&composition, []byte(`{"MESSAGE":"orchestrator: production runtime requires configured estate publisher, key rotation, free-tier reaper, restore drill, and delivery mirror adapters","PRIORITY":"3"}`))
	if len(composition.Categories) != 1 || composition.Categories[0] != "production-composition-missing" {
		t.Fatalf("composition category lost: %+v", composition)
	}
	var estate startupServiceDiagnostic
	parseStartupJournal(&estate, []byte(`{"MESSAGE":"orchestrator: OCI estate verification requires TS_ORCH_OCI_ESTATE_FILE, TS_ORCH_OCI_KEY_ID, and TS_ORCH_OCI_PRIVATE_KEY_FILE","PRIORITY":"3"}`))
	if len(estate.Categories) != 1 || estate.Categories[0] != "oci-estate-configuration-missing" {
		t.Fatalf("estate category lost: %+v", estate)
	}
	var report startupServiceDiagnostic
	parseStartupJournal(&report, []byte(strings.Repeat(`{"MESSAGE":"permission denied TOKEN","PRIORITY":"3"}`+"\n", 100)))
	if report.JournalEntries != 20 || report.SeverityCounts[3] != 20 || len(report.Categories) != 1 {
		t.Fatalf("unbounded journal: %+v", report)
	}
	var copied startupBoundedOutput
	if _, err := io.Copy(&copied, io.LimitReader(strings.NewReader(strings.Repeat("x", 128<<10)), 128<<10)); err == nil || copied.Len() != 64<<10 {
		t.Fatal("io.Copy bypassed output bound")
	}
	var buffer startupBoundedOutput
	if _, err := buffer.Write(make([]byte, 128<<10)); err == nil || buffer.Len() != 64<<10 {
		t.Fatal("output bound not enforced")
	}
}
