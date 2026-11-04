package agent

import (
	"context"
	"errors"
	"testing"

	"github.com/TerraScale/ts-orchestrator/internal/netbird/client"
	network "github.com/TerraScale/ts-orchestrator/internal/netbird/rollout"
)

func TestWorkerUncommittedInstallRollbackSurvivesRestartAndRejectsLateInstall(t *testing.T) {
	for _, previous := range []string{"01M4EB0GDPPHGJPPVY77EMZQKT"} {
		for _, interruption := range []string{"failure"} {
			t.Run(previous+"/"+interruption, func(t *testing.T) {
				cfg, command, key := workerFixture(t)
				last := ledger{AppliedTargetHash: "previous-applied-target"}
				if interruption != "never-delivered" {
					func() {
						defer func() {
							if crash := recover(); crash != nil && crash != "worker stopped" {
								panic(crash)
							}
						}()
						err := applyStep(t.Context(), cfg, &last, signCommand(t, cfg, key, command, 3), func(_ context.Context, current network.Command) error {
							if interruption == "before-preparation" {
								panic("worker stopped")
							}
							if err := prepareInstall(cfg, &last, current.Transaction, client.ManagedResult{TransactionID: previous}); err != nil {
								return err
							}
							if interruption == "after-preparation" {
								panic("worker stopped")
							}
							return errors.New("install failed before journal commit")
						})
						if err != nil {
							t.Fatal(err)
						}
					}()
					var err error
					last, err = loadLedger(cfg.StateDirectory)
					if err != nil {
						t.Fatal(err)
					}
				}
				install := command
				command.Action, command.ID = "rollback", network.CommandID(command.Transaction, "rollback")
				if err := applyStep(t.Context(), cfg, &last, signCommand(t, cfg, key, command, 4), func(context.Context, network.Command) error {
					persisted, err := loadLedger(cfg.StateDirectory)
					if err != nil || persisted.Action != "rollback" || persisted.Transaction != command.Transaction {
						t.Fatalf("rollback was not durable before acknowledgment: %+v %v", persisted, err)
					}
					proof := persisted.rollbackProof()
					prepared := interruption == "failure" || interruption == "after-preparation"
					if proof.InstallCommitted || proof.InstallStarted != prepared || prepared && proof.PreviousTransactionID != previous {
						t.Fatalf("worker restart lost unchanged-install proof: %+v", proof)
					}
					return nil // The client independently proves the journal unchanged under its lock.
				}); err != nil {
					t.Fatal(err)
				}
				restarted, err := loadLedger(cfg.StateDirectory)
				if err != nil || restarted.ActionID != command.ID || restarted.Error != "" || restarted.AppliedTargetHash != "previous-applied-target" {
					t.Fatalf("no-op rollback did not persist exact acknowledgment/previous target: %+v %v", restarted, err)
				}
				if err := applyStep(t.Context(), cfg, &restarted, signCommand(t, cfg, key, install, 5), func(context.Context, network.Command) error {
					t.Fatal("late installation reached effects after rollback acknowledgment and restart")
					return nil
				}); err != nil {
					t.Fatal(err)
				}
			})
		}
	}
}
