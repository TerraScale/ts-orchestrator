package agent

import (
	"context"
	"errors"
	"testing"

	"git.terrascale.tech/TerraScale/ts-orchestrator/internal/netbird/client"
	network "git.terrascale.tech/TerraScale/ts-orchestrator/internal/netbird/rollout"
)

func TestWorkerUncommittedInstallRollbackSurvivesRestartAndRejectsLateInstall(t *testing.T) {
	for _, previous := range []string{"", "01M4EB0GDPPHGJPPVY77EMZQKT"} {
		for _, interruption := range []string{"failure", "before-preparation", "after-preparation", "never-delivered"} {
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

func TestWorkerNoopProofCannotWaiveKnownMutationOrLegacyState(t *testing.T) {
	for _, test := range []struct {
		name, progress, installed string
		committed                 bool
	}{
		{"unstarted", "unstarted", "", false},
		{"prepared", "prepared", "", false},
		{"journaled failure", "journaled", "", true},
		{"successful install", "prepared", "installed-target", true},
		{"legacy ledger", "", "", true},
		{"unknown progress", "invalid", "", true},
	} {
		t.Run(test.name, func(t *testing.T) {
			last := ledger{InstallProgress: test.progress, InstalledTargetHash: test.installed, PreviousManagedTransaction: "1P4DT7KVBAJVZ9B4AJPV2KEYWF"}
			if proof := last.rollbackProof(); proof.InstallCommitted != test.committed || proof.PreviousTransactionID != "1P4DT7KVBAJVZ9B4AJPV2KEYWF" {
				t.Fatalf("unsafe worker proof: %+v", proof)
			}
		})
	}
}

func TestWorkerPreparationPreservesBaselineAndDurablyObservesMatchingMutation(t *testing.T) {
	cfg, command, _ := workerFixture(t)
	last := ledger{Transaction: command.Transaction, Action: "install", InstallProgress: "unstarted"}
	if err := prepareInstall(cfg, &last, command.Transaction, client.ManagedResult{TransactionID: "0VWD7JSS84Y3FHDZ5Y8RJWJJMA"}); err != nil {
		t.Fatal(err)
	}
	// A crash followed by an idempotent retry must keep the original baseline.
	restarted, err := loadLedger(cfg.StateDirectory)
	if err != nil {
		t.Fatal(err)
	}
	if err := prepareInstall(cfg, &restarted, command.Transaction, client.ManagedResult{TransactionID: "47B1SZF31Y8DRYG1YRQ8M14C5R"}); err == nil {
		t.Fatal("worker accepted a changed completed journal as its original baseline")
	}
	unchanged, err := loadLedger(cfg.StateDirectory)
	if err != nil || unchanged != last {
		t.Fatalf("failed preparation changed private proof: %+v %v", unchanged, err)
	}
	if err := prepareInstall(cfg, &restarted, command.Transaction, client.ManagedResult{TransactionID: command.Transaction, Pending: true}); err != nil {
		t.Fatal(err)
	}
	journaled, err := loadLedger(cfg.StateDirectory)
	if err != nil || journaled.InstallProgress != "journaled" || !journaled.rollbackProof().InstallCommitted {
		t.Fatalf("matching pending mutation was not durable: %+v %v", journaled, err)
	}
}

func TestWorkerRollbackCrashStillPreventsLateInstallBeforeAck(t *testing.T) {
	cfg, command, key := workerFixture(t)
	last := ledger{}
	install := command
	command.Action, command.ID = "rollback", network.CommandID(command.Transaction, "rollback")
	func() {
		defer func() {
			if crash := recover(); crash != "worker stopped" {
				t.Fatalf("unexpected worker stop: %v", crash)
			}
		}()
		_ = applyStep(t.Context(), cfg, &last, signCommand(t, cfg, key, command, 3), func(context.Context, network.Command) error {
			panic("worker stopped")
		})
	}()
	restarted, err := loadLedger(cfg.StateDirectory)
	if err != nil || restarted.Action != "rollback" || restarted.ActionID == command.ID {
		t.Fatalf("rollback authority was not persisted before worker stop: %+v %v", restarted, err)
	}
	if err := applyStep(t.Context(), cfg, &restarted, signCommand(t, cfg, key, install, 4), func(context.Context, network.Command) error {
		t.Fatal("late installation ran after interrupted rollback")
		return nil
	}); err != nil {
		t.Fatal(err)
	}
	if err := applyStep(t.Context(), cfg, &restarted, signCommand(t, cfg, key, command, 4), func(context.Context, network.Command) error { return nil }); err != nil {
		t.Fatal(err)
	}
	if restarted.ActionID != command.ID || restarted.Error != "" {
		t.Fatalf("interrupted rollback cannot resume acknowledgment: %+v", restarted)
	}
}
