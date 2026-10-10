package app

import (
	"bytes"
	"context"
	"errors"
	"fmt"
	"os"
	"time"

	"git.terrascale.tech/TerraScale/ts-orchestrator/internal/authority"
	"git.terrascale.tech/TerraScale/ts-orchestrator/internal/bootstrapstart"
	"git.terrascale.tech/TerraScale/ts-orchestrator/internal/natscell"
)

// openControllerRuntime reconciles rooted shared identity before exposing any
// bridge, leafnode or ordinary authority on an installation that was re-keyed.
func openControllerRuntime(ctx context.Context, cfg Config, clockCheck func() error) (*natscell.Runtime, error) {
	if cfg.NATS.Lab {
		return natscell.Start(ctx, cfg.NATS)
	}
	accepted, err := bootstrapstart.NewMarkerStore().ReadIdentity()
	if err != nil {
		return nil, err
	}
	journal, err := bootstrapstart.ReadIdentityRekeyJournal(accepted)
	if errors.Is(err, os.ErrNotExist) {
		return natscell.Start(ctx, cfg.NATS)
	}
	if err != nil {
		return nil, err
	}
	observe := controllerIdentityObserver(cfg)
	if err := bootstrapstart.VerifyAcceptedLocalIdentity(accepted, observe); err != nil {
		return nil, err
	}
	held, err := natscell.StartIdentityRekey(ctx, cfg.NATS)
	if err != nil {
		return nil, err
	}
	defer held.Close()
	if err := held.WaitForCluster(ctx, cfg.NATS.Replicas); err != nil {
		return nil, fmt.Errorf("identity rekey quorum: %w", err)
	}
	envelope, err := journal.ResetEnvelope()
	if err != nil {
		return nil, err
	}
	if err := verifyIdentityRekeyGlobalScope(cfg, journal.Reset()); err != nil {
		return nil, err
	}
	// Completion and committed resumption retain the exact accepted root pins.
	completed, err := authority.IdentityResetCompletion(ctx, held.JetStream(), envelope,
		journal.AcceptedRoots(), journal.ResetTarget(), accepted.AcceptedAt)
	if err != nil {
		return nil, err
	}
	if completed == 0 {
		inputs, err := bootstrapstart.LoadTrustInputs(accepted)
		if err != nil {
			return nil, err
		}
		committed, err := authority.IdentityResetCommitted(ctx, held.JetStream(), envelope, journal.AcceptedRoots(), journal.ResetTarget())
		if err != nil {
			return nil, err
		}
		check := func() (time.Time, error) {
			if clockCheck == nil {
				return time.Time{}, errors.New("identity rekey requires healthy NTP before shared effects")
			}
			if err := clockCheck(); err != nil {
				return time.Time{}, err
			}
			if err := bootstrapstart.VerifyAcceptedLocalIdentity(accepted, observe); err != nil {
				return time.Time{}, err
			}
			fresh, err := bootstrapstart.ReadIdentityRekeyJournal(accepted)
			if err != nil {
				return time.Time{}, err
			}
			if !bytes.Equal(fresh.Wire(), journal.Wire()) {
				return time.Time{}, bootstrapstart.ErrIdentityRekeyJournal
			}
			inputs, err = bootstrapstart.LoadTrustInputs(accepted)
			if err != nil {
				return time.Time{}, err
			}
			now := time.Now().Round(0).UTC()
			if !committed {
				if _, err := journal.VerifyCurrent(inputs, now); err != nil {
					return time.Time{}, err
				}
			}
			return now, ctx.Err()
		}
		now, err := check()
		if err != nil {
			return nil, err
		}
		if !committed {
			if _, err := authority.ResetIdentityLease(ctx, held.JetStream(), envelope, inputs.Roots.Current, journal.ResetTarget(), now); err != nil {
				return nil, err
			}
			committed = true
		}
		now, err = check()
		if err != nil {
			return nil, err
		}
		if _, err := authority.ReplaceIdentityRecords(ctx, held.JetStream(), envelope, journal.AcceptedRoots(), journal.ResetTarget(), journal.Values(), now); err != nil {
			return nil, err
		}
		now, err = check()
		if err != nil {
			return nil, err
		}
		if _, err := authority.CompleteIdentityReset(ctx, held.JetStream(), envelope, journal.AcceptedRoots(), journal.ResetTarget(), now); err != nil {
			return nil, err
		}
	}
	// NATS cannot hot-add its leaf listener. Reopen this one broker only, using
	// the same store/name/Raft pins; its two connected peers retain quorum.
	if err := held.Close(); err != nil {
		return nil, err
	}
	if err := bootstrapstart.VerifyAcceptedLocalIdentity(accepted, observe); err != nil {
		return nil, err
	}
	return natscell.Start(ctx, cfg.NATS)
}

func verifyIdentityRekeyGlobalScope(cfg Config, reset authority.IdentityReset) error {
	home, err := globalControlHome(cfg.Controller.Global, cfg.NATS)
	if err != nil {
		return err
	}
	if (home == cfg.NATS.Cell) != (reset.GlobalLease != nil) {
		return errors.New("identity rekey must root-pin the global lease exactly in its topology home")
	}
	return nil
}

// checkControllerIdentityRekeyCompletion makes no cloud or broker mutation.
func checkControllerIdentityRekeyCompletion(ctx context.Context, cfg Config) error {
	ctx, cancel := context.WithTimeout(ctx, 15*time.Second)
	defer cancel()
	gate, _, err := acceptedControllerAdmissionGate(cfg, bootstrapstart.NewMarkerStore(), nil)
	if err != nil {
		return err
	}
	accepted, err := gate.AdmitIdentityRekeyCompletion(ctx)
	if err != nil {
		return err
	}
	client := cfg.NATS
	client.Embedded, client.ClientRole = nil, "controller"
	runtime, err := natscell.Start(ctx, client)
	if err != nil {
		return err
	}
	defer runtime.Close()
	return bootstrapstart.VerifyIdentityRekeyCompletion(ctx, accepted, runtime.JetStream())
}
