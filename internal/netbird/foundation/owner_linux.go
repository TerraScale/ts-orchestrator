// Package foundation owns the dedicated NetBird service before overlay admission.
package foundation

import (
	"context"
	"errors"
	"fmt"
	"log/slog"
	"time"

	"github.com/TerraScale/ts-orchestrator/internal/ociclient"
	"github.com/TerraScale/ts-orchestrator/internal/region"
)

type owner struct {
	factory        *ociclient.Factory
	resolver       region.FoundationResolver
	manager        region.VerifiedNetBirdManager
	custody        *storeCustody
	runtime        *componentRuntime
	configurations [3]componentConfiguration
	metadata       ownerRecord
	storeReady     bool
}

type ownerRecord struct {
	Version int          `json:"version"`
	Binding storeBinding `json:"binding"`
	Latest  BackupRecord `json:"latest"`
}

// RunOwner serves only the finite, independently admitted manager role. Losing
// remote authority still permits joining the directly owned local processes.
func RunOwner(ctx context.Context, factory *ociclient.Factory, resolver region.FoundationResolver, manager region.VerifiedNetBirdManager) (err error) {
	if ctx == nil || factory == nil {
		return errors.New("NetBird owner requires its current foundation identity")
	}
	if err := manager.Check(ctx); err != nil {
		return err
	}
	custody, err := openStoreCustody(ctx, manager, resolver)
	if err != nil {
		return err
	}
	defer func() { err = errors.Join(err, custody.Close()) }()
	o := &owner{factory: factory, resolver: resolver, manager: manager, custody: custody}
	material, err := o.current(ctx)
	if err != nil {
		return err
	}
	o.runtime, err = openComponentRuntime(custody)
	if err != nil {
		return err
	}
	defer func() {
		// Keep process handles and the store lock until every owned writer is joined.
		for {
			cleanup, cancel := context.WithTimeout(context.WithoutCancel(ctx), time.Minute)
			stopErr := o.runtime.quiesce(cleanup)
			cancel()
			if stopErr == nil {
				err = errors.Join(err, o.runtime.Close())
				return
			}
			slog.Error("NetBird shutdown is pending; retaining store custody", "error", stopErr)
			time.Sleep(time.Second)
		}
	}()
	if err := o.runtime.quiesce(ctx); err != nil {
		return err
	}
	found, err := custody.loadOwner(&o.metadata)
	if err != nil {
		return err
	}
	if found {
		if o.metadata.Version != 1 || o.metadata.Binding != custody.binding() ||
			o.metadata.Latest.Object == "" && (o.metadata.Latest.Bytes != 0 || !o.metadata.Latest.CreatedAt.IsZero()) {
			return errors.New("NetBird owner record belongs to a different physical store")
		}
	} else {
		o.metadata = ownerRecord{Version: 1, Binding: custody.binding()}
		if err := o.authorize(ctx, material); err != nil {
			return err
		}
		if err := custody.saveOwner(o.metadata); err != nil {
			return err
		}
	}
	if err := o.prepareAccount(ctx, material); err != nil {
		return err
	}
	if err := o.prepareStore(ctx, material); err != nil {
		return err
	}
	if err := o.reconcile(ctx, material); err != nil {
		return err
	}
	backupInterval := 6 * time.Hour
	if o.metadata.Latest.Object == "" || time.Since(o.metadata.Latest.CreatedAt) >= backupInterval {
		if err := o.backup(ctx, material); err != nil {
			if err := o.pending(ctx, err); err != nil {
				return err
			}
			backupInterval = time.Minute
		}
	}
	health := time.NewTicker(15 * time.Second)
	defer health.Stop()
	backup := time.NewTicker(backupInterval)
	defer backup.Stop()
	for {
		select {
		case <-ctx.Done():
			return ctx.Err()
		case <-health.C:
			material, err = o.current(ctx)
			if err != nil {
				if err := o.pending(ctx, err); err != nil {
					return err
				}
				continue
			}
			if err := o.reconcile(ctx, material); err != nil {
				if err := o.pending(ctx, err); err != nil {
					return err
				}
			}
		case <-backup.C:
			material, err = o.current(ctx)
			if err != nil {
				if err := o.pending(ctx, err); err != nil {
					return err
				}
				backup.Reset(time.Minute)
				continue
			}
			if err := o.backup(ctx, material); err != nil {
				if err := o.pending(ctx, err); err != nil {
					return err
				}
				backup.Reset(time.Minute)
			} else {
				backup.Reset(6 * time.Hour)
			}
		}
	}
}

func (o *owner) pending(ctx context.Context, cause error) error {
	if err := ctx.Err(); err != nil {
		return errors.Join(cause, err)
	}
	if errors.Is(cause, errComponentCustody) {
		return cause
	}
	if err := o.custody.check(); err != nil {
		return errors.Join(cause, err)
	}
	slog.Warn("NetBird reconciliation is pending", "error", cause)
	return nil
}

func (o *owner) authorize(ctx context.Context, material region.NetBirdComponents) error {
	if err := o.manager.Check(ctx); err != nil {
		return err
	}
	if err := material.Check(ctx); err != nil {
		return err
	}
	if err := material.RetainReleaseFloors(ctx); err != nil {
		return err
	}
	return o.custody.check()
}

func (o *owner) current(ctx context.Context) (region.NetBirdComponents, error) {
	material, err := region.ReadNetBirdComponents(ctx, o.factory, o.resolver, o.manager)
	if err != nil {
		return region.NetBirdComponents{}, err
	}
	if err := o.authorize(ctx, material); err != nil {
		return region.NetBirdComponents{}, err
	}
	return material, nil
}

func (o *owner) refresh(ctx context.Context, previous region.NetBirdComponents) (region.NetBirdComponents, error) {
	current, err := o.current(ctx)
	if err != nil {
		return region.NetBirdComponents{}, err
	}
	oldSet, nextSet := previous.ReleaseSnapshot(), current.ReleaseSnapshot()
	for i, role := range [3]string{"netbird-server", "netbird-dashboard", "netbird-ingress"} {
		old, next := oldSet[i], nextSet[i]
		if old.Role() != role || next.Role() != role {
			return region.NetBirdComponents{}, errors.New("NetBird resume requires the complete previous release set")
		}
		a, b := old.Release().Claim(), next.Release().Claim()
		am, bm := old.Release().Migration(), next.Release().Migration()
		if a.ReleaseSequence != b.ReleaseSequence || old.Release().ReleaseIdentity() != next.Release().ReleaseIdentity() ||
			a.Image != b.Image || a.SequenceMigrationSHA256 != b.SequenceMigrationSHA256 ||
			am.Namespace != bm.Namespace || am.Bucket != bm.Bucket || am.Region != bm.Region {
			return region.NetBirdComponents{}, errors.New("NetBird resume cannot change the quiesced component release set")
		}
	}
	return current, nil
}

func (o *owner) requestContext(ctx context.Context, material region.NetBirdComponents) context.Context {
	return ociclient.WithRequestGuard(ctx, func(wire context.Context) error {
		return o.authorize(wire, material)
	})
}

func (o *owner) configuration(ctx context.Context, material region.NetBirdComponents) ([]byte, error) {
	if err := o.authorize(ctx, material); err != nil {
		return nil, err
	}
	keys, err := region.ReadNetBirdConfiguration(o.requestContext(ctx, material), o.factory, o.resolver, o.manager)
	defer func() {
		for _, key := range keys {
			clear(key)
		}
	}()
	if err != nil {
		return nil, err
	}
	wire, err := renderConfiguration(keys)
	if err != nil {
		return nil, err
	}
	if err := o.authorize(ctx, material); err != nil {
		clear(wire)
		return nil, err
	}
	return wire, nil
}

func (o *owner) prepareStore(ctx context.Context, material region.NetBirdComponents) error {
	config, err := o.configuration(ctx, material)
	if err != nil {
		return err
	}
	defer clear(config)
	if o.custody.prepared() {
		if err := o.custody.verifyConfiguration(config); err != nil {
			return err
		}
		if err := o.custody.ready(); err != nil {
			return err
		}
	} else if !o.manager.RecoveryRequired() {
		if err := o.authorize(ctx, material); err != nil {
			return err
		}
		if err := o.custody.prepareGenesis(o.requestContext(ctx, material), o.manager, config); err != nil {
			return err
		}
		if err := o.initializeAccount(ctx, material); err != nil {
			return err
		}
	} else if err := o.restore(ctx, material, config); err != nil {
		return err
	}
	if err := o.authorize(ctx, material); err != nil {
		return err
	}
	if err := o.custody.prepareRuntime(o.requestContext(ctx, material), o.manager, []byte(ingressConfiguration)); err != nil {
		return err
	}
	o.configurations = configureComponents(o.custody.rootPath())
	return nil
}

func (o *owner) reconcile(ctx context.Context, material region.NetBirdComponents) error {
	config, err := o.configuration(ctx, material)
	if err != nil {
		return err
	}
	err = o.custody.verifyConfiguration(config)
	clear(config)
	if err != nil {
		return err
	}
	if err := o.runtime.backend(ctx, o, material); err != nil {
		return err
	}
	if err := o.ensureAccount(ctx, material); err != nil {
		return err
	}
	material, err = o.refresh(ctx, material)
	if err != nil {
		return err
	}
	if err := o.accountReady(ctx, material); err != nil {
		return err
	}
	if err := o.custody.ready(); err != nil {
		return err
	}
	if err := o.authorize(ctx, material); err != nil {
		return err
	}
	if !o.storeReady {
		if err := o.manager.MarkStoreReady(o.requestContext(ctx, material)); err != nil {
			return err
		}
		o.storeReady = true
	}
	return o.runtime.expose(ctx, o, material)
}

func (o *owner) restore(ctx context.Context, material region.NetBirdComponents, config []byte) error {
	ctx = o.requestContext(ctx, material)
	targets, err := NewBackupTargets(ctx, o.factory, o.resolver, o.manager)
	if err != nil {
		return err
	}
	var latest [2]BackupRecord
	for i, target := range targets {
		latest[i], err = LatestBackup(ctx, target)
		if err != nil && !errors.Is(err, ErrNoBackup) {
			return err
		}
	}
	selected := 0
	if latest[1].Object > latest[0].Object {
		selected = 1
	}
	record := latest[selected]
	if record.Object == "" {
		return ErrNoBackup
	}
	if err := o.archiveFloor(targets[0].scope, record); err != nil {
		return err
	}
	if err := o.authorize(ctx, material); err != nil {
		return err
	}
	_, err = Restore(ctx, targets[selected], record.Object, o.custody.rootPath()+"/store")
	if err != nil {
		mirror := 1 - selected
		if latest[mirror] != record {
			return err
		}
		if guardErr := o.authorize(ctx, material); guardErr != nil {
			return errors.Join(err, guardErr)
		}
		_, mirrorErr := Restore(ctx, targets[mirror], record.Object, o.custody.rootPath()+"/store")
		if mirrorErr != nil {
			return errors.Join(err, mirrorErr)
		}
	}
	if err := o.authorize(ctx, material); err != nil {
		return err
	}
	if err := o.custody.acceptRestoredStore(ctx, o.manager, config); err != nil {
		return err
	}
	o.metadata.Latest = record
	return o.custody.saveOwner(o.metadata)
}

func (o *owner) archiveFloor(scope backupScope, record BackupRecord) error {
	created, _, err := backupObjectDigest(scope, record.Object)
	if err != nil || record.Bytes <= 0 || record.Bytes > maxBackupBytes+(16<<20) || !record.CreatedAt.Equal(created) {
		return errors.Join(errors.New("NetBird archive metadata is invalid"), err)
	}
	if previous := o.metadata.Latest; previous.Object != "" {
		if _, _, err := backupObjectDigest(scope, previous.Object); err != nil {
			return err
		}
		if record.Object < previous.Object || record.Object == previous.Object && record != previous {
			return errors.New("NetBird archive would move behind the retained recovery floor")
		}
	}
	return nil
}

func (o *owner) backup(ctx context.Context, material region.NetBirdComponents) error {
	base := ctx
	ctx = ociclient.WithRequestGuard(ctx, func(wire context.Context) error {
		return o.authorize(wire, material)
	})
	targets, err := NewBackupTargets(ctx, o.factory, o.resolver, o.manager)
	if err != nil {
		return err
	}
	if err := o.authorize(ctx, material); err != nil {
		return err
	}
	record, err := Backup(ctx, o.custody.rootPath()+"/store/data", o.custody.rootPath()+"/store/config.yaml", targets,
		func(stop context.Context) (func(context.Context) error, error) {
			if err := o.runtime.quiesce(stop); err != nil {
				return nil, err
			}
			if err := o.custody.check(); err != nil {
				return nil, err
			}
			return func(resume context.Context) error {
				deadline, ok := resume.Deadline()
				if !ok {
					return errors.New("NetBird backup resume requires a bounded cleanup context")
				}
				// Reacquire CURRENT without carrying the quiesced proof's wire guard.
				fresh, cancel := context.WithDeadline(context.WithoutCancel(base), deadline)
				defer cancel()
				stop := context.AfterFunc(resume, cancel)
				defer stop()
				current, err := o.refresh(fresh, material)
				if err != nil {
					return err
				}
				material = current
				return o.reconcile(fresh, current)
			}, nil
		})
	if err != nil {
		return fmt.Errorf("NetBird protected backup: %w", err)
	}
	if err := o.archiveFloor(targets[0].scope, record); err != nil {
		return err
	}
	if err := o.authorize(ctx, material); err != nil {
		return err
	}
	o.metadata.Latest = record
	return o.custody.saveOwner(o.metadata)
}
