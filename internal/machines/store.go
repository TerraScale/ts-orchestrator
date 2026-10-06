package machines

import (
	"cmp"
	"context"
	"errors"
	"fmt"
	"slices"
	"time"

	"git.terrascale.tech/TerraScale/ts-orchestrator/internal/authority"
	"git.terrascale.tech/TerraScale/ts-orchestrator/internal/protocol"
	"github.com/nats-io/nats.go/jetstream"
)

const (
	// Bucket holds apps and machines, the desired state. It is snapshotted
	// with the other configuration buckets.
	Bucket = "TS_APPS"
	// StatusBucket holds observed machine states. A rebuilt cell relearns
	// them from its hosts, so it is not snapshotted.
	StatusBucket = "TS_MACHINE_STATUS"
)

const maxRecordBytes = 64 << 10

var (
	ErrNotFound    = errors.New("app or machine record not found")
	ErrConflict    = errors.New("app or machine record changed concurrently")
	ErrHasMachines = errors.New("app still has machines")
)

func appKey(name string) string        { return "apps." + name }
func machineKey(app, id string) string { return "machines." + app + "." + id }
func statusKey(app, id string) string  { return "status." + app + "." + id }

func (a App) key() string     { return appKey(a.Name) }
func (m Machine) key() string { return machineKey(m.App, m.ID) }
func (s Status) key() string  { return statusKey(s.App, s.ID) }

func (a *App) revision() *uint64     { return &a.Revision }
func (m *Machine) revision() *uint64 { return &m.Revision }
func (s *Status) revision() *uint64  { return &s.Revision }

// Store keeps one region's apps, machines and statuses. Only the authority
// leader writes: every write is guarded by the writer's authority epoch and
// is a compare-and-swap on the record's Revision (zero creates). Every read
// checks that a record is valid and belongs to its key.
type Store struct {
	apps, statuses jetstream.KeyValue
	region         string
	fencer         authority.Fencer
}

// OpenStore provisions or binds both buckets for region.
func OpenStore(ctx context.Context, js jetstream.JetStream, region string, replicas int, fencer authority.Fencer) (*Store, error) {
	if js == nil || fencer == nil || !validRegion(region) || replicas != 1 && replicas != 3 && replicas != 5 {
		return nil, fmt.Errorf("%w: store configuration", ErrInvalid)
	}
	open := func(bucket, description string) (jetstream.KeyValue, error) {
		kv, err := js.CreateOrUpdateKeyValue(ctx, jetstream.KeyValueConfig{
			Bucket: bucket, Description: description, History: 4, MaxValueSize: maxRecordBytes,
			MaxBytes: 256 << 20, Storage: jetstream.FileStorage, Replicas: replicas,
		})
		if err != nil {
			return nil, fmt.Errorf("open %s: %w", bucket, err)
		}
		return kv, nil
	}
	apps, err := open(Bucket, "ts-orch apps and machines")
	if err != nil {
		return nil, err
	}
	statuses, err := open(StatusBucket, "ts-orch observed machine states")
	if err != nil {
		return nil, err
	}
	return &Store{apps: apps, statuses: statuses, region: region, fencer: fencer}, nil
}

// App returns an app.
func (s *Store) App(ctx context.Context, name string) (App, error) {
	return get[App](ctx, s.apps, appKey(name))
}

// Apps lists every app by name.
func (s *Store) Apps(ctx context.Context) ([]App, error) {
	apps, err := list[App](ctx, s.apps, "apps.*")
	slices.SortFunc(apps, func(a, b App) int { return cmp.Compare(a.Name, b.Name) })
	return apps, err
}

// PutApp creates the app (Revision zero) or replaces the one at Revision,
// and returns what it stored. The store sets ID and Version; ID, Class and
// Tenant never change. An unchanged app is a no-op.
func (s *Store) PutApp(ctx context.Context, epoch uint64, app App) (App, error) {
	if app.Revision == 0 {
		app.ID, app.Version = newID(), 1
	} else {
		current, err := s.App(ctx, app.Name)
		if err != nil {
			return App{}, err
		}
		if current.Revision != app.Revision {
			return App{}, fmt.Errorf("%w: %s", ErrConflict, app.key())
		}
		if app.ID != current.ID || app.Class != current.Class || app.Tenant != current.Tenant {
			return App{}, fmt.Errorf("%w: app %s ID, class and tenant never change", ErrInvalid, app.Name)
		}
		app.Version = current.Version
		if !sameJSON(app.Config, current.Config) {
			app.Version++
		} else if sameJSON(app, current) {
			return current, nil
		}
	}
	if err := app.Validate(); err != nil {
		return App{}, err
	}
	if err := put(ctx, s, s.apps, epoch, &app); err != nil {
		return App{}, err
	}
	return app, nil
}

// DeleteApp deletes the app at its Revision once no machine record names
// it. A machine created for it concurrently keeps the deleted app's ID, so
// it is an orphan that the scheduler destroys.
func (s *Store) DeleteApp(ctx context.Context, epoch uint64, app App) error {
	machines, err := s.Machines(ctx, app.Name)
	if err != nil {
		return err
	}
	if len(machines) != 0 {
		return fmt.Errorf("%w: %s has %d", ErrHasMachines, app.Name, len(machines))
	}
	return remove(ctx, s, s.apps, epoch, app.key(), app.Revision)
}

// Machine returns a machine.
func (s *Store) Machine(ctx context.Context, app, id string) (Machine, error) {
	return get[Machine](ctx, s.apps, machineKey(app, id))
}

// Machines lists the machines whose App is app, orphans included, or every
// machine when app is empty, by app and ID.
func (s *Store) Machines(ctx context.Context, app string) ([]Machine, error) {
	filter, err := appFilter("machines", app)
	if err != nil {
		return nil, err
	}
	machines, err := list[Machine](ctx, s.apps, filter)
	slices.SortFunc(machines, func(a, b Machine) int { return cmp.Or(cmp.Compare(a.App, b.App), cmp.Compare(a.ID, b.ID)) })
	return machines, err
}

// PutMachine creates the machine (Revision zero) or replaces the one at
// Revision, and returns what it stored. A new machine is in the store's
// region and belongs to the current app of its name. AppID, Region and a
// set Host never change, and a destroyed machine stays destroyed.
func (s *Store) PutMachine(ctx context.Context, epoch uint64, machine Machine) (Machine, error) {
	if err := machine.Validate(); err != nil {
		return Machine{}, err
	}
	if machine.Revision == 0 {
		if machine.Region != s.region {
			return Machine{}, fmt.Errorf("%w: machine %s is not in region %s", ErrInvalid, machine.ID, s.region)
		}
		app, err := s.App(ctx, machine.App)
		if err != nil {
			return Machine{}, err
		}
		if app.ID != machine.AppID {
			return Machine{}, fmt.Errorf("%w: machine %s names another incarnation of app %s", ErrInvalid, machine.ID, app.Name)
		}
	} else {
		current, err := s.Machine(ctx, machine.App, machine.ID)
		if err != nil {
			return Machine{}, err
		}
		if current.Revision != machine.Revision {
			return Machine{}, fmt.Errorf("%w: %s", ErrConflict, machine.key())
		}
		switch {
		case machine.AppID != current.AppID || machine.Region != current.Region:
			return Machine{}, fmt.Errorf("%w: machine %s app and region never change", ErrInvalid, machine.ID)
		case current.Host != "" && (machine.Host != current.Host || machine.FailureDomain != current.FailureDomain):
			return Machine{}, fmt.Errorf("%w: machine %s host never changes once placed", ErrInvalid, machine.ID)
		case current.Desired == DesiredDestroyed && machine.Desired != DesiredDestroyed:
			return Machine{}, fmt.Errorf("%w: machine %s is destroyed", ErrInvalid, machine.ID)
		}
	}
	if err := put(ctx, s, s.apps, epoch, &machine); err != nil {
		return Machine{}, err
	}
	return machine, nil
}

// DeleteMachine deletes a destroyed machine's records at its Revision. A
// placed machine needs a destroyed status first, so its record outlives its
// process. The machine goes first; a status left behind, for example by a
// host report racing the delete, is removed by SweepStatuses.
func (s *Store) DeleteMachine(ctx context.Context, epoch uint64, machine Machine) error {
	current, err := s.Machine(ctx, machine.App, machine.ID)
	if err != nil {
		return err
	}
	if current.Revision != machine.Revision {
		return fmt.Errorf("%w: %s", ErrConflict, machine.key())
	}
	if current.Desired != DesiredDestroyed {
		return fmt.Errorf("%w: machine %s is not destroyed", ErrInvalid, machine.ID)
	}
	status, err := s.Status(ctx, machine.App, machine.ID)
	if err != nil && !errors.Is(err, ErrNotFound) {
		return err
	}
	if current.Host != "" && status.State != StateDestroyed {
		return fmt.Errorf("%w: machine %s has not been observed destroyed", ErrInvalid, machine.ID)
	}
	if err := remove(ctx, s, s.apps, epoch, current.key(), current.Revision); err != nil {
		return err
	}
	if status.Revision != 0 {
		// Best effort: SweepStatuses retries.
		_ = remove(ctx, s, s.statuses, epoch, status.key(), status.Revision)
	}
	return nil
}

// SweepStatuses deletes the statuses whose machine is gone and returns how
// many it deleted. Statuses are listed before machines: a machine always
// exists before its status, so a status listed first whose machine is
// missing afterwards is an orphan, never a status of a new machine. A status
// that changes during the sweep is left for the next one.
func (s *Store) SweepStatuses(ctx context.Context, epoch uint64) (int, error) {
	statuses, err := s.Statuses(ctx, "")
	if err != nil {
		return 0, err
	}
	machines, err := s.Machines(ctx, "")
	if err != nil {
		return 0, err
	}
	live := make(map[string]bool, len(machines))
	for _, machine := range machines {
		live[statusKey(machine.App, machine.ID)] = true
	}
	swept := 0
	for _, status := range statuses {
		if live[status.key()] {
			continue
		}
		err := remove(ctx, s, s.statuses, epoch, status.key(), status.Revision)
		switch {
		case err == nil:
			swept++
		case !errors.Is(err, ErrConflict):
			return swept, err
		}
	}
	return swept, nil
}

// Status returns a machine's observed status.
func (s *Store) Status(ctx context.Context, app, id string) (Status, error) {
	return get[Status](ctx, s.statuses, statusKey(app, id))
}

// Statuses lists the statuses of app's machines, or of every machine when
// app is empty, by app and ID.
func (s *Store) Statuses(ctx context.Context, app string) ([]Status, error) {
	filter, err := appFilter("status", app)
	if err != nil {
		return nil, err
	}
	statuses, err := list[Status](ctx, s.statuses, filter)
	slices.SortFunc(statuses, func(a, b Status) int { return cmp.Or(cmp.Compare(a.App, b.App), cmp.Compare(a.ID, b.ID)) })
	return statuses, err
}

// PutStatus creates a machine's status (Revision zero) or replaces the one
// at Revision, stamps UpdatedAt and returns what it stored. Only an
// existing machine gets a status, and destroyed is final. A write that races
// the machine's deletion can still leave a status behind; SweepStatuses
// removes it, and readers join statuses to machines.
func (s *Store) PutStatus(ctx context.Context, epoch uint64, status Status) (Status, error) {
	status.UpdatedAt = time.Now().UTC()
	if err := status.Validate(); err != nil {
		return Status{}, err
	}
	if _, err := s.Machine(ctx, status.App, status.ID); err != nil {
		return Status{}, err
	}
	if status.Revision != 0 {
		current, err := s.Status(ctx, status.App, status.ID)
		if err != nil {
			return Status{}, err
		}
		if current.Revision != status.Revision {
			return Status{}, fmt.Errorf("%w: %s", ErrConflict, status.key())
		}
		if current.State == StateDestroyed && status.State != StateDestroyed {
			return Status{}, fmt.Errorf("%w: machine %s is destroyed", ErrInvalid, status.ID)
		}
	}
	if err := put(ctx, s, s.statuses, epoch, &status); err != nil {
		return Status{}, err
	}
	return status, nil
}

func appFilter(prefix, app string) (string, error) {
	if app == "" {
		return prefix + ".>", nil
	}
	if !tokenRE.MatchString(app) {
		return "", fmt.Errorf("%w: app name", ErrInvalid)
	}
	return prefix + "." + app + ".*", nil
}

type record[T any] interface {
	*T
	Validate() error
	key() string
	revision() *uint64
}

func decode[T any, P record[T]](key string, data []byte, revision uint64) (T, error) {
	var value T
	if err := protocol.DecodeStrict(data, &value, maxRecordBytes); err != nil {
		return value, fmt.Errorf("%w: %s: %v", ErrInvalid, key, err)
	}
	if err := P(&value).Validate(); err != nil {
		return value, fmt.Errorf("%s: %w", key, err)
	}
	if P(&value).key() != key {
		return value, fmt.Errorf("%w: %s holds the record of %s", ErrInvalid, key, P(&value).key())
	}
	*P(&value).revision() = revision
	return value, nil
}

func get[T any, P record[T]](ctx context.Context, kv jetstream.KeyValue, key string) (T, error) {
	entry, err := kv.Get(ctx, key)
	if errors.Is(err, jetstream.ErrKeyNotFound) {
		return *new(T), fmt.Errorf("%w: %s", ErrNotFound, key)
	}
	if err != nil {
		return *new(T), fmt.Errorf("read %s: %w", key, err)
	}
	return decode[T, P](key, entry.Value(), entry.Revision())
}

// list reads every value under filter in one pass. A record that fails its
// checks fails the whole list: callers never act on a partial view.
func list[T any, P record[T]](ctx context.Context, kv jetstream.KeyValue, filter string) ([]T, error) {
	watcher, err := kv.WatchFiltered(ctx, []string{filter}, jetstream.IgnoreDeletes())
	if err != nil {
		return nil, fmt.Errorf("list %s: %w", filter, err)
	}
	defer stopWatch(watcher)
	var values []T
	var bad error
	for {
		select {
		case entry, ok := <-watcher.Updates():
			if !ok {
				return nil, fmt.Errorf("list %s: watcher closed early", filter)
			}
			if entry == nil {
				if bad != nil {
					return nil, bad
				}
				return values, nil
			}
			// Keep reading after a bad record: the watcher blocks on unread
			// values.
			if value, err := decode[T, P](entry.Key(), entry.Value(), entry.Revision()); err != nil {
				bad = errors.Join(bad, err)
			} else {
				values = append(values, value)
			}
		case <-ctx.Done():
			return nil, fmt.Errorf("list %s: %w", filter, ctx.Err())
		}
	}
}

// stopWatch stops a watcher and drains it for at most a minute: a delivery
// blocked on its full Updates channel holds it open until read.
func stopWatch(watcher jetstream.KeyWatcher) {
	_ = watcher.Stop()
	go func() {
		timeout := time.NewTimer(time.Minute)
		defer timeout.Stop()
		for {
			select {
			case _, ok := <-watcher.Updates():
				if !ok {
					return
				}
			case <-timeout.C:
				return
			}
		}
	}()
}

// sameJSON compares canonical encodings, where nil and empty collections
// are equal.
func sameJSON(a, b any) bool {
	left, leftErr := protocol.EncodeJSON(a)
	right, rightErr := protocol.EncodeJSON(b)
	return leftErr == nil && rightErr == nil && string(left) == string(right)
}

// put writes value at its Revision after checking the writer's epoch, and
// sets the new Revision.
func put[T any, P record[T]](ctx context.Context, s *Store, kv jetstream.KeyValue, epoch uint64, value P) error {
	key := value.key()
	data, err := protocol.EncodeJSON(value)
	if err != nil {
		return err
	}
	if len(data) > maxRecordBytes {
		return fmt.Errorf("%w: %s exceeds %d bytes", ErrInvalid, key, maxRecordBytes)
	}
	if err := s.fencer.Guard(ctx, epoch); err != nil {
		return err
	}
	revision := value.revision()
	var written uint64
	if *revision == 0 {
		written, err = kv.Create(ctx, key, data)
	} else {
		written, err = kv.Update(ctx, key, data, *revision)
	}
	if errors.Is(err, jetstream.ErrKeyExists) || errors.Is(err, jetstream.ErrKeyRevisionMismatch) {
		return fmt.Errorf("%w: %s", ErrConflict, key)
	}
	if err != nil {
		return fmt.Errorf("write %s: %w", key, err)
	}
	*revision = written
	return nil
}

func remove(ctx context.Context, s *Store, kv jetstream.KeyValue, epoch uint64, key string, revision uint64) error {
	if revision == 0 {
		return fmt.Errorf("%w: delete %s needs its revision", ErrInvalid, key)
	}
	if err := s.fencer.Guard(ctx, epoch); err != nil {
		return err
	}
	err := kv.Delete(ctx, key, jetstream.LastRevision(revision))
	if errors.Is(err, jetstream.ErrKeyRevisionMismatch) || errors.Is(err, jetstream.ErrKeyExists) {
		return fmt.Errorf("%w: %s", ErrConflict, key)
	}
	if err != nil {
		return fmt.Errorf("delete %s: %w", key, err)
	}
	return nil
}
