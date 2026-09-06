package keylease

import (
	"context"
	"strings"
	"time"
)

// DatabaseScope identifies the database whose local wrapped copies are removed.
// The caller must prove deletion authority for this full scope before invoking
// destruction; a database ID alone is not an authorization boundary.
type DatabaseScope struct {
	Environment string `json:"environment"`
	TenantID    string `json:"tenant_id"`
	ProjectID   string `json:"project_id"`
	DatabaseID  string `json:"database_id"`
}

func (scope DatabaseScope) valid() bool {
	return validEnvironment(scope.Environment) && validULID(scope.TenantID) && validULID(scope.ProjectID) && validULID(scope.DatabaseID)
}
func (b Binding) Scope() DatabaseScope {
	return DatabaseScope{Environment: b.Environment, TenantID: b.TenantID, ProjectID: b.ProjectID, DatabaseID: b.DatabaseID}
}

type DatabaseTombstone struct {
	Scope          DatabaseScope `json:"scope"`
	OperationKey   string        `json:"operation_key"`
	DestroyedAt    time.Time     `json:"destroyed_at"`
	LeasesExpireAt time.Time     `json:"leases_expire_at"`
	RemovedCopies  uint32        `json:"removed_copies"`
}

// DestructionReceipt is a local durable fact, never a global crypto-shred proof.
// Every admitted host must acknowledge its tombstone and all reported lease
// horizons must pass before the fenced reaper can conclude key destruction.
type DestructionReceipt = DatabaseTombstone

func (tombstone DatabaseTombstone) valid() bool {
	return tombstone.Scope.valid() && len(tombstone.OperationKey) > 0 && len(tombstone.OperationKey) <= 256 && !strings.ContainsAny(tombstone.OperationKey, "\x00\r\n") && !tombstone.DestroyedAt.IsZero() && !tombstone.LeasesExpireAt.Before(tombstone.DestroyedAt) && tombstone.LeasesExpireAt.Sub(tombstone.DestroyedAt) <= 1800*time.Second
}
func (c Catalog) destroyed(scope DatabaseScope) bool {
	for _, tombstone := range c.Tombstones {
		if tombstone.Scope == scope {
			return true
		}
	}
	return false
}

// DestroyDatabase removes every version/purpose/Region wrapper for this scope,
// retaining a permanent tombstone that refuses late deliveries and new issuance.
// It neither destroys a shared regional KEK nor claims to erase another host.
func DestroyDatabase(ctx context.Context, path string, scope DatabaseScope, operationKey string) (DestructionReceipt, error) {
	return destroyDatabase(ctx, path, scope, operationKey, time.Time{})
}
func destroyDatabase(ctx context.Context, path string, scope DatabaseScope, operationKey string, now time.Time) (DestructionReceipt, error) {
	tombstone := DatabaseTombstone{Scope: scope, OperationKey: operationKey, DestroyedAt: now, LeasesExpireAt: now.Add(1800 * time.Second)}
	probe := tombstone
	if now.IsZero() {
		probe.DestroyedAt = time.Unix(1, 0)
		probe.LeasesExpireAt = probe.DestroyedAt
	}
	if ctx == nil || ctx.Err() != nil || !probe.valid() {
		return DestructionReceipt{}, ErrUnavailable
	}
	unlock, err := catalogLock(path)
	if err != nil {
		return DestructionReceipt{}, ErrUnavailable
	}
	defer unlock()
	if now.IsZero() {
		now = time.Now().UTC()
		tombstone.DestroyedAt = now
		tombstone.LeasesExpireAt = now.Add(1800 * time.Second)
	}
	catalog, err := ReadCatalog(path)
	if err != nil {
		return DestructionReceipt{}, ErrUnavailable
	}
	for _, existing := range catalog.Tombstones {
		if existing.Scope == scope {
			if existing.OperationKey != operationKey {
				return DestructionReceipt{}, ErrUnavailable
			}
			return existing, nil
		}
	}
	kept := make([]Entry, 0, len(catalog.Entries))
	for _, entry := range catalog.Entries {
		if entry.Binding.Scope() != scope {
			kept = append(kept, entry)
			continue
		}
		tombstone.RemovedCopies++
		// Keep the global maximum horizon even if a previously issued version
		// was already retired from this catalog before deletion began.
		// A lease issued immediately before this commit can live this long even
		// when the wrapper is already expired/revoked by the time it is removed.
		expiry := now.Add(time.Duration(entry.LeaseSeconds) * time.Second)
		if expiry.After(tombstone.LeasesExpireAt) {
			tombstone.LeasesExpireAt = expiry
		}
	}
	catalog.Entries = kept
	catalog.Tombstones = append(catalog.Tombstones, tombstone)
	if ctx.Err() != nil || writeCatalog(path, catalog) != nil {
		return DestructionReceipt{}, ErrUnavailable
	}
	return tombstone, nil
}

func sameTombstone(a, b DatabaseTombstone) bool {
	ad, bd, ae, be := a.DestroyedAt, b.DestroyedAt, a.LeasesExpireAt, b.LeasesExpireAt
	a.DestroyedAt = time.Time{}
	b.DestroyedAt = time.Time{}
	a.LeasesExpireAt = time.Time{}
	b.LeasesExpireAt = time.Time{}
	return a == b && ad.Equal(bd) && ae.Equal(be)
}
