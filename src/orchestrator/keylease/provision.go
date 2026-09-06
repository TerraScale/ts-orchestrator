package keylease

import (
	"context"
	"crypto/rand"
	"os"
	"time"

	"golang.org/x/sys/unix"
	"terrascale.tech/orchestrator/src/orchestrator/hostsecrets"
)

// ProvisionTarget names an already admitted regional KEK and the exact key
// version allocated by the durable database-create operation. Purposes are
// provisioned separately; selected regions receive the same database DEK.
type ProvisionTarget struct {
	Binding        Binding
	CryptoEndpoint string
	KEKID          string
	KEKVersionID   string
	LeaseSeconds   uint32
	NotAfter       time.Time
}

type WrapFunc func(context.Context, ProvisionTarget, []byte) (string, error)

// Provision is idempotent for the complete set of scope/version/region bindings.
// It acknowledges only after every selected Region's wrapped copy is fsynced.
// A caller must replicate this ciphertext catalog to admitted member hosts
// before publishing placement; the lease socket never generates missing keys.
func Provision(ctx context.Context, path string, targets []ProvisionTarget) error {
	return provision(ctx, path, targets, func(ctx context.Context, target ProvisionTarget, key []byte) (string, error) {
		return hostsecrets.WrapDataKey(ctx, ociRegion(target.Binding.Region), target.CryptoEndpoint, target.KEKID, target.KEKVersionID, key, target.Binding.AssociatedData())
	})
}
func provision(ctx context.Context, path string, targets []ProvisionTarget, wrap WrapFunc) error {
	if ctx == nil || ctx.Err() != nil || len(targets) < 1 || len(targets) > 3 || wrap == nil {
		return ErrUnavailable
	}
	probe := Catalog{Version: 1}
	primary := targets[0].Binding
	for _, target := range targets {
		binding := target.Binding
		binding.Region = primary.Region
		if binding != primary || !target.NotAfter.After(time.Now()) {
			return ErrUnavailable
		}
		probe.Entries = append(probe.Entries, Entry{Binding: target.Binding, CryptoEndpoint: target.CryptoEndpoint, KEKID: target.KEKID, KEKVersionID: target.KEKVersionID, Ciphertext: "pending", LeaseSeconds: target.LeaseSeconds, NotAfter: target.NotAfter})
	}
	if probe.validate() != nil {
		return ErrUnavailable
	}
	unlock, err := catalogLock(path)
	if err != nil {
		return ErrUnavailable
	}
	defer unlock()
	catalog, err := ReadCatalog(path)
	if err != nil {
		return ErrUnavailable
	}
	existing := 0
	for _, target := range targets {
		for _, entry := range catalog.Entries {
			if entry.Binding == target.Binding {
				if entry.Revoked || entry.KEKID != target.KEKID || entry.KEKVersionID != target.KEKVersionID || entry.CryptoEndpoint != target.CryptoEndpoint || entry.LeaseSeconds != target.LeaseSeconds || !entry.NotAfter.Equal(target.NotAfter) {
					return ErrUnavailable
				}
				existing++
			}
		}
	}
	scopeCopies := 0
	for _, entry := range catalog.Entries {
		binding := entry.Binding
		binding.Region = primary.Region
		if binding == primary {
			scopeCopies++
		}
	}
	if existing == len(targets) {
		if scopeCopies != len(targets) {
			return ErrUnavailable
		}
		return nil
	}
	if existing != 0 {
		return ErrUnavailable
	}
	// A scope/version cannot later gain a region by generating unrelated material.
	for _, entry := range catalog.Entries {
		binding := entry.Binding
		binding.Region = primary.Region
		if binding == primary {
			return ErrUnavailable
		}
	}
	locked, err := unix.Mmap(-1, 0, 4096, unix.PROT_READ|unix.PROT_WRITE, unix.MAP_PRIVATE|unix.MAP_ANON)
	if err != nil {
		return ErrUnavailable
	}
	defer func() { clear(locked); unix.Munlock(locked); unix.Munmap(locked) }()
	if unix.Mlock(locked) != nil || unix.Madvise(locked, unix.MADV_DONTDUMP) != nil {
		return ErrUnavailable
	}
	if _, err := rand.Read(locked[:32]); err != nil {
		return ErrUnavailable
	}
	for i, target := range targets {
		ciphertext, err := wrap(ctx, target, locked[:32])
		if err != nil || ctx.Err() != nil {
			return ErrUnavailable
		}
		entry := probe.Entries[i]
		entry.Ciphertext = ciphertext
		catalog.Entries = append(catalog.Entries, entry)
	}
	if writeCatalog(path, catalog) != nil {
		return ErrUnavailable
	}
	return nil
}

func catalogLock(path string) (func(), error) {
	root, name, err := privateRoot(path)
	if err != nil {
		return nil, ErrUnavailable
	}
	f, err := root.OpenFile(name+".lock", os.O_CREATE|os.O_RDWR|unix.O_NOFOLLOW, 0600)
	root.Close()
	if err != nil {
		return nil, ErrUnavailable
	}
	var st unix.Stat_t
	if unix.Fstat(int(f.Fd()), &st) != nil || st.Uid != uint32(os.Geteuid()) || st.Mode&0777 != 0600 || st.Mode&unix.S_IFMT != unix.S_IFREG || unix.Flock(int(f.Fd()), unix.LOCK_EX|unix.LOCK_NB) != nil {
		f.Close()
		return nil, ErrUnavailable
	}
	return func() { unix.Flock(int(f.Fd()), unix.LOCK_UN); f.Close() }, nil
}
