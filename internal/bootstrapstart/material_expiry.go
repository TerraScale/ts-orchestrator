package bootstrapstart

import (
	"context"
	"errors"
	"os"
	"time"

	"github.com/TerraScale/ts-orchestrator/internal/bootstrap"
	"github.com/TerraScale/ts-orchestrator/internal/maintenance"
	"github.com/TerraScale/ts-orchestrator/internal/observability"
	"github.com/TerraScale/ts-orchestrator/internal/trust"
	"golang.org/x/sys/unix"
)

// BrokerCredentialExpiries reads only the two fixed privileged broker users,
// after verifying their exact signed material pins and root-only file custody.
// The result contains public times; no JWT, seed, path or selector is returned.
func (store MaterialStore) BrokerCredentialExpiries(ctx context.Context, accepted AcceptedIdentity, roots trust.Keyring) ([]observability.CredentialView, error) {
	if os.Geteuid() != 0 || ctx == nil || ctx.Err() != nil {
		return nil, ErrMaterial
	}
	dir, err := openMaterialDirectory(store.installedDirectory, store.serviceUID, store.serviceGID, 0o700, store.allowUnsafeAncestors)
	if err != nil {
		return nil, err
	}
	defer unix.Close(dir)
	pins, err := restartPins(dir, store.serviceUID, store.serviceGID, accepted, roots)
	if err != nil {
		return nil, err
	}
	if pins.Generation != nil && !time.Now().Before(pins.Generation.ExpiresAt()) {
		return nil, ErrMaterial
	}
	views := []observability.CredentialView{}
	for _, user := range []struct{ name, label string }{
		{"system.creds", "nats system credentials"},
		{"membership.creds", "nats membership credentials"},
	} {
		if ctx.Err() != nil {
			return nil, ctx.Err()
		}
		want := pins.Digests[user.name]
		if want == "" {
			if user.name == "system.creds" {
				return nil, ErrMaterial
			}
			continue
		}
		wire, err := readMaterial(dir, user.name, store.serviceUID, store.serviceGID, want, bootstrap.MaxSecretBytes)
		if err != nil {
			return nil, err
		}
		found, err := maintenance.CredentialExpiries(user.label, wire)
		clear(wire)
		if err != nil {
			return nil, err
		}
		views = append(views, found...)
	}
	current, err := restartPins(dir, store.serviceUID, store.serviceGID, accepted, roots)
	if err != nil || !sameMaterials(pins.Digests, current.Digests) {
		return nil, errors.Join(ErrMaterial, err)
	}
	if pins.Generation != nil && (current.Generation == nil ||
		pins.Generation.Fingerprint() != current.Generation.Fingerprint() ||
		!time.Now().Before(current.Generation.ExpiresAt())) {
		return nil, ErrMaterial
	}
	if pins.Generation == nil && current.Generation != nil {
		return nil, ErrMaterial
	}
	return views, ctx.Err()
}
