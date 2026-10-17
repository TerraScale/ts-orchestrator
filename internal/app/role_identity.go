package app

import (
	"context"
	"errors"
	"fmt"
	"os"
	"time"

	"github.com/TerraScale/ts-orchestrator/internal/host"
	"github.com/TerraScale/ts-orchestrator/internal/hostenroll"
	"github.com/TerraScale/ts-orchestrator/internal/natscell"
	"github.com/TerraScale/ts-orchestrator/internal/roleidentity"
	"github.com/nats-io/nats.go/jetstream"
)

// loadHostIssuer loads the controller's host NATS and TLS issuer.
func loadHostIssuer(ctx context.Context, cfg Config, native controllerBrokerNative) (*hostenroll.Issuer, error) {
	if err := ctx.Err(); err != nil {
		return nil, err
	}
	if native == nil || cfg.NATS.Embedded == nil {
		return nil, errors.New("regional host enrollment requires the native controller account")
	}
	account, err := native.ReadControllerAccount(ctx)
	if err != nil {
		return nil, err
	}
	rootPEM, err := os.ReadFile(cfg.NATS.Embedded.TLS.CAFile)
	if err != nil || len(rootPEM) == 0 || len(rootPEM) > 8192 {
		return nil, errors.New("regional host enrollment CA is unavailable")
	}
	issuer, err := hostenroll.LoadIssuer(cfg.NATS.Cell, account.Account,
		cfg.Controller.HostNATSIssuerSeedFile, cfg.Controller.HostTLSIssuerKeyFile,
		cfg.Controller.HostTLSIssuerCertFile, rootPEM)
	if err != nil {
		return nil, err
	}
	current, err := native.ReadControllerAccount(ctx)
	if err == nil && current.Account != issuer.CellAccount {
		err = errors.New("host issuer account changed while loading its keys")
	}
	if err == nil {
		err = issuer.ValidateAccountScope(current.JWT)
	}
	if err != nil {
		issuer.NATSKey.Wipe()
		return nil, err
	}
	return issuer, nil
}

// roleIdentityIssuer issues a granted role's NATS identity (TS-651) once the
// broker's current cell account carries the role signer, after it creates
// the role's buckets: a role may read and write them but not create them.
func roleIdentityIssuer(issuer *hostenroll.Issuer, transport *natscell.Runtime, native controllerBrokerNative, replicas int) host.RoleIdentityIssuer {
	validateScope := func(ctx context.Context) error {
		if err := ctx.Err(); err != nil {
			return err
		}
		if issuer == nil || native == nil {
			return errors.New("role identity requires the native controller account")
		}
		account, err := native.ReadControllerAccount(ctx)
		if err != nil {
			return err
		}
		if account.Account != issuer.CellAccount {
			return errors.New("role issuer differs from the native controller account")
		}
		return issuer.ValidateRoleScope(account.JWT)
	}
	return func(ctx context.Context, role, node, userKey, csrPEM string) (string, []byte, error) {
		if transport == nil {
			return "", nil, errors.New("role identity requires the controller transport")
		}
		if err := validateScope(ctx); err != nil {
			return "", nil, err
		}
		for _, bucket := range roleidentity.Grants[role].Buckets {
			storage := jetstream.FileStorage
			if bucket.Memory {
				storage = jetstream.MemoryStorage
			}
			if _, err := transport.JetStream().CreateOrUpdateKeyValue(ctx, jetstream.KeyValueConfig{Bucket: bucket.Name,
				TTL: bucket.TTL, History: bucket.History, Storage: storage, Replicas: replicas}); err != nil {
				return "", nil, fmt.Errorf("create %s bucket %s: %w", role, bucket.Name, err)
			}
		}
		// Bucket creation may wait while the broker installs a new account claim.
		if err := validateScope(ctx); err != nil {
			return "", nil, err
		}
		raw, chain, _, err := issuer.IssueRole(role, node, userKey, csrPEM, time.Now().UTC())
		return raw, chain, err
	}
}
