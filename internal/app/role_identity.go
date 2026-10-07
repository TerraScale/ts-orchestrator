package app

import (
	"context"
	"errors"
	"fmt"
	"os"
	"time"

	"git.terrascale.tech/TerraScale/ts-orchestrator/internal/host"
	"git.terrascale.tech/TerraScale/ts-orchestrator/internal/hostenroll"
	"git.terrascale.tech/TerraScale/ts-orchestrator/internal/natscell"
	"git.terrascale.tech/TerraScale/ts-orchestrator/internal/roleidentity"
	"github.com/nats-io/nats.go/jetstream"
)

// loadHostIssuer loads the controller's host NATS and TLS issuer.
func loadHostIssuer(cfg Config, runtime *natscell.Runtime) (*hostenroll.Issuer, error) {
	rootPEM, err := os.ReadFile(cfg.NATS.Embedded.TLS.CAFile)
	if err != nil || len(rootPEM) == 0 || len(rootPEM) > 8192 {
		return nil, errors.New("regional host enrollment CA is unavailable")
	}
	return hostenroll.LoadIssuer(cfg.NATS.Cell, runtime.CellAccount(),
		cfg.Controller.HostNATSIssuerSeedFile, cfg.Controller.HostTLSIssuerKeyFile,
		cfg.Controller.HostTLSIssuerCertFile, rootPEM)
}

// roleIdentityIssuer issues a granted role's NATS identity (TS-651) once the
// broker's current cell account carries the role signer, after it creates
// the role's buckets: a role may read and write them but not create them.
func roleIdentityIssuer(issuer *hostenroll.Issuer, runtime *natscell.Runtime, replicas int) host.RoleIdentityIssuer {
	return func(ctx context.Context, role, node, userKey, csrPEM string) (string, []byte, error) {
		// InitialCellJWT reads the resolver, which holds the applied claim.
		if err := issuer.ValidateRoleScope(runtime.InitialCellJWT()); err != nil {
			return "", nil, err
		}
		for _, bucket := range roleidentity.Grants[role].Buckets {
			storage := jetstream.FileStorage
			if bucket.Memory {
				storage = jetstream.MemoryStorage
			}
			if _, err := runtime.JetStream().CreateOrUpdateKeyValue(ctx, jetstream.KeyValueConfig{Bucket: bucket.Name,
				TTL: bucket.TTL, History: bucket.History, Storage: storage, Replicas: replicas}); err != nil {
				return "", nil, fmt.Errorf("create %s bucket %s: %w", role, bucket.Name, err)
			}
		}
		raw, chain, _, err := issuer.IssueRole(role, node, userKey, csrPEM, time.Now().UTC())
		return raw, chain, err
	}
}
