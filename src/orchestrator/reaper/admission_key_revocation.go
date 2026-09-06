package reaper

import (
	"context"
	"errors"
	"path/filepath"
	"time"

	"github.com/nats-io/nats.go"
	"terrascale.tech/orchestrator/src/orchestrator/databaseadmission"
	"terrascale.tech/orchestrator/src/orchestrator/keylease"
)

// AdmissionKeyRevoker discovers the original delivery intent from the durable
// admission journal. Targets remain included when their installed acknowledgement
// was lost. It also revokes the actual local provisioning catalog.
//
// This revokes these known copies only. It is not a KeyAdapter: encrypted key
// wrappers retained in journal history or snapshots still require independent
// irreversible destruction of their wrapping authority.
type AdmissionKeyRevoker struct {
	journal                  *databaseadmission.NATSJournal
	connection               *nats.Conn
	authority                NATSStateStoreConfig
	check                    func(context.Context) error
	environment, catalogPath string
}

type AdmissionKeyRevokerConfig struct {
	Journal                 *databaseadmission.NATSJournal
	Connection              *nats.Conn
	Authority               NATSStateStoreConfig
	CheckEffectAuthority    func(context.Context) error
	Environment             string
	ProvisioningCatalogPath string
}

type AdmissionKeyRevocation struct {
	AdmissionRevision   uint64
	Hosts               HostKeyRevocation
	ProvisioningCatalog *keylease.DatabaseTombstone
	LeasesExpireAt      time.Time
}

func NewAdmissionKeyRevoker(config AdmissionKeyRevokerConfig) (*AdmissionKeyRevoker, error) {
	if config.Journal == nil || config.CheckEffectAuthority == nil || !destructionEnvironment.MatchString(config.Environment) || !filepath.IsAbs(config.ProvisioningCatalogPath) {
		return nil, ErrKeyDestructionUnavailable
	}
	config.Authority.Connection = config.Connection
	if _, err := NewNATSStateStore(config.Authority); err != nil {
		return nil, err
	}
	if _, err := keylease.ReadCatalog(config.ProvisioningCatalogPath); err != nil {
		return nil, err
	}
	return &AdmissionKeyRevoker{config.Journal, config.Connection, config.Authority, config.CheckEffectAuthority, config.Environment, config.ProvisioningCatalogPath}, nil
}

func (r *AdmissionKeyRevoker) RevokeWrappedCopies(ctx context.Context, databaseID, operationKey string) (AdmissionKeyRevocation, error) {
	var proof AdmissionKeyRevocation
	if r == nil || ctx == nil || !destructionULID.MatchString(databaseID) {
		return proof, ErrKeyDestructionUnavailable
	}
	if err := r.check(ctx); err != nil {
		return proof, err
	}
	records, err := r.journal.List(ctx)
	if err != nil {
		return proof, err
	}
	record, err := admissionKeyRecord(records, r.environment, databaseID)
	if err != nil {
		return proof, err
	}
	proof.AdmissionRevision = record.Revision
	scope := keylease.DatabaseScope{Environment: record.Request.Environment, TenantID: record.Request.TenantID, ProjectID: record.Request.ProjectID, DatabaseID: record.DatabaseID}
	hosts := make([]string, 0, len(record.Targets))
	for _, target := range record.Targets {
		hosts = append(hosts, target.ServerIdentity)
	}
	remote, err := NewHostKeyRevoker(HostKeyRevokerConfig{Connection: r.connection, Scope: scope, HostIdentities: hosts, Authority: r.authority, CheckEffectAuthority: r.check})
	if err != nil {
		return proof, err
	}
	defer remote.Close()
	proof.Hosts, err = remote.RevokeWrappedCopies(ctx, databaseID, operationKey)
	if err != nil && !errors.Is(err, ErrKeyLeasesPending) {
		return proof, err
	}
	if err := r.check(ctx); err != nil {
		return proof, err
	}
	fence := keyDestructionRequest{Scope: scope, OperationKey: operationKey, CandidateID: r.authority.CandidateID, AuthorityEpoch: r.authority.AuthorityEpoch, LeaseID: r.authority.LeaseID}
	if err := checkKeyDestructionFence(ctx, r.connection, fence); err != nil {
		return proof, err
	}
	local, err := keylease.DestroyDatabase(ctx, r.catalogPath, scope, operationKey)
	if err != nil {
		return proof, err
	}
	proof.ProvisioningCatalog = &local
	proof.LeasesExpireAt = maxLeaseHorizon(proof.Hosts.LeasesExpireAt, local.LeasesExpireAt)
	if err := r.check(ctx); err != nil {
		return proof, err
	}
	if time.Now().Before(proof.LeasesExpireAt) {
		return proof, ErrKeyLeasesPending
	}
	return proof, nil
}

func maxLeaseHorizon(a, b time.Time) time.Time {
	if b.After(a) {
		return b
	}
	return a
}

func admissionKeyRecord(records []databaseadmission.Record, environment, databaseID string) (databaseadmission.Record, error) {
	var selected databaseadmission.Record
	for _, record := range records {
		if record.Request.Environment != environment || record.DatabaseID != databaseID {
			continue
		}
		if selected.DatabaseID != "" || databaseadmission.ValidateRecord(record) != nil {
			return databaseadmission.Record{}, ErrKeyDestructionUnavailable
		}
		selected = record
	}
	if selected.DatabaseID == "" {
		return selected, ErrKeyDestructionUnavailable
	}
	return selected, nil
}
