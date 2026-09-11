package keylease

import (
	"context"
	"errors"
	"sync/atomic"
	"testing"
	"time"

	"terrascale.tech/orchestrator/src/orchestrator/hostsecrets"
)

type allowGate struct{ calls atomic.Int32 }

func (g *allowGate) Check(context.Context, RenewalRequest) (time.Time, error) {
	g.calls.Add(1)
	return time.Now().Add(60 * time.Second), nil
}

type denyGate struct{ calls atomic.Int32 }

func (g *denyGate) Check(context.Context, RenewalRequest) (time.Time, error) {
	g.calls.Add(1)
	return time.Time{}, errors.New("policy denied")
}

type countingIssuer struct{ calls atomic.Int32 }

func (i *countingIssuer) Issue(context.Context, WorkloadIdentityScope) (WorkloadIdentityCredentials, error) {
	i.calls.Add(1)
	return WorkloadIdentityCredentials{AccessKey: "access", SecretKey: "secret", SessionToken: "token", ExpiresAtUnixSeconds: uint64(time.Now().Add(time.Hour).Unix())}, nil
}

func byokFixtureMetadata() *BYOKMetadata {
	return &BYOKMetadata{BackupEndpoint: "https://s3.example.test", BackupBucket: "backups", BackupRegion: "gru", BackupRoleARN: "arn:aws:iam::123456789012:role/backup", KeyProvider: "aws-kms", KeyID: "arn:aws:kms:sa-east-1:123456789012:key/12345678-1234-1234-1234-123456789012", KeyRegion: "sa-east-1", KeyEndpoint: "https://kms.example.test"}
}

// purposeCatalog writes the production shape for one provisioned BYOK
// database: data, backup, and checkpoint purpose entries sharing one
// admission operation and one BYOK metadata value.
func purposeCatalog(t *testing.T, config Config, catalog Catalog, admission string, byok *BYOKMetadata) Catalog {
	t.Helper()
	catalog.Entries = nil
	for _, purpose := range []string{"data", "backup", "checkpoint"} {
		entry := fixtureEntry()
		entry.CryptoEndpoint = "https://" + entry.CryptoEndpoint
		entry.Binding.Purpose = purpose
		entry.Provider = byok.KeyProvider
		entry.KeyID, entry.KeyRegion, entry.KeyEndpoint = byok.KeyID, byok.KeyRegion, byok.KeyEndpoint
		entry.CryptoEndpoint, entry.KEKID, entry.KEKVersionID = "", "", ""
		entry.AdmissionOperationID = admission
		entry.BYOK = byok
		catalog.Entries = append(catalog.Entries, entry)
	}
	if err := WriteCatalog(config.CatalogPath, catalog); err != nil {
		t.Fatal(err)
	}
	return catalog
}

func workloadScopeFor(entry Entry, byok *BYOKMetadata) WorkloadIdentityScope {
	return WorkloadIdentityScope{Environment: entry.Binding.Environment, TenantID: entry.Binding.TenantID, ProjectID: entry.Binding.ProjectID, DatabaseID: entry.Binding.DatabaseID, Role: byok.BackupRoleARN, Endpoint: byok.BackupEndpoint, Bucket: byok.BackupBucket, Region: byok.BackupRegion}
}

func TestStartRejectsWorkloadIdentityWithoutRenewalPolicy(t *testing.T) {
	config, _ := fixture(t)
	config.WorkloadIdentity = &countingIssuer{}
	_, err := start(t.Context(), config, func(context.Context, Entry) (*hostsecrets.DataKey, error) {
		return testDataKey(t, 1), nil
	})
	if !errors.Is(err, ErrUnavailable) {
		t.Fatalf("expected workload identity without renewal policy to be rejected, got %v", err)
	}
}

// A fully provisioned database carries three purpose entries with identical
// BYOK metadata; the workload grant is one logical grant, not an ambiguity.
func TestWorkloadIdentityThreePurposeCatalogIssuesCredentials(t *testing.T) {
	config, catalog := fixture(t)
	byok := byokFixtureMetadata()
	catalog = purposeCatalog(t, config, catalog, "01J00000000000000000000003", byok)
	gate := &allowGate{}
	issuer := &countingIssuer{}
	config.RenewalPolicy, config.WorkloadIdentity = gate, issuer
	server, err := start(t.Context(), config, func(context.Context, Entry) (*hostsecrets.DataKey, error) { return testDataKey(t, 1), nil })
	if err != nil {
		t.Fatal(err)
	}
	defer server.Close()
	body := workloadRequest(t, config.SocketPath, workloadScopeFor(catalog.Entries[0], byok))
	if len(body) == 0 || issuer.calls.Load() != 1 {
		t.Fatalf("three-purpose catalog denied workload credentials: bodyLen=%d issuer=%d", len(body), issuer.calls.Load())
	}
}

// A revoked purpose entry must deny the workload grant even when its siblings
// remain live: revocation anywhere under the scope revokes the grant.
func TestWorkloadIdentityRevokedPurposeEntryDeniesCredentials(t *testing.T) {
	config, catalog := fixture(t)
	byok := byokFixtureMetadata()
	catalog = purposeCatalog(t, config, catalog, "01J00000000000000000000003", byok)
	catalog.Entries[1].Revoked = true
	if err := WriteCatalog(config.CatalogPath, catalog); err != nil {
		t.Fatal(err)
	}
	issuer := &countingIssuer{}
	config.RenewalPolicy, config.WorkloadIdentity = &allowGate{}, issuer
	server, err := start(t.Context(), config, func(context.Context, Entry) (*hostsecrets.DataKey, error) { return testDataKey(t, 1), nil })
	if err != nil {
		t.Fatal(err)
	}
	defer server.Close()
	body := workloadRequest(t, config.SocketPath, workloadScopeFor(catalog.Entries[0], byok))
	if len(body) != 0 || issuer.calls.Load() != 0 {
		t.Fatalf("revoked purpose entry issued credentials: bodyLen=%d issuer=%d", len(body), issuer.calls.Load())
	}
}

// Purpose entries that disagree on the admission operation describe different
// grants for one scope; that ambiguity must fail closed.
func TestWorkloadIdentityConflictingAdmissionDeniesCredentials(t *testing.T) {
	config, catalog := fixture(t)
	byok := byokFixtureMetadata()
	catalog = purposeCatalog(t, config, catalog, "01J00000000000000000000003", byok)
	catalog.Entries[2].AdmissionOperationID = "01J00000000000000000000009"
	if err := WriteCatalog(config.CatalogPath, catalog); err != nil {
		t.Fatal(err)
	}
	issuer := &countingIssuer{}
	config.RenewalPolicy, config.WorkloadIdentity = &allowGate{}, issuer
	server, err := start(t.Context(), config, func(context.Context, Entry) (*hostsecrets.DataKey, error) { return testDataKey(t, 1), nil })
	if err != nil {
		t.Fatal(err)
	}
	defer server.Close()
	body := workloadRequest(t, config.SocketPath, workloadScopeFor(catalog.Entries[0], byok))
	if len(body) != 0 || issuer.calls.Load() != 0 {
		t.Fatalf("conflicting admission operations issued credentials: bodyLen=%d issuer=%d", len(body), issuer.calls.Load())
	}
}

// The revocation linearization re-reads the catalog after unwrap; entries are
// decoded independently on every read, so re-verification must compare BYOK
// metadata by value or every customer lease is denied.
func TestCustomerLeaseSucceedsWithBYOKAcrossCatalogDecodes(t *testing.T) {
	config, catalog := fixture(t)
	entry := fixtureEntry()
	entry.CryptoEndpoint = "https://" + entry.CryptoEndpoint
	entry.Provider = "aws-kms"
	entry.KeyID = "arn:aws:kms:sa-east-1:123456789012:key/12345678-1234-1234-1234-123456789012"
	entry.KeyRegion = "sa-east-1"
	entry.KeyEndpoint = "https://kms.example.test"
	entry.CryptoEndpoint, entry.KEKID, entry.KEKVersionID = "", "", ""
	entry.AdmissionOperationID = "01J00000000000000000000003"
	entry.BYOK = byokFixtureMetadata()
	catalog.Entries[0] = entry
	if err := WriteCatalog(config.CatalogPath, catalog); err != nil {
		t.Fatal(err)
	}
	config.Customer = &CustomerConfig{Provider: entry.Provider, KeyID: entry.KeyID, KeyRegion: entry.KeyRegion, KeyEndpoint: entry.KeyEndpoint, Authority: customerAuthorityFunc(func(context.Context, Binding, string) (*hostsecrets.DataKey, error) { return testDataKey(t, 9), nil })}
	config.RenewalPolicy = &allowGate{}
	server, err := start(t.Context(), config, func(context.Context, Entry) (*hostsecrets.DataKey, error) {
		t.Fatal("customer request reached OCI")
		return nil, ErrUnavailable
	})
	if err != nil {
		t.Fatal(err)
	}
	defer server.Close()
	body := requestProtocol(t, config.SocketPath, entry.Binding, "TBCK")
	if len(body) != 68 || string(body[0:4]) != "TBCK" || body[4] != 1 || body[5] != 0 {
		t.Fatalf("valid BYOK lease denied by decode-sensitive comparison: %x", body)
	}
}

func TestCatalogAcceptsAWSRegionalDefaultEndpoint(t *testing.T) {
	config, catalog := fixture(t)
	entry := catalog.Entries[0]
	entry.Provider = "aws-kms"
	entry.KeyID = "arn:aws:kms:sa-east-1:123456789012:key/12345678-1234-1234-1234-123456789012"
	entry.KeyRegion = "sa-east-1"
	entry.CryptoEndpoint, entry.KEKID, entry.KEKVersionID = "", "", ""
	entry.AdmissionOperationID = "01J00000000000000000000003"
	entry.BYOK = &BYOKMetadata{KeyProvider: entry.Provider, KeyID: entry.KeyID, KeyRegion: entry.KeyRegion}
	if err := WriteCatalog(config.CatalogPath, Catalog{Version: 1, Entries: []Entry{entry}}); err != nil {
		t.Fatalf("regional AWS endpoint default rejected: %v", err)
	}
}

// Platform (service-managed) entries carry no BYOK metadata and no dashboard
// admission; the renewal policy gate applies only to customer BYOK entries.
// A policy configured for S3 workload identity must not deny platform keys.
func TestPlatformLeaseSkipsRenewalPolicyGate(t *testing.T) {
	config, catalog := fixture(t)
	gate := &denyGate{}
	config.RenewalPolicy = gate
	server, err := start(t.Context(), config, func(context.Context, Entry) (*hostsecrets.DataKey, error) { return testDataKey(t, 4), nil })
	if err != nil {
		t.Fatal(err)
	}
	defer server.Close()
	body := requestProtocol(t, config.SocketPath, catalog.Entries[0].Binding, "TBKL")
	if len(body) != 68 || string(body[0:4]) != "TBKL" || body[4] != 1 || body[5] != 0 {
		t.Fatalf("platform lease denied by BYOK-only renewal policy: %x", body)
	}
	if gate.calls.Load() != 0 {
		t.Fatalf("renewal policy consulted for platform entry: %d", gate.calls.Load())
	}
}

// RemoteInstall retries and the activation replay redeliver byte-identical
// entries; the incoming entries are always freshly JSON-decoded, so catalog
// equality must compare BYOK metadata by value or installs never converge.
func TestMergeEntriesIdempotentBYOKRedelivery(t *testing.T) {
	config, catalog := fixture(t)
	byok := byokFixtureMetadata()
	catalog = purposeCatalog(t, config, catalog, "01J00000000000000000000003", byok)
	// Re-decode the just-written catalog: the decoded entries must merge
	// cleanly even though every BYOK pointer is a fresh allocation.
	reread, err := ReadCatalog(config.CatalogPath)
	if err != nil {
		t.Fatal(err)
	}
	if err := MergeEntries(config.CatalogPath, reread.Entries); err != nil {
		t.Fatalf("idempotent BYOK redelivery rejected: %v", err)
	}
	final, err := ReadCatalog(config.CatalogPath)
	if err != nil {
		t.Fatal(err)
	}
	if len(final.Entries) != len(catalog.Entries) {
		t.Fatalf("idempotent redelivery duplicated entries: %d != %d", len(final.Entries), len(catalog.Entries))
	}
}
