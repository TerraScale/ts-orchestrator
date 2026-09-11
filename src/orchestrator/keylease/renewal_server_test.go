package keylease

import (
	"bytes"
	"context"
	"encoding/binary"
	"encoding/json/v2"
	"errors"
	"io"
	"net"
	"os"
	"sync/atomic"
	"testing"
	"time"

	"terrascale.tech/orchestrator/src/orchestrator/hostsecrets"
)

type renewalGate struct{ calls atomic.Int32 }

func (g *renewalGate) Check(context.Context, RenewalRequest) (time.Time, error) {
	if g.calls.Add(1) > 1 {
		return time.Time{}, errors.New("policy revoked during unwrap")
	}
	return time.Now().Add(20 * time.Second), nil
}

func TestCustomerLeasePostcheckBlocksKeyAfterPolicyRevocation(t *testing.T) {
	config, catalog := fixture(t)
	entry := catalog.Entries[0]
	entry.Provider = "aws-kms"
	entry.KeyID = "arn:aws:kms:sa-east-1:123456789012:key/12345678-1234-1234-1234-123456789012"
	entry.KeyRegion = "sa-east-1"
	entry.KeyEndpoint = "https://kms.example.test"
	entry.CryptoEndpoint, entry.KEKID, entry.KEKVersionID = "", "", ""
	entry.AdmissionOperationID = "01J00000000000000000000003"
	entry.BYOK = &BYOKMetadata{KeyProvider: entry.Provider, KeyID: entry.KeyID, KeyRegion: entry.KeyRegion, KeyEndpoint: entry.KeyEndpoint}
	catalog.Entries[0] = entry
	if err := WriteCatalog(config.CatalogPath, catalog); err != nil {
		t.Fatal(err)
	}
	config.Customer = &CustomerConfig{Provider: entry.Provider, KeyID: entry.KeyID, KeyRegion: entry.KeyRegion, KeyEndpoint: entry.KeyEndpoint, Authority: customerAuthorityFunc(func(context.Context, Binding, string) (*hostsecrets.DataKey, error) { return testDataKey(t, 9), nil })}
	config.RenewalPolicy = &renewalGate{}
	server, err := start(t.Context(), config, func(context.Context, Entry) (*hostsecrets.DataKey, error) {
		t.Fatal("customer request reached OCI")
		return nil, ErrUnavailable
	})
	if err != nil {
		t.Fatal(err)
	}
	defer server.Close()
	body := requestProtocol(t, config.SocketPath, entry.Binding, "TBCK")
	if !bytes.Equal(body, []byte{'T', 'B', 'C', 'K', 1, 1}) {
		t.Fatalf("revoked postcheck returned key: %x", body)
	}
}

type renewalIssuer struct{ calls atomic.Int32 }

func (i *renewalIssuer) Issue(context.Context, WorkloadIdentityScope) (WorkloadIdentityCredentials, error) {
	i.calls.Add(1)
	return WorkloadIdentityCredentials{AccessKey: "access", SecretKey: "secret", SessionToken: "token", ExpiresAtUnixSeconds: uint64(time.Now().Add(time.Hour).Unix())}, nil
}

func TestWorkloadIdentityPostcheckBlocksCredentialsAfterPolicyRevocation(t *testing.T) {
	config, catalog := fixture(t)
	entry := catalog.Entries[0]
	entry.AdmissionOperationID = "01J00000000000000000000003"
	entry.Provider = "aws-kms"
	entry.KeyID = "arn:aws:kms:sa-east-1:123456789012:key/12345678-1234-1234-1234-123456789012"
	entry.KeyRegion = "sa-east-1"
	entry.KeyEndpoint = "https://kms.example.test"
	entry.CryptoEndpoint, entry.KEKID, entry.KEKVersionID = "", "", ""
	entry.BYOK = &BYOKMetadata{BackupEndpoint: "https://s3.example.test", BackupBucket: "backups", BackupRegion: "gru", BackupRoleARN: "arn:aws:iam::123456789012:role/backup", KeyProvider: entry.Provider, KeyID: entry.KeyID, KeyRegion: entry.KeyRegion, KeyEndpoint: entry.KeyEndpoint}
	catalog.Entries[0] = entry
	if err := WriteCatalog(config.CatalogPath, catalog); err != nil {
		t.Fatal(err)
	}
	gate := &renewalGate{}
	issuer := &renewalIssuer{}
	config.RenewalPolicy, config.WorkloadIdentity = gate, issuer
	server, err := start(t.Context(), config, func(context.Context, Entry) (*hostsecrets.DataKey, error) { return testDataKey(t, 1), nil })
	if err != nil {
		t.Fatal(err)
	}
	defer server.Close()
	body := workloadRequest(t, config.SocketPath, WorkloadIdentityScope{Environment: entry.Binding.Environment, TenantID: entry.Binding.TenantID, ProjectID: entry.Binding.ProjectID, DatabaseID: entry.Binding.DatabaseID, Role: entry.BYOK.BackupRoleARN, Endpoint: entry.BYOK.BackupEndpoint, Bucket: entry.BYOK.BackupBucket, Region: entry.BYOK.BackupRegion})
	if len(body) != 0 || issuer.calls.Load() != 1 {
		t.Fatalf("revoked workload credentials escaped postcheck: body=%x calls=%d", body, issuer.calls.Load())
	}
}

func workloadRequest(t *testing.T, path string, scope WorkloadIdentityScope) []byte {
	t.Helper()
	connection, err := net.Dial("unix", path)
	if err != nil {
		t.Fatal(err)
	}
	defer connection.Close()
	_ = connection.SetDeadline(time.Now().Add(3 * time.Second))
	body, err := json.Marshal(struct {
		Version uint8                 `json:"version"`
		Scope   WorkloadIdentityScope `json:"scope"`
	}{1, scope})
	if err != nil {
		t.Fatal(err)
	}
	if _, err := connection.Write(append(binary.BigEndian.AppendUint32(nil, uint32(len(body))), body...)); err != nil {
		t.Fatal(err)
	}
	var prefix [4]byte
	if _, err := io.ReadFull(connection, prefix[:]); errors.Is(err, io.EOF) {
		return nil
	} else if err != nil {
		t.Fatal(err)
	}
	response := make([]byte, binary.BigEndian.Uint32(prefix[:]))
	if _, err := io.ReadFull(connection, response); err != nil && !errors.Is(err, os.ErrClosed) {
		t.Fatal(err)
	}
	return response
}
