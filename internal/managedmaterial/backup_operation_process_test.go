//go:build linux

package managedmaterial

import (
	"bytes"
	"context"
	"encoding/json/v2"
	"errors"
	"os"
	"path/filepath"
	"strconv"
	"strings"
	"syscall"
	"testing"
	"time"

	"github.com/TerraScale/ts-orchestrator/internal/authority"
	"github.com/TerraScale/ts-orchestrator/internal/memberstatus"
	"github.com/nats-io/nats-server/v2/server"
	"github.com/nats-io/nats.go"
	"github.com/nats-io/nats.go/jetstream"
)

type backupProcessPacket struct {
	Version               uint64                `json:"version"`
	DatabaseID            string                `json:"database_id"`
	PartitionID           string                `json:"partition_id"`
	AuthorityPKCS8Hex     string                `json:"authority_pkcs8_hex"`
	SourceScopeDigest     string                `json:"source_scope_digest"`
	SourceAuthoritySHA256 string                `json:"source_authority_sha256"`
	SourceConfigurationID string                `json:"source_configuration_id"`
	SourceTargetDigest    string                `json:"source_target_digest"`
	BackupSet             string                `json:"backup_set"`
	BackupTargetDigest    string                `json:"backup_target_digest"`
	SignerKeyID           string                `json:"signer_key_id"`
	OwnerMemberID         string                `json:"owner_member_id"`
	Roster                []backupProcessMember `json:"roster"`
}

type backupProcessMember struct {
	Origin                string                 `json:"origin"`
	MemberID              string                 `json:"member_id"`
	Incarnation           string                 `json:"incarnation"`
	TLSLeafSHA256         string                 `json:"tls_leaf_sha256"`
	Node                  string                 `json:"node"`
	Role                  string                 `json:"role"`
	SocketPath            string                 `json:"socket_path"`
	ServerCertificatePath string                 `json:"server_certificate_path"`
	PID                   int                    `json:"pid"`
	UID                   uint32                 `json:"uid"`
	GID                   uint32                 `json:"gid"`
	KernelStart           string                 `json:"kernel_start"`
	Cgroup                string                 `json:"cgroup"`
	Scope                 memberstatus.Scope     `json:"scope"`
	Authority             memberstatus.Authority `json:"authority"`
}

func assertBackupProcessReadback(t *testing.T, ctx context.Context, runtime *authority.Runtime,
	record authority.BackupOperationRecord, sequence uint64,
) {
	t.Helper()
	read, observed, err := runtime.ReadBackupOperation(ctx, record.DatabaseID, record.PartitionID)
	want, wantErr := json.Marshal(record)
	actual, actualErr := json.Marshal(read)
	if err != nil || wantErr != nil || actualErr != nil || observed != sequence ||
		!bytes.Equal(want, actual) {
		t.Fatalf("R3 exact operation readback failed: sequence=%d/%d error=%v", observed, sequence, err)
	}
}

func backupProcessClient(t *testing.T, member backupProcessMember) *memberstatus.Client {
	t.Helper()
	observe := func(ctx context.Context) (memberstatus.ProcessObservation, error) {
		if err := ctx.Err(); err != nil {
			return memberstatus.ProcessObservation{}, err
		}
		path := filepath.Join("/proc", strconv.Itoa(member.PID))
		info, err := os.Stat(path)
		if err != nil {
			return memberstatus.ProcessObservation{}, err
		}
		stat, ok := info.Sys().(*syscall.Stat_t)
		if !ok || stat.Uid != member.UID || stat.Gid != member.GID {
			return memberstatus.ProcessObservation{}, errors.New("Rust member process owner changed")
		}
		statBytes, err := os.ReadFile(filepath.Join(path, "stat"))
		if err != nil {
			return memberstatus.ProcessObservation{}, err
		}
		closeName := bytes.LastIndexByte(statBytes, ')')
		if closeName < 0 {
			return memberstatus.ProcessObservation{}, errors.New("Rust member process stat is invalid")
		}
		fields := strings.Fields(string(statBytes[closeName+1:]))
		if len(fields) <= 19 || fields[19] != member.KernelStart {
			return memberstatus.ProcessObservation{}, errors.New("Rust member process start changed")
		}
		cgroup, err := os.ReadFile(filepath.Join(path, "cgroup"))
		if err != nil || strings.TrimSpace(string(cgroup)) != member.Cgroup {
			return memberstatus.ProcessObservation{}, errors.New("Rust member process cgroup changed")
		}
		return memberstatus.ProcessObservation{PID: member.PID, UID: member.UID,
			GID: member.GID, KernelStart: member.KernelStart, Cgroup: member.Cgroup}, nil
	}
	client, err := memberstatus.NewClient(member.SocketPath, member.Scope, member.Authority, observe)
	if err != nil {
		t.Fatal(err)
	}
	status, err := client.Status(t.Context())
	if err != nil || status.Process.PID != member.PID || status.Scope != member.Scope ||
		status.Authority != member.Authority {
		t.Fatal("Rust member status differs from process packet:", err)
	}
	return client
}

func backupProcessJetStream(t *testing.T) jetstream.JetStream {
	t.Helper()
	srv, err := server.NewServer(&server.Options{Host: "127.0.0.1", Port: -1,
		JetStream: true, StoreDir: filepath.Join(t.TempDir(), "jetstream")})
	if err != nil {
		t.Fatal(err)
	}
	go srv.Start()
	if !srv.ReadyForConnections(5 * time.Second) {
		t.Fatal("NATS did not start")
	}
	t.Cleanup(func() { srv.Shutdown(); srv.WaitForShutdown() })
	conn, err := nats.Connect(srv.ClientURL())
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(conn.Close)
	js, err := jetstream.New(conn)
	if err != nil {
		t.Fatal(err)
	}
	return js
}
