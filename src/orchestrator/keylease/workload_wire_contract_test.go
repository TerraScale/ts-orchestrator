//go:build linux

package keylease

import (
	"bytes"
	"context"
	"encoding/binary"
	"encoding/hex"
	"encoding/json/v2"
	"errors"
	"io"
	"net"
	"os"
	"path/filepath"
	"sync/atomic"
	"testing"
	"time"

	"terrascale.tech/orchestrator/src/orchestrator/hostsecrets"
)

type wireContractIssuer struct{ calls atomic.Int32 }

func (i *wireContractIssuer) Issue(context.Context, WorkloadIdentityScope) (WorkloadIdentityCredentials, error) {
	i.calls.Add(1)
	return WorkloadIdentityCredentials{AccessKey: "access", SecretKey: "secret", SessionToken: "token", ExpiresAtUnixSeconds: uint64(time.Now().Add(time.Hour).Unix())}, nil
}

func TestRustWorkloadIdentityFrameMatchesProductionCatalog(t *testing.T) {
	config, catalog := fixture(t)
	byok := byokFixtureMetadata()
	catalog = purposeCatalog(t, config, catalog, "01J00000000000000000000003", byok)
	issuer := &wireContractIssuer{}
	config.RenewalPolicy, config.WorkloadIdentity = &allowGate{}, issuer
	server, err := start(t.Context(), config, func(context.Context, Entry) (*hostsecrets.DataKey, error) { return testDataKey(t, 1), nil })
	if err != nil {
		t.Fatal(err)
	}
	defer server.Close()

	frame := rustWorkloadFrame(t)
	response := sendWorkloadFrame(t, config.SocketPath, frame)
	if len(response) == 0 || issuer.calls.Load() != 1 {
		t.Fatalf("Rust-generated frame was not issued: response=%x issuer=%d", response, issuer.calls.Load())
	}
	var credentials WorkloadIdentityCredentials
	if err := json.Unmarshal(response, &credentials); err != nil || credentials.AccessKey != "access" || credentials.SecretKey != "secret" || credentials.SessionToken != "token" || credentials.ExpiresAtUnixSeconds <= uint64(time.Now().Unix()) {
		t.Fatalf("invalid broker response: %s (%v)", response, err)
	}

	for _, name := range []string{"missing tenant identity", "mismatched database identity"} {
		candidate := bytes.Clone(frame)
		if name[0] == 'm' && name[8] == 't' {
			candidate = bytes.Replace(candidate, []byte(`"tenant_id":"01ARZ3NDEKTSV4RRFFQ69G5FAV",`), nil, 1)
		} else {
			candidate = bytes.Replace(candidate, []byte(`01ARZ3NDEKTSV4RRFFQ69G5FAX`), []byte(`01ARZ3NDEKTSV4RRFFQ69G5FAY`), 1)
		}
		if response := sendWorkloadFrame(t, config.SocketPath, candidate); len(response) != 0 {
			t.Errorf("%s unexpectedly received credentials: %x", name, response)
		}
	}
	if issuer.calls.Load() != 1 {
		t.Fatalf("invalid identity reached issuer: calls=%d", issuer.calls.Load())
	}
}

func rustWorkloadFrame(t *testing.T) []byte {
	t.Helper()
	data, err := os.ReadFile(filepath.Join("testdata", "rust_workload_identity_frame.hex"))
	if err != nil {
		t.Fatal(err)
	}
	frame, err := hex.DecodeString(string(bytes.TrimSpace(data)))
	if err != nil {
		t.Fatal(err)
	}
	return frame
}

func sendWorkloadFrame(t *testing.T, path string, frame []byte) []byte {
	t.Helper()
	connection, err := net.Dial("unix", path)
	if err != nil {
		t.Fatal(err)
	}
	defer connection.Close()
	_ = connection.SetDeadline(time.Now().Add(3 * time.Second))
	if _, err := connection.Write(frame); err != nil {
		t.Fatal(err)
	}
	var prefix [4]byte
	if _, err := io.ReadFull(connection, prefix[:]); errors.Is(err, os.ErrClosed) || errors.Is(err, context.Canceled) {
		return nil
	} else if err != nil {
		return nil
	}
	response := make([]byte, binary.BigEndian.Uint32(prefix[:]))
	if _, err := io.ReadFull(connection, response); err != nil {
		return nil
	}
	return response
}
