//go:build linux

package host

import (
	"context"
	"io"
	"net"
	"net/http"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"
)

const memberStatusFixture = `{"schema_version":1,"nonce":"00000000000000000000000000000001","process":{"pid":123,"start_nonce":"00000000000000000000000000000002"},"scope":{"cluster_id":"00000000000000000000000000000003","tenant_id":"01ARZ3NDEKTSV4RRFFQ69G5FAV","database_id":"01ARZ3NDEKTSV4RRFFQ69G5FAW","shard_id":0,"member_id":"01ARZ3NDEKTSV4RRFFQ69G5FAX","incarnation":"00000000000000000000000000000004"},"authority":{"epoch":1,"configuration_id":"aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa","certificate_sha256":"bbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbb","tls_leaf_sha256":"cccccccccccccccccccccccccccccccccccccccccccccccccccccccccccccccc"},"local":{"storage_recovered":true,"replication_listener_ready":true,"healthy":true,"ready":false},"receiver_only":true,"serving":false,"capabilities":{"serving_proof":false,"durable_drain":false}}`

func memberFixtureExpectation() ExpectedMemberStatus {
	return ExpectedMemberStatus{
		Scope: MemberScope{
			ClusterID: "00000000000000000000000000000003", TenantID: "01ARZ3NDEKTSV4RRFFQ69G5FAV",
			DatabaseID: "01ARZ3NDEKTSV4RRFFQ69G5FAW", ShardID: 0,
			MemberID: "01ARZ3NDEKTSV4RRFFQ69G5FAX", Incarnation: "00000000000000000000000000000004",
		},
		Authority: MemberAuthority{
			Epoch: 1, ConfigurationID: strings.Repeat("a", 64),
			CertificateSHA256: strings.Repeat("b", 64), TLSLeafSHA256: strings.Repeat("c", 64),
		},
	}
}

func TestDecodeMemberStatusStrictReceiverContract(t *testing.T) {
	nonce := "00000000000000000000000000000001"
	expected := memberFixtureExpectation()
	status, err := decodeMemberStatus([]byte(memberStatusFixture), nonce, 123, expected)
	if err != nil {
		t.Fatal(err)
	}
	if !status.ReceiverOnly || status.Serving || status.Capabilities.ServingProof || status.Capabilities.DurableDrain ||
		!status.Local.StorageRecovered || !status.Local.ReplicationListenerReady || !status.Local.Healthy || status.Local.Ready {
		t.Fatalf("receiver status changed meaning: %+v", status)
	}

	for _, test := range []struct {
		name string
		body string
		want string
	}{
		{"unknown field", strings.Replace(memberStatusFixture, `"receiver_only":true`, `"new_field":0,"receiver_only":true`, 1), "invalid member status JSON"},
		{"duplicate field", strings.Replace(memberStatusFixture, `"nonce":"00000000000000000000000000000001"`, `"nonce":"00000000000000000000000000000001","nonce":"00000000000000000000000000000001"`, 1), "invalid member status JSON"},
		{"missing false field", strings.Replace(memberStatusFixture, `"serving_proof":false,`, "", 1), "omits required fields"},
		{"null field", strings.Replace(memberStatusFixture, `"serving_proof":false`, `"serving_proof":null`, 1), "omits required fields"},
		{"nonce mismatch", strings.Replace(memberStatusFixture, nonce, "00000000000000000000000000000009", 1), "identity or capability mismatch"},
		{"PID mismatch", strings.Replace(memberStatusFixture, `"pid":123`, `"pid":124`, 1), "identity or capability mismatch"},
		{"authority mismatch", strings.Replace(memberStatusFixture, strings.Repeat("b", 64), strings.Repeat("d", 64), 1), "identity or capability mismatch"},
		{"false serving claim", strings.Replace(memberStatusFixture, `"serving":false`, `"serving":true`, 1), "identity or capability mismatch"},
		{"trailing data", memberStatusFixture + ` {}`, "invalid member status JSON"},
	} {
		t.Run(test.name, func(t *testing.T) {
			_, err := decodeMemberStatus([]byte(test.body), nonce, 123, expected)
			if err == nil || !strings.Contains(err.Error(), test.want) {
				t.Fatalf("decode error = %v, want %q", err, test.want)
			}
		})
	}
}

func TestDecodeMemberStatusSenderRoleDoesNotClaimServing(t *testing.T) {
	nonce := "00000000000000000000000000000001"
	expected := memberFixtureExpectation()
	senderStatus := strings.Replace(memberStatusFixture, `"receiver_only":true`, `"receiver_only":false`, 1)
	status, err := decodeMemberStatus([]byte(senderStatus), nonce, 123, expected)
	if err != nil {
		t.Fatal(err)
	}
	if status.ReceiverOnly || status.Serving || status.Capabilities.ServingProof || status.Capabilities.DurableDrain {
		t.Fatalf("sender role changed capability meaning: %+v", status)
	}

	for _, test := range []struct {
		name string
		body string
	}{
		{"serving", strings.Replace(senderStatus, `"serving":false`, `"serving":true`, 1)},
		{"serving proof", strings.Replace(senderStatus, `"serving_proof":false`, `"serving_proof":true`, 1)},
		{"durable drain", strings.Replace(senderStatus, `"durable_drain":false`, `"durable_drain":true`, 1)},
	} {
		t.Run(test.name, func(t *testing.T) {
			if _, err := decodeMemberStatus([]byte(test.body), nonce, 123, expected); err == nil ||
				!strings.Contains(err.Error(), "identity or capability mismatch") {
				t.Fatalf("unexpected capability accepted: %v", err)
			}
		})
	}
}

func TestMemberSocketRequiresPrivateOwnership(t *testing.T) {
	path := filepath.Join(t.TempDir(), "member.sock")
	listener, err := net.Listen("unix", path)
	if err != nil {
		t.Fatal(err)
	}
	defer listener.Close()
	if _, err := inspectMemberSocket(path, WorkloadIdentity{UID: uint32(os.Geteuid()), GID: uint32(os.Getegid())}); err == nil {
		t.Fatal("ordinary test directory and socket passed the management ownership check")
	}
	if err := os.Remove(path); err != nil {
		t.Fatal(err)
	}
	if err := os.Symlink("/dev/null", path); err != nil {
		t.Fatal(err)
	}
	if _, err := inspectMemberSocket(path, WorkloadIdentity{UID: uint32(os.Geteuid()), GID: uint32(os.Getegid())}); err == nil {
		t.Fatal("symlink passed the management socket check")
	}
}

func TestMemberPeerCredentialsUseUnixKernelIdentity(t *testing.T) {
	path := filepath.Join(t.TempDir(), "peer.sock")
	listener, err := net.Listen("unix", path)
	if err != nil {
		t.Fatal(err)
	}
	defer listener.Close()
	client, err := (&net.Dialer{}).DialContext(t.Context(), "unix", path)
	if err != nil {
		t.Fatal(err)
	}
	defer client.Close()
	credentials, err := memberPeerCredentials(client)
	if err != nil {
		t.Fatal(err)
	}
	if credentials.Pid != int32(os.Getpid()) || credentials.Uid != uint32(os.Geteuid()) || credentials.Gid != uint32(os.Getegid()) {
		t.Fatalf("wrong kernel peer credentials: %+v", credentials)
	}
}

func TestMemberStatusTransportRejectsOversizedResponseHeaders(t *testing.T) {
	path := filepath.Join(t.TempDir(), "large-header.sock")
	listener, err := net.Listen("unix", path)
	if err != nil {
		t.Fatal(err)
	}
	defer listener.Close()
	served := make(chan struct{})
	go func() {
		defer close(served)
		conn, err := listener.Accept()
		if err != nil {
			return
		}
		defer conn.Close()
		_ = conn.SetDeadline(time.Now().Add(2 * time.Second))
		buffer := make([]byte, 1024)
		_, _ = conn.Read(buffer)
		_, _ = io.WriteString(conn, "HTTP/1.1 200 OK\r\nX-Large: "+strings.Repeat("x", 5000)+"\r\nContent-Type: application/json\r\nContent-Length: 2\r\n\r\n{}")
	}()
	ctx, cancel := context.WithTimeout(t.Context(), 2*time.Second)
	defer cancel()
	request, err := http.NewRequestWithContext(ctx, http.MethodGet, "http://unix/v1/member/status", nil)
	if err != nil {
		t.Fatal(err)
	}
	transport := newMemberStatusTransport(func(ctx context.Context, _, _ string) (net.Conn, error) {
		return (&net.Dialer{}).DialContext(ctx, "unix", path)
	})
	defer transport.CloseIdleConnections()
	response, err := (&http.Client{Transport: transport}).Do(request)
	if response != nil {
		_ = response.Body.Close()
	}
	if err == nil || !strings.Contains(err.Error(), "response headers exceeded") {
		t.Fatalf("oversized response header error = %v", err)
	}
	<-served
}

type unsupportedMemberRunner struct{}

func (unsupportedMemberRunner) Recover(context.Context) error         { return nil }
func (unsupportedMemberRunner) Apply(context.Context, Workload) error { return nil }
func (unsupportedMemberRunner) Stop(context.Context, string) error    { return nil }
func (unsupportedMemberRunner) Observe(context.Context, string) (Observation, error) {
	return Observation{}, nil
}
func (unsupportedMemberRunner) Close(context.Context) error { return nil }

func TestMemberStatusRejectsUnboundRunner(t *testing.T) {
	_, err := ReadMemberStatus(t.Context(), unsupportedMemberRunner{}, memberFixtureExpectation())
	if err == nil || !strings.Contains(err.Error(), "native process runner") {
		t.Fatalf("unbound runner error = %v", err)
	}
}
