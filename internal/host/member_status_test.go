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

const memberStatusFixture = `{"schema_version":2,"nonce":"00000000000000000000000000000001","process":{"pid":123,"start_nonce":"00000000000000000000000000000002"},"scope":{"cluster_id":"00000000000000000000000000000003","tenant_id":"01HW000000E008000000000001","database_id":"01HW000000E008000000000002","shard_id":1,"member_id":"01HW000000E008000000000003","incarnation":"00000000000000000000000000000004"},"authority":{"epoch":1,"configuration_id":"aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa","certificate_sha256":"bbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbb","tls_leaf_sha256":"cccccccccccccccccccccccccccccccccccccccccccccccccccccccccccccccc"},"local":{"storage_recovered":true,"replication_listener_ready":true,"healthy":true,"ready":false},"receiver_only":false,"serving":false,"capabilities":{"serving_proof":true,"durable_drain":true}}`

func memberFixtureExpectation() ExpectedMemberStatus {
	return ExpectedMemberStatus{
		Scope: MemberScope{
			ClusterID: "00000000000000000000000000000003", TenantID: "01HW000000E008000000000001",
			DatabaseID: "01HW000000E008000000000002", ShardID: 1,
			MemberID: "01HW000000E008000000000003", Incarnation: "00000000000000000000000000000004",
		},
		Authority: MemberAuthority{
			Epoch: 1, ConfigurationID: strings.Repeat("a", 64),
			CertificateSHA256: strings.Repeat("b", 64), TLSLeafSHA256: strings.Repeat("c", 64),
		},
	}
}

func TestDecodeMemberStatusStrictServingContract(t *testing.T) {
	nonce := "00000000000000000000000000000001"
	expected := memberFixtureExpectation()
	status, err := decodeMemberStatus([]byte(memberStatusFixture), nonce, 123, expected)
	if err != nil {
		t.Fatal(err)
	}
	if status.ReceiverOnly || status.Serving || !status.Capabilities.ServingProof || !status.Capabilities.DurableDrain ||
		!status.Local.StorageRecovered || !status.Local.ReplicationListenerReady || !status.Local.Healthy || status.Local.Ready {
		t.Fatalf("receiver status changed meaning: %+v", status)
	}

	for _, test := range []struct {
		name string
		body string
		want string
	}{
		{"unknown field", strings.Replace(memberStatusFixture, `"receiver_only":false`, `"new_field":0,"receiver_only":false`, 1), "invalid member status JSON"},
		{"duplicate field", strings.Replace(memberStatusFixture, `"nonce":"00000000000000000000000000000001"`, `"nonce":"00000000000000000000000000000001","nonce":"00000000000000000000000000000001"`, 1), "invalid member status JSON"},
		{"missing field", strings.Replace(memberStatusFixture, `"serving_proof":true,`, "", 1), "omits required fields"},
		{"null field", strings.Replace(memberStatusFixture, `"serving_proof":true`, `"serving_proof":null`, 1), "omits required fields"},
		{"nonce mismatch", strings.Replace(memberStatusFixture, nonce, "00000000000000000000000000000009", 1), "identity or capability mismatch"},
		{"PID mismatch", strings.Replace(memberStatusFixture, `"pid":123`, `"pid":124`, 1), "identity or capability mismatch"},
		{"authority mismatch", strings.Replace(memberStatusFixture, strings.Repeat("b", 64), strings.Repeat("d", 64), 1), "identity or capability mismatch"},
		{"serving without readiness", strings.Replace(memberStatusFixture, `"serving":false`, `"serving":true`, 1), "identity or capability mismatch"},
		{"missing serving proof", strings.Replace(memberStatusFixture, `"serving_proof":true`, `"serving_proof":false`, 1), "identity or capability mismatch"},
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

func TestDecodeMemberStatusServingRequiresLiveReadiness(t *testing.T) {
	nonce := "00000000000000000000000000000001"
	expected := memberFixtureExpectation()
	senderStatus := strings.Replace(memberStatusFixture, `"ready":false`, `"ready":true`, 1)
	senderStatus = strings.Replace(senderStatus, `"serving":false`, `"serving":true`, 1)
	status, err := decodeMemberStatus([]byte(senderStatus), nonce, 123, expected)
	if err != nil {
		t.Fatal(err)
	}
	if status.ReceiverOnly || !status.Serving || !status.Capabilities.ServingProof || !status.Capabilities.DurableDrain {
		t.Fatalf("serving proof was rejected: %+v", status)
	}

	for _, test := range []struct {
		name string
		body string
	}{
		{"receiver-only", strings.Replace(senderStatus, `"receiver_only":false`, `"receiver_only":true`, 1)},
		{"serving proof", strings.Replace(senderStatus, `"serving_proof":true`, `"serving_proof":false`, 1)},
		{"durable drain", strings.Replace(senderStatus, `"durable_drain":true`, `"durable_drain":false`, 1)},
	} {
		t.Run(test.name, func(t *testing.T) {
			if _, err := decodeMemberStatus([]byte(test.body), nonce, 123, expected); err == nil ||
				!strings.Contains(err.Error(), "identity or capability mismatch") {
				t.Fatalf("unexpected capability accepted: %v", err)
			}
		})
	}
}

func TestMemberStatusRequiresCanonicalULID(t *testing.T) {
	if !canonicalMemberID("01HW000000E008000000000001") {
		t.Fatal("native canonical UUID was rejected")
	}
	for _, value := range []string{
		"acct_0000000000Y3F2HK4F04NBVBD6",
		"018F0000-0000-7000-8000-000000000001",
		"018f0000000070008000000000000001",
		"00000000000000000000000000",
	} {
		if canonicalMemberID(value) {
			t.Fatalf("noncanonical or historical identity accepted: %q", value)
		}
	}
	expected := memberFixtureExpectation()
	expected.Scope.MemberID = "018f0000-0000-7000-8000-000000000003"
	legacyBody := strings.Replace(memberStatusFixture, "01HW000000E008000000000003", expected.Scope.MemberID, 1)
	if _, err := decodeMemberStatus([]byte(legacyBody), "00000000000000000000000000000001", 123, expected); err == nil {
		t.Fatal("UUID member status was accepted even with matching expectation")
	}
	zeroShard := strings.Replace(memberStatusFixture, `"shard_id":1`, `"shard_id":0`, 1)
	expected = memberFixtureExpectation()
	expected.Scope.ShardID = 0
	if _, err := decodeMemberStatus([]byte(zeroShard), "00000000000000000000000000000001", 123, expected); err == nil {
		t.Fatal("zero-shard member status was accepted")
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

func TestDecodeMemberStatusOptionalLoadBlock(t *testing.T) {
	nonce := "00000000000000000000000000000001"
	expected := memberFixtureExpectation()
	withLoad := func(load string) string {
		return strings.Replace(memberStatusFixture, `"receiver_only":false`, `"load":`+load+`,"receiver_only":false`, 1)
	}
	status, err := decodeMemberStatus([]byte(withLoad(`{"connections":12,"storage_bytes":4096,"replication_lag_seq":3,"write_qps":1.5}`)), nonce, 123, expected)
	if err != nil {
		t.Fatal(err)
	}
	if status.Load == nil || status.Load.Connections != 12 || status.Load.StorageBytes != 4096 ||
		status.Load.ReplicationLagSeq != 3 || status.Load.WriteQPS != 1.5 {
		t.Fatalf("load block not decoded: %+v", status.Load)
	}
	// Telemetry problems never fail the status itself: the block is dropped.
	for name, load := range map[string]string{
		"incomplete": `{"connections":12}`,
		"negative":   `{"connections":1,"storage_bytes":1,"replication_lag_seq":1,"write_qps":-1}`,
		"oversized":  `{"connections":99999999999,"storage_bytes":1,"replication_lag_seq":1,"write_qps":1}`,
		// Values the typed decoder itself would refuse must not fail the
		// status either.
		"negative counter": `{"connections":-1,"storage_bytes":1,"replication_lag_seq":1,"write_qps":1}`,
		"overflowing qps":  `{"connections":1,"storage_bytes":1,"replication_lag_seq":1,"write_qps":1e400}`,
		"string counter":   `{"connections":"1","storage_bytes":1,"replication_lag_seq":1,"write_qps":1}`,
		"not an object":    `[1,2]`,
		"null":             `null`,
		"repeated counter": `{"connections":1,"connections":2,"storage_bytes":1,"replication_lag_seq":1,"write_qps":1}`,
		// A newer TerraBase that adds a counter only loses its telemetry.
		"unknown member": `{"connections":1,"storage_bytes":1,"replication_lag_seq":1,"write_qps":1,"extra":1}`,
	} {
		status, err := decodeMemberStatus([]byte(withLoad(load)), nonce, 123, expected)
		if err != nil || status.Load != nil {
			t.Errorf("%s load: status=%+v err=%v, want accepted status without load", name, status.Load, err)
		}
	}
	// The evidence around the block stays strict.
	if _, err := decodeMemberStatus([]byte(strings.Replace(withLoad(`{"connections":1,"storage_bytes":1,"replication_lag_seq":1,"write_qps":1}`),
		`"receiver_only":false`, `"receiver_only":false,"extra":1`, 1)), nonce, 123, expected); err == nil {
		t.Error("unknown status member accepted next to a load block")
	}
}
