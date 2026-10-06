package terrabase

import (
	"bytes"
	"crypto/tls"
	"crypto/x509"
	"fmt"
	"io"
	"net"
	"net/http"
	"net/netip"
	"os"
	"os/exec"
	"path/filepath"
	"strconv"
	"strings"
	"syscall"
	"testing"
	"time"

	"git.terrascale.tech/TerraScale/ts-orchestrator/internal/testutil/tier"
)

// TestTerraBaseBinaryPeerMesh runs three members of the real release binary,
// configured only through the environment the host agent builds, with member
// certificates from the cell CA. Each peer listener accepts the other
// members, rejects a client without a certificate or with one from another
// CA, and every member drains and exits 0 on SIGTERM.
//
// TS_TERRABASE_BINARY names a terrabase-linux-<arch> release asset with its
// .sha256 asset beside it.
func TestTerraBaseBinaryPeerMesh(t *testing.T) {
	binary := releaseBinaryForTest(t)
	now := time.Now()
	caPEM, caKey, err := NewCA("lab-1", now)
	if err != nil {
		t.Fatal(err)
	}
	dir := t.TempDir()
	writeFile(t, filepath.Join(dir, "ca.pem"), caPEM)
	writeFile(t, filepath.Join(dir, "ca.key"), caKey)
	ca, err := LoadCA(filepath.Join(dir, "ca.pem"), filepath.Join(dir, "ca.key"))
	if err != nil {
		t.Fatal(err)
	}
	type member struct {
		peer    Peer
		admin   int
		layout  Layout
		command *exec.Cmd
		exited  <-chan error
		log     string
	}
	members := make([]*member, 3)
	var list []string
	for i := range members {
		peerPort, admin := freePort(t), freePort(t)
		m := &member{peer: Peer{Name: fmt.Sprintf("lab-1-db-%d", i+1), Address: netip.AddrPortFrom(netip.MustParseAddr("127.0.0.1"), uint16(peerPort))},
			admin: admin, layout: Layout(filepath.Join(dir, fmt.Sprint(i+1)))}
		for _, path := range []string{string(m.layout), m.layout.TLS(), m.layout.Data(), m.layout.Bundle()} {
			if err := os.MkdirAll(path, 0o700); err != nil {
				t.Fatal(err)
			}
		}
		key, csr, err := NewMemberKey()
		if err != nil {
			t.Fatal(err)
		}
		certificate, err := ca.Issue(csr, m.peer, now)
		if err != nil {
			t.Fatal(err)
		}
		writeFile(t, m.layout.Key(), key)
		writeFile(t, m.layout.Certificate(), certificate)
		writeFile(t, m.layout.CA(), ca.CertificatePEM())
		members[i] = m
		list = append(list, m.peer.Name+"="+m.peer.Address.String())
	}
	for _, m := range members {
		env := m.layout.Env(map[string]string{EnvAdminPort: strconv.Itoa(m.admin),
			EnvPeerPort: strconv.Itoa(int(m.peer.Address.Port())), EnvPeers: strings.Join(list, ",")},
			Profile{PeerPort: int(m.peer.Address.Port())}, m.peer.Name)
		m.command, m.exited, m.log = startMember(t, binary, env)
	}
	for _, m := range members {
		waitHealthy(t, m.admin, m.exited, m.log)
	}
	roots := x509.NewCertPool()
	roots.AppendCertsFromPEM(caPEM)
	for i, server := range members {
		client := members[(i+1)%len(members)]
		pair, err := tls.LoadX509KeyPair(client.layout.Certificate(), client.layout.Key())
		if err != nil {
			t.Fatal(err)
		}
		status, err := replicationSync(server.peer.Address, roots, []tls.Certificate{pair})
		if err != nil || status == "" {
			t.Fatalf("%s did not accept peer %s: status %q, %v\n%s", server.peer.Name, client.peer.Name, status, err, readLog(server.log))
		}
		t.Logf("%s accepted %s: grpc-status %s", server.peer.Name, client.peer.Name, status)
		if _, err := replicationSync(server.peer.Address, roots, nil); err == nil {
			t.Fatalf("%s accepted a peer without a certificate", server.peer.Name)
		}
	}
	foreignPEM, foreignKey, err := NewCA("lab-2", now)
	if err != nil {
		t.Fatal(err)
	}
	writeFile(t, filepath.Join(dir, "foreign.pem"), foreignPEM)
	writeFile(t, filepath.Join(dir, "foreign.key"), foreignKey)
	foreign, err := LoadCA(filepath.Join(dir, "foreign.pem"), filepath.Join(dir, "foreign.key"))
	if err != nil {
		t.Fatal(err)
	}
	key, csr, err := NewMemberKey()
	if err != nil {
		t.Fatal(err)
	}
	certificate, err := foreign.Issue(csr, members[1].peer, now)
	if err != nil {
		t.Fatal(err)
	}
	pair, err := tls.X509KeyPair(certificate, key)
	if err != nil {
		t.Fatal(err)
	}
	if _, err := replicationSync(members[0].peer.Address, roots, []tls.Certificate{pair}); err == nil {
		t.Fatal("a member accepted a peer certificate from another cell's CA")
	}
	for _, m := range members {
		if err := m.command.Process.Signal(syscall.SIGTERM); err != nil {
			t.Fatal(err)
		}
	}
	for _, m := range members {
		select {
		case err := <-m.exited:
			if err != nil {
				t.Fatalf("%s did not drain cleanly: %v\n%s", m.peer.Name, err, readLog(m.log))
			}
		case <-time.After(40 * time.Second):
			t.Fatalf("%s did not exit after SIGTERM", m.peer.Name)
		}
	}
}

// replicationSync opens Replication/Sync with a Hello frame over mutual TLS
// and returns the gRPC status the member answered.
func replicationSync(address netip.AddrPort, roots *x509.CertPool, certificates []tls.Certificate) (string, error) {
	transport := &http.Transport{ForceAttemptHTTP2: true,
		TLSClientConfig: &tls.Config{RootCAs: roots, Certificates: certificates, MinVersion: tls.VersionTLS12}}
	defer transport.CloseIdleConnections()
	client := &http.Client{Transport: transport, Timeout: 10 * time.Second}
	// A gRPC message frame holding SyncRequest{hello: Hello{}}.
	request, err := http.NewRequest(http.MethodPost, "https://"+address.String()+"/terrabase.v1.Replication/Sync",
		bytes.NewReader([]byte{0, 0, 0, 0, 2, 0x0a, 0x00}))
	if err != nil {
		return "", err
	}
	request.Header.Set("Content-Type", "application/grpc")
	request.Header.Set("TE", "trailers")
	response, err := client.Do(request)
	if err != nil {
		return "", err
	}
	defer response.Body.Close()
	if _, err := io.Copy(io.Discard, response.Body); err != nil {
		return "", err
	}
	if response.ProtoMajor != 2 || response.StatusCode != http.StatusOK {
		return "", fmt.Errorf("HTTP/%d %d", response.ProtoMajor, response.StatusCode)
	}
	status := response.Trailer.Get("Grpc-Status")
	if status == "" {
		status = response.Header.Get("Grpc-Status")
	}
	return status, nil
}

// releaseBinaryForTest returns an executable copy of the release binary named
// by TS_TERRABASE_BINARY after checking it against its .sha256 asset.
func releaseBinaryForTest(t testing.TB) string {
	t.Helper()
	path := tier.Qualification(t, "TS_TERRABASE_BINARY")[0]
	if _, err := VerifyRelease(path, path+".sha256"); err != nil {
		t.Fatal(err)
	}
	data, err := os.ReadFile(path)
	if err != nil {
		t.Fatal(err)
	}
	copied := filepath.Join(t.TempDir(), filepath.Base(path))
	if err := os.WriteFile(copied, data, 0o755); err != nil {
		t.Fatal(err)
	}
	return copied
}

// startMember starts a member with the host's base environment and returns
// it, a channel that receives its exit, and the path of its log.
func startMember(t testing.TB, binary string, env map[string]string) (*exec.Cmd, <-chan error, string) {
	t.Helper()
	command := exec.Command(binary)
	command.Env = []string{"HOME=/", "LANG=C", "PATH=/usr/bin:/bin"}
	for key, value := range env {
		command.Env = append(command.Env, key+"="+value)
	}
	log, err := os.CreateTemp(t.TempDir(), "member-*.log")
	if err != nil {
		t.Fatal(err)
	}
	defer log.Close()
	command.Stdout, command.Stderr = log, log
	if err := command.Start(); err != nil {
		t.Fatal(err)
	}
	exited := make(chan error, 1)
	go func() { exited <- command.Wait() }()
	t.Cleanup(func() { _ = command.Process.Kill() })
	return command, exited, log.Name()
}

// waitHealthy waits until the member answers /healthz, and fails at once
// when it exits first.
func waitHealthy(t testing.TB, adminPort int, exited <-chan error, log string) {
	t.Helper()
	deadline := time.After(60 * time.Second)
	for {
		err := Healthy(t.Context(), adminPort)
		if err == nil {
			return
		}
		select {
		case exit := <-exited:
			t.Fatalf("member on admin port %d exited before it was healthy: %v\n%s", adminPort, exit, readLog(log))
		case <-deadline:
			t.Fatalf("member on admin port %d never became healthy: %v\n%s", adminPort, err, readLog(log))
		case <-time.After(100 * time.Millisecond):
		}
	}
}

func readLog(path string) string {
	data, _ := os.ReadFile(path)
	return string(data)
}

// freePort returns a loopback TCP port that was free a moment ago.
func freePort(t testing.TB) int {
	t.Helper()
	listener, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	defer listener.Close()
	return listener.Addr().(*net.TCPAddr).Port
}

func writeFile(t testing.TB, path string, data []byte) {
	t.Helper()
	if err := os.WriteFile(path, data, 0o600); err != nil {
		t.Fatal(err)
	}
}
