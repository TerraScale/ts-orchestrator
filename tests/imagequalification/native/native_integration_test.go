package native

import (
	"bufio"
	"context"
	"crypto/ed25519"
	"crypto/rand"
	"crypto/x509"
	"encoding/json"
	"encoding/pem"
	"errors"
	"io"
	"net"
	"net/http"
	"net/http/httptest"
	"os"
	"os/exec"
	"path/filepath"
	"strings"
	"sync/atomic"
	"testing"
	"time"

	"golang.org/x/crypto/ssh"
)

// These cross local filesystem/process/HTTP/SSH boundaries. Their result is
// source integration evidence only; no fixture result establishes native HA.
func TestPrivateKeyFilesystemAndSSHAuthentication(t *testing.T) {
	_, private, err := ed25519.GenerateKey(rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	wire, err := x509.MarshalPKCS8PrivateKey(private)
	if err != nil {
		t.Fatal(err)
	}
	path := filepath.Join(t.TempDir(), "key")
	if err := os.WriteFile(path, pem.EncodeToMemory(&pem.Block{Type: "PRIVATE KEY", Bytes: wire}), 0600); err != nil {
		t.Fatal(err)
	}
	signer, err := readPrivateKey(path)
	if err != nil {
		t.Fatal(err)
	}
	if err := os.Chmod(path, 0644); err != nil {
		t.Fatal(err)
	}
	if _, err := readPrivateKey(path); err == nil {
		t.Fatal("world-readable key accepted")
	}
	if err := os.Chmod(path, 0600); err != nil {
		t.Fatal(err)
	}
	link := filepath.Join(t.TempDir(), "key-link")
	if err := os.Symlink(path, link); err != nil {
		t.Fatal(err)
	}
	if _, err := readPrivateKey(link); err == nil {
		t.Fatal("symlink key accepted")
	}
	listener, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	defer listener.Close()
	config := &ssh.ServerConfig{PublicKeyCallback: func(_ ssh.ConnMetadata, key ssh.PublicKey) (*ssh.Permissions, error) {
		if string(key.Marshal()) != string(signer.PublicKey().Marshal()) {
			return nil, errors.New("wrong client key")
		}
		return &ssh.Permissions{}, nil
	}}
	config.AddHostKey(signer)
	finished := make(chan error, 1)
	go func() {
		raw, err := listener.Accept()
		if err != nil {
			finished <- err
			return
		}
		server, channels, requests, err := ssh.NewServerConn(raw, config)
		if err != nil {
			finished <- err
			return
		}
		go ssh.DiscardRequests(requests)
		go func() {
			for c := range channels {
				_ = c.Reject(ssh.UnknownChannelType, "fixture has no shell")
			}
		}()
		finished <- server.Wait()
	}()
	client, err := ssh.Dial("tcp", listener.Addr().String(), &ssh.ClientConfig{User: "fixture", Auth: []ssh.AuthMethod{ssh.PublicKeys(signer)}, HostKeyCallback: ssh.FixedHostKey(signer.PublicKey()), Timeout: time.Second})
	if err != nil {
		t.Fatal(err)
	}
	client.Close()
	<-finished
}

func TestWorkerProtocolSubprocessRejectsUnverifiedHost(t *testing.T) {
	ctx, cancel := context.WithTimeout(t.Context(), 5*time.Second)
	defer cancel()
	process := exec.CommandContext(ctx, os.Args[0], "-test.run=^$")
	process.Env = append(os.Environ(), "TS_NATIVE_PROTOCOL_FIXTURE=1")
	in, err := process.StdinPipe()
	if err != nil {
		t.Fatal(err)
	}
	out, err := process.StdoutPipe()
	if err != nil {
		t.Fatal(err)
	}
	process.Stderr = os.Stderr
	if err := process.Start(); err != nil {
		t.Fatal(err)
	}
	if _, err := io.WriteString(in, "{\"operation\":\"cluster\"}\n"); err != nil {
		t.Fatal(err)
	}
	scanner := bufio.NewScanner(out)
	if !scanner.Scan() {
		t.Fatalf("worker returned no frame: %v", scanner.Err())
	}
	var result response
	if err := json.Unmarshal(scanner.Bytes(), &result); err != nil {
		t.Fatal(err)
	}
	if !strings.Contains(result.Error, "identity must be verified") {
		t.Fatalf("unverified worker operated: %+v", result)
	}
	in.Close()
	if err := process.Wait(); err != nil {
		t.Fatal(err)
	}
}

func TestMain(m *testing.M) {
	if os.Getenv("TS_NATIVE_PROTOCOL_FIXTURE") == "1" {
		if err := Serve(context.Background(), os.Stdin, os.Stdout); err != nil {
			os.Exit(1)
		}
		os.Exit(0)
	}
	os.Exit(m.Run())
}

func TestContinuousHTTPRecordsProcessWindowAndRejectsOutage(t *testing.T) {
	var status atomic.Int32
	status.Store(http.StatusOK)
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		w.WriteHeader(int(status.Load()))
		_, _ = io.WriteString(w, "ready")
	}))
	defer server.Close()
	ctx, cancel := context.WithTimeout(t.Context(), 5*time.Second)
	defer cancel()
	marker := filepath.Join(t.TempDir(), "process-marker")
	var samples atomic.Int32
	action := func() error {
		child := exec.CommandContext(ctx, "sh", "-c", "printf observed > \"$1\"; sleep 0.35", "fixture", marker)
		if err := child.Run(); err != nil {
			return err
		}
		wire, err := os.ReadFile(marker)
		if err != nil {
			return err
		}
		if string(wire) != "observed" {
			return errors.New("child filesystem observation missing")
		}
		return nil
	}
	if err := continuous(ctx, func(ctx context.Context) error { return probeHTTP(ctx, server.URL+"/readyz") }, action, func(error) { samples.Add(1) }); err != nil {
		t.Fatal(err)
	}
	if samples.Load() < 3 {
		t.Fatalf("only %d HTTP samples during child process", samples.Load())
	}
	err := continuous(ctx, func(ctx context.Context) error { return probeHTTP(ctx, server.URL+"/readyz") }, func() error {
		status.Store(http.StatusServiceUnavailable)
		return exec.CommandContext(ctx, "sh", "-c", "sleep 0.25").Run()
	}, func(error) {})
	if err == nil {
		t.Fatal("HTTP503 during disruption accepted")
	}
}
