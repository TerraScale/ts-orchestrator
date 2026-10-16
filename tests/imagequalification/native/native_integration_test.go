package native

import (
	"bufio"
	"context"
	"crypto/ed25519"
	"crypto/rand"
	"crypto/x509"
	"encoding/json/v2"
	"encoding/pem"
	"errors"
	"io"
	"net"
	"net/http"
	"net/http/httptest"
	"net/url"
	"os"
	"os/exec"
	"path/filepath"
	"strconv"
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
	web := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) { _, _ = io.WriteString(w, "ready") }))
	defer web.Close()
	endpoint, _ := url.Parse(web.URL)
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
	uploadDirectory := t.TempDir()
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
				if c.ChannelType() == "session" {
					channel, requests, err := c.Accept()
					if err != nil {
						continue
					}
					go serveSSHFixture(channel, requests, uploadDirectory)
					continue
				}
				if c.ChannelType() != "direct-tcpip" {
					_ = c.Reject(ssh.UnknownChannelType, "fixture has no shell")
					continue
				}
				var target struct {
					Host       string
					Port       uint32
					OriginHost string
					OriginPort uint32
				}
				if err := ssh.Unmarshal(c.ExtraData(), &target); err != nil || net.JoinHostPort(target.Host, strconv.Itoa(int(target.Port))) != endpoint.Host {
					_ = c.Reject(ssh.Prohibited, "wrong HTTP target")
					continue
				}
				remote, err := net.Dial("tcp", endpoint.Host)
				if err != nil {
					_ = c.Reject(ssh.ConnectionFailed, err.Error())
					continue
				}
				channel, requests, err := c.Accept()
				if err != nil {
					remote.Close()
					continue
				}
				go ssh.DiscardRequests(requests)
				go func() { _, _ = io.Copy(channel, remote); channel.Close() }()
				go func() { _, _ = io.Copy(remote, channel); remote.Close() }()
			}
		}()
		finished <- server.Wait()
	}()
	client, err := ssh.Dial("tcp", listener.Addr().String(), &ssh.ClientConfig{User: "fixture", Auth: []ssh.AuthMethod{ssh.PublicKeys(signer)}, HostKeyCallback: ssh.FixedHostKey(signer.PublicKey()), Timeout: time.Second})
	if err != nil {
		t.Fatal(err)
	}
	if err := probeHTTP(t.Context(), web.URL+"/readyz", client.DialContext); err != nil {
		t.Fatal(err)
	}
	payload := filepath.Join(t.TempDir(), "payload")
	if err := os.WriteFile(payload, []byte("exact upload bytes"), 0600); err != nil {
		t.Fatal(err)
	}
	p := &Session{client: client, remote: "/run/ts-native-fixture"}
	if err := p.UploadFile(t.Context(), "payload.oci", payload, digest([]byte("exact upload bytes"))); err != nil {
		t.Fatal(err)
	}
	actual, err := os.ReadFile(filepath.Join(uploadDirectory, "payload.oci"))
	if err != nil || string(actual) != "exact upload bytes" {
		t.Fatalf("SSH upload bytes differ: %q, %v", actual, err)
	}
	if err := p.UploadFile(t.Context(), "payload.oci", payload, digest([]byte("exact upload bytes"))); err == nil {
		t.Fatal("existing remote upload overwritten")
	}
	if err := p.UploadFile(t.Context(), "../escape", payload, digest([]byte("exact upload bytes"))); err == nil {
		t.Fatal("upload path traversal accepted")
	}
	if err := p.UploadFile(t.Context(), "wrong.oci", payload, digest([]byte("different bytes"))); err == nil {
		t.Fatal("local upload digest mismatch accepted")
	}
	for _, mode := range []string{"native-fixture-serve", "native-fixture-unknown", "native-fixture-stall"} {
		session, err := client.NewSession()
		if err != nil {
			t.Fatal(err)
		}
		p.session = session
		p.in, err = session.StdinPipe()
		if err != nil {
			t.Fatal(err)
		}
		output, err := session.StdoutPipe()
		if err != nil {
			t.Fatal(err)
		}
		p.out = bufio.NewScanner(output)
		p.out.Buffer(make([]byte, 4096), maxFrame)
		if err := session.Start(mode); err != nil {
			t.Fatal(err)
		}
		var result response
		operation := t.Context()
		cancel := func() {}
		if mode == "native-fixture-stall" {
			operation, cancel = context.WithTimeout(operation, 100*time.Millisecond)
		}
		err = p.Exchange(operation, command{Operation: "cluster"}, &result)
		cancel()
		if mode == "native-fixture-serve" && (err != nil || !strings.Contains(result.Error, "identity must be verified")) {
			t.Fatalf("SSH worker protocol: %+v, %v", result, err)
		}
		if mode == "native-fixture-unknown" && err == nil {
			t.Fatal("unknown SSH response member accepted")
		}
		if mode == "native-fixture-stall" && !errors.Is(err, context.DeadlineExceeded) {
			t.Fatalf("blocked SSH exchange did not abort on context deadline: %v", err)
		}
		p.in.Close()
		session.Close()
	}
	p.Close()
	<-finished
}

func serveSSHFixture(channel ssh.Channel, requests <-chan *ssh.Request, uploadDirectory string) {
	defer channel.Close()
	for request := range requests {
		var invocation struct{ Command string }
		if request.Type != "exec" || ssh.Unmarshal(request.Payload, &invocation) != nil {
			_ = request.Reply(false, nil)
			continue
		}
		_ = request.Reply(true, nil)
		var process *exec.Cmd
		switch invocation.Command {
		case "native-fixture-serve":
			process = exec.Command(os.Args[0], "-test.run=^$")
			process.Env = append(os.Environ(), "TS_NATIVE_PROTOCOL_FIXTURE=1")
		case "native-fixture-unknown":
			process = exec.Command("sh", "-c", `read line; printf '{"unexpected":true}\n'`)
		case "native-fixture-stall":
			process = exec.Command("sh", "-c", "cat >/dev/null")
		default:
			// Only the production uploader's fixed command reaches this fixture.
			process = exec.Command("sh", "-c", strings.ReplaceAll(invocation.Command, "/run/ts-native-fixture", uploadDirectory))
		}
		process.Stdin, process.Stdout, process.Stderr = channel, channel, channel.Stderr()
		status := uint32(0)
		if err := process.Run(); err != nil {
			status = 1
		}
		_, _ = channel.SendRequest("exit-status", false, ssh.Marshal(struct{ Status uint32 }{status}))
		return
	}
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
	if err := continuous(ctx, func(ctx context.Context) error {
		return probeHTTP(ctx, server.URL+"/readyz", (&net.Dialer{}).DialContext)
	}, action, func(error) { samples.Add(1) }); err != nil {
		t.Fatal(err)
	}
	if samples.Load() < 3 {
		t.Fatalf("only %d HTTP samples during child process", samples.Load())
	}
	err := continuous(ctx, func(ctx context.Context) error {
		return probeHTTP(ctx, server.URL+"/readyz", (&net.Dialer{}).DialContext)
	}, func() error {
		status.Store(http.StatusServiceUnavailable)
		return exec.CommandContext(ctx, "sh", "-c", "sleep 0.25").Run()
	}, func(error) {})
	if err == nil {
		t.Fatal("HTTP503 during disruption accepted")
	}
}
