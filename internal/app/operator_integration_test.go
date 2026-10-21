package app

import (
	"bytes"
	"context"
	"crypto/ed25519"
	"crypto/rand"
	"encoding/base64"
	"encoding/json/v2"
	"os"
	"path/filepath"
	"strings"
	"sync"
	"testing"

	"github.com/TerraScale/ts-orchestrator/internal/host"
	"github.com/nats-io/nkeys"
)

type inMemoryRunner struct {
	mu       sync.Mutex
	observed host.Observation
}

func testHostWorkloadIdentity() host.WorkloadIdentity {
	if os.Geteuid() == 0 {
		return host.WorkloadIdentity{UID: 65534, GID: 65534}
	}
	return host.WorkloadIdentity{UID: uint32(os.Getuid()), GID: uint32(os.Getgid())}
}

func testHostInstallRoot(t *testing.T) string {
	t.Helper()
	parent, err := os.MkdirTemp("/tmp", "ts-host-install-")
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() {
		if err := os.RemoveAll(parent); err != nil {
			t.Errorf("remove test install parent: %v", err)
		}
	})
	if err := os.Chmod(parent, 0o755); err != nil {
		t.Fatal(err)
	}
	return filepath.Join(parent, "install")
}

func testHostStateRoot(t *testing.T) string {
	t.Helper()
	if os.Geteuid() != 0 {
		return filepath.Join(t.TempDir(), "state")
	}
	parent, err := os.MkdirTemp("/var/lib", "ts-host-state-")
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() {
		if err := os.RemoveAll(parent); err != nil {
			t.Errorf("remove test state parent: %v", err)
		}
	})
	return filepath.Join(parent, "state")
}

func (*inMemoryRunner) Recover(context.Context) error { return nil }
func (r *inMemoryRunner) Apply(_ context.Context, workload host.Workload) error {
	r.mu.Lock()
	defer r.mu.Unlock()
	r.observed = host.Observation{Role: workload.Role, Digest: workload.Digest, Fingerprint: workload.Fingerprint, Running: true, PID: 1}
	return nil
}
func (r *inMemoryRunner) Stop(_ context.Context, role string) error {
	r.mu.Lock()
	defer r.mu.Unlock()
	r.observed = host.Observation{Role: role}
	return nil
}
func (r *inMemoryRunner) Observe(_ context.Context, _ string) (host.Observation, error) {
	r.mu.Lock()
	defer r.mu.Unlock()
	return r.observed, nil
}
func (*inMemoryRunner) Close(context.Context) error { return nil }

type readyWriter struct {
	mu     sync.Mutex
	ready  chan struct{}
	once   sync.Once
	buffer bytes.Buffer
}

func (w *readyWriter) Write(data []byte) (int, error) {
	w.mu.Lock()
	defer w.mu.Unlock()
	n, err := w.buffer.Write(data)
	if strings.Contains(w.buffer.String(), " ready in cell ") {
		w.once.Do(func() { close(w.ready) })
	}
	return n, err
}

func testNKey(t *testing.T) (string, string) {
	t.Helper()
	pair, err := nkeys.CreateUser()
	if err != nil {
		t.Fatal(err)
	}
	defer pair.Wipe()
	public, err := pair.PublicKey()
	if err != nil {
		t.Fatal(err)
	}
	seed, err := pair.Seed()
	if err != nil {
		t.Fatal(err)
	}
	defer clear(seed)
	path := filepath.Join(t.TempDir(), "user.nk")
	if err := os.WriteFile(path, seed, 0o600); err != nil {
		t.Fatal(err)
	}
	return public, path
}

func testEd25519(t *testing.T, dir, name string) (ed25519.PublicKey, ed25519.PrivateKey) {
	t.Helper()
	public, private, err := ed25519.GenerateKey(rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(filepath.Join(dir, name), []byte(base64.StdEncoding.EncodeToString(private)), 0o600); err != nil {
		t.Fatal(err)
	}
	return public, private
}

func testJSONFile(t *testing.T, dir, name string, value any) string {
	t.Helper()
	if cfg, ok := value.(Config); ok && cfg.Version == 0 {
		cfg.Version = ConfigVersion
		value = cfg
	}
	data, err := json.Marshal(value)
	if err != nil {
		t.Fatal(err)
	}
	path := filepath.Join(dir, name)
	if err := os.WriteFile(path, data, 0o600); err != nil {
		t.Fatal(err)
	}
	return path
}
