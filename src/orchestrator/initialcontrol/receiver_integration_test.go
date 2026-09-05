//go:build linux

package initialcontrol_test

import (
	"bytes"
	"context"
	"crypto/ecdsa"
	"crypto/ed25519"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/sha256"
	"crypto/tls"
	"crypto/x509"
	"encoding/hex"
	"encoding/json"
	"encoding/pem"
	"errors"
	"net"
	"os"
	"path/filepath"
	"sync"
	"testing"
	"time"

	"github.com/nats-io/nats-server/v2/server"
	"github.com/nats-io/nats.go"
	"github.com/nats-io/nkeys"
	"golang.org/x/sys/unix"
	"terrascale.tech/orchestrator/src/orchestrator/delivery"
	"terrascale.tech/orchestrator/src/orchestrator/hostagent"
	"terrascale.tech/orchestrator/src/orchestrator/hostcontrol"
	"terrascale.tech/orchestrator/src/orchestrator/hostmanifest"
	"terrascale.tech/orchestrator/src/orchestrator/initialcontrol"
	"terrascale.tech/orchestrator/src/orchestrator/initialgrant"
	"terrascale.tech/orchestrator/src/orchestrator/nodeauthority"
	"terrascale.tech/orchestrator/src/orchestrator/nodebootstrap"
	runtimeplan "terrascale.tech/orchestrator/src/orchestrator/runtime"
	"terrascale.tech/orchestrator/src/orchestrator/security"
)

type receiverUnits struct {
	mu     sync.Mutex
	active bool
	start  func(context.Context) error
}

func (u *receiverUnits) DaemonReload(context.Context) error        { return nil }
func (u *receiverUnits) EnableUnit(context.Context, string) error  { return nil }
func (u *receiverUnits) DisableUnit(context.Context, string) error { return nil }
func (u *receiverUnits) StartUnit(ctx context.Context, _ string) error {
	u.mu.Lock()
	defer u.mu.Unlock()
	if !u.active {
		if err := u.start(ctx); err != nil {
			return err
		}
		u.active = true
	}
	return nil
}
func (u *receiverUnits) StopUnit(context.Context, string) error {
	u.mu.Lock()
	defer u.mu.Unlock()
	u.active = false
	return nil
}
func (u *receiverUnits) RestartUnit(ctx context.Context, s string) error { return u.StartUnit(ctx, s) }
func (u *receiverUnits) UnitActive(context.Context, string) (bool, error) {
	u.mu.Lock()
	defer u.mu.Unlock()
	return u.active, nil
}

type receiverUsers struct{}

func (receiverUsers) EnsureUser(context.Context, string) error           { return nil }
func (receiverUsers) OwnDirectory(context.Context, string, string) error { return nil }

type receiverClock struct{}

func (receiverClock) Offset(context.Context) (time.Duration, error) { return 0, nil }

type receiverDownloads map[string][]byte

func (d receiverDownloads) Download(_ context.Context, url, path string, limit int64) error {
	data, ok := d[url]
	if !ok || int64(len(data)) > limit {
		return errors.New("unadmitted fixture release")
	}
	return os.WriteFile(path, data, 0600)
}
func receiverSigner(t *testing.T) (*security.CommandSignatureSigner, []byte, *security.CommandSignatureVerifier) {
	t.Helper()
	key, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	signer, err := security.NewCommandSignatureSignerFromKey(key)
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { signer.Close() })
	der, _ := x509.MarshalPKIXPublicKey(&key.PublicKey)
	trust, err := security.NewCommandSignatureVerifierFromKeys([]security.CommandSignatureTrustKey{{KeyID: signer.PublicKeyID(), Algorithm: security.CommandSignatureAlgorithm, PublicKeySPKI: der}})
	if err != nil {
		t.Fatal(err)
	}
	return signer, pem.EncodeToMemory(&pem.Block{Type: "PUBLIC KEY", Bytes: der}), trust
}
func readerConnection(t *testing.T, c initialgrant.Config) *nats.Conn {
	t.Helper()
	r := c.AuthorityReader
	return client(t, c, initialgrant.Connection{NKeySeedFile: r.NKeySeedFile, PublicNKey: r.PublicNKey, TLS: initialgrant.TLSFiles{CAFile: r.CAFile, CertificateFile: r.CertificateFile, KeyFile: r.KeyFile}})
}

// The systemd seam starts the actual initialcontrol runtime after the real
// host receiver admits and installs the owner-signed release. No fake lease or
// authority verifier is used. The root transport has no JetStream state.
func TestReceiverSeparateAuthorityOwnerActivationAndLiveLease(t *testing.T) {
	namespace(t)
	cfg, _ := fixtureConfig(t)
	ctx := t.Context()
	commandSigner, _, trust := receiverSigner(t)
	owner, ownerPublic, _ := receiverSigner(t)
	root := t.TempDir()
	install, units, data := filepath.Join(root, "install"), filepath.Join(root, "units"), filepath.Join(root, "data")
	public, private, _ := ed25519.GenerateKey(rand.Reader)
	defer clear(private)
	binary := []byte("signed executable fixture")
	sum := sha256.Sum256(binary)
	installer, err := hostagent.NewInstaller(hostagent.InstallerConfig{InstallRoot: install, PublicKeyHex: hex.EncodeToString(public), AllowedHosts: []string{"releases.example"}, Downloader: receiverDownloads{"https://releases.example/orchestrator": binary, "https://releases.example/orchestrator.sig": ed25519.Sign(private, binary)}})
	if err != nil {
		t.Fatal(err)
	}
	raw, _ := json.Marshal(cfg)
	spec := hostmanifest.ComponentSpec{Name: "orchestrator", Version: "initial", ArtifactURL: "https://releases.example/orchestrator", SignatureURL: "https://releases.example/orchestrator.sig", Sha256: hex.EncodeToString(sum[:]), User: "terrascale-orchestrator", DataVolume: filepath.Join(data, "orchestrator"), CPUWeight: 100, MemoryMaxBytes: 1 << 30, IOWeight: 100, Arguments: initialgrant.Arguments, Configuration: string(raw)}
	manifest := hostmanifest.HostManifest{Components: []hostmanifest.ComponentSpec{spec}}
	manifestJSON, err := hostmanifest.CanonicalHostManifestJSON(manifest)
	if err != nil {
		t.Fatal(err)
	}
	grant := nodebootstrap.BootstrapGrant{Version: 1, GrantID: "receiver-owner-grant", NodeID: cfg.NodeID, Manifest: manifestJSON, IssuedAt: time.Now().Add(-time.Minute), ExpiresAt: time.Now().Add(time.Hour)}
	signed, err := nodebootstrap.SignBootstrapGrant(owner, grant)
	if err != nil {
		t.Fatal(err)
	}
	lazy, err := nodeauthority.NewLazyRegionalCommandAuthorizer(cfg.AuthorityReader, cfg.NodeID, "ORCH_LEADERS", trust, map[string]string{commandSigner.PublicKeyID(): "gru-controller-" + cfg.Instance})
	if err != nil {
		t.Fatal(err)
	}
	authorizer, err := hostagent.NewBootstrapAuthority(lazy, cfg.NodeID, ownerPublic, signed)
	if err != nil {
		t.Fatal(err)
	}
	var controlRuntime *initialcontrol.Runtime
	systemd := &receiverUnits{start: func(op context.Context) error {
		admission, err := initialgrant.AdmitConfiguration(op, raw)
		if err != nil {
			return err
		}
		controlRuntime, err = initialcontrol.Start(ctx, admission)
		return err
	}}
	t.Cleanup(func() {
		if controlRuntime != nil {
			controlRuntime.Close()
		}
	})
	lifecycle, err := hostagent.NewLifecycle(hostagent.LifecycleConfig{InstallRoot: install, UnitDir: units, DataVolumeRoot: data, Installer: installer, Systemd: systemd, Users: receiverUsers{}})
	if err != nil {
		t.Fatal(err)
	}
	facts, err := hostagent.NewHostFactsSource(hostagent.HostFactsSourceConfig{Clock: receiverClock{}, Statfs: hostagent.OsStatfs, DataVolumeRoot: data, Systemd: systemd, InstallRoot: install, Installer: installer})
	if err != nil {
		t.Fatal(err)
	}
	transportKey, _ := nkeys.CreateUser()
	defer transportKey.Wipe()
	transportPublic, _ := transportKey.PublicKey()
	rootTLS, err := tls.LoadX509KeyPair(cfg.Broker.TLS.CertificateFile, cfg.Broker.TLS.KeyFile)
	if err != nil {
		t.Fatal(err)
	}
	ca, _ := os.ReadFile(cfg.Broker.TLS.CAFile)
	roots := x509.NewCertPool()
	roots.AppendCertsFromPEM(ca)
	broker, err := server.NewServer(&server.Options{Host: "10.77.0.10", Port: -1, ServerName: "command-transport-only", NoSigs: true, NoLog: true, MaxPayload: 4 << 20, Nkeys: []*server.NkeyUser{{Nkey: transportPublic}}, TLSConfig: &tls.Config{MinVersion: tls.VersionTLS13, Certificates: []tls.Certificate{rootTLS}, ClientAuth: tls.RequireAndVerifyClientCert, ClientCAs: roots}})
	if err != nil {
		t.Fatal(err)
	}
	broker.Start()
	t.Cleanup(func() { broker.Shutdown(); broker.WaitForShutdown() })
	if !broker.ReadyForConnections(5 * time.Second) {
		t.Fatal("transport unavailable")
	}
	clientTLS, err := tls.LoadX509KeyPair(cfg.Regional.Runtime.TLS.CertificateFile, cfg.Regional.Runtime.TLS.KeyFile)
	if err != nil {
		t.Fatal(err)
	}
	dial := func() *nats.Conn {
		c, err := nats.Connect(broker.ClientURL(), nats.Nkey(transportPublic, transportKey.Sign), nats.Secure(&tls.Config{MinVersion: tls.VersionTLS13, RootCAs: roots, Certificates: []tls.Certificate{clientTLS}}), nats.NoReconnect())
		if err != nil {
			t.Fatal(err)
		}
		t.Cleanup(c.Close)
		return c
	}
	sender, node := dial(), dial()
	live, err := hostagent.NewLiveNatsConnection(node)
	if err != nil {
		t.Fatal(err)
	}
	manifestPath := filepath.Join(data, "ts-node", "manifest.json")
	write(t, manifestPath, manifestJSON)
	nodeID, _ := hostagent.NewNodeId(cfg.NodeID)
	agent, err := hostagent.NewHostAgent(hostagent.HostAgentConfig{NodeId: nodeID, Connection: live, Lifecycle: lifecycle, Facts: facts, ManifestPath: manifestPath, RequireManifestAdmission: true, CommandAuthorityFactory: func(hostagent.NatsConnection) (nodeauthority.CommandAuthorizer, error) { return authorizer, nil }, ReconcileInterval: time.Hour, HeartbeatInterval: time.Hour, Now: time.Now})
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { agent.Close() })
	if err = agent.Start(ctx); err != nil {
		t.Fatal(err)
	}
	if controlRuntime != nil {
		t.Fatal("broker started before owner activation")
	}
	status, _ := hostagent.NodeDrainStatusSubject(nodeID)
	statusRequest, _ := hostagent.NewNodeStatusRequest("before-broker")
	statusJSON, _ := json.Marshal(statusRequest)
	if _, err = sender.RequestWithContext(ctx, status, statusJSON); err != nil {
		t.Fatal(err)
	}
	commands, err := nodebootstrap.BootstrapCommands(grant)
	if err != nil {
		t.Fatal(err)
	}
	for _, command := range commands {
		now := time.Now()
		wire, err := nodebootstrap.SignBootstrapCommand(owner, signed, command.Subject, json.RawMessage(command.Command), now, now.Add(30*time.Second))
		if err != nil {
			t.Fatal(err)
		}
		reply, err := sender.RequestWithContext(ctx, command.Subject, wire)
		if err != nil {
			t.Fatal(err)
		}
		if bytes.Contains(reply.Data, []byte(`"error"`)) {
			t.Fatalf("owner command: %s", reply.Data)
		}
	}
	if controlRuntime == nil || !controlRuntime.RegionalAuthority().Ready() {
		t.Fatal("owner activation did not start real elected runtime")
	}
	observer := readerConnection(t, cfg)
	var captured delivery.RegionalCommandAuthority
	authorityOffline := false
	resolve := func(ctx context.Context, _ hostcontrol.Host) (delivery.RegionalCommandAuthority, error) {
		if authorityOffline {
			return captured, nil
		}
		lease, _, err := nodeauthority.ReadRegionalCommandLease(ctx, observer, "ORCH_LEADERS")
		captured = delivery.RegionalCommandAuthority{AuthorityID: lease.AuthorityId, Epoch: lease.Epoch, DesiredGeneration: 1, CandidateID: lease.CandidateId, LeaseID: lease.LeaseId, IssuedAt: lease.IssuedAt, ExpiresAt: lease.IssuedAt.Add(time.Duration(lease.DurationMilliseconds) * time.Millisecond)}
		return captured, err
	}
	controlClient, err := hostcontrol.New(hostcontrol.Config{Region: "GRU", SigningKey: commandSigner, Connection: sender, Timeout: time.Second, ResolveHost: func(context.Context, string) (hostcontrol.Host, error) {
		return hostcontrol.Host{NodeID: nodeID, Region: "GRU", Architecture: runtimeplan.HostArchitectureX64}, nil
	}, CommandAuthority: resolve, Authorize: func(ctx context.Context, h hostcontrol.Host) error { _, err := resolve(ctx, h); return err }})
	if err != nil {
		t.Fatal(err)
	}
	if _, err = controlClient.SetDrain(ctx, cfg.NodeID, "runtime-live", false); err != nil {
		t.Fatal(err)
	}
	for _, subject := range []string{"$KV.ORCH_LEADERS.authority.regional", "$JS.API.STREAM.CREATE.ESCAPE", "$JS.API.STREAM.UPDATE.KV_ORCH_LEADERS"} {
		bounded, cancel := context.WithTimeout(ctx, 100*time.Millisecond)
		_, err := observer.RequestWithContext(bounded, subject, []byte(`{}`))
		cancel()
		if err == nil {
			t.Fatal("observer mutation was allowed")
		}
	}
	if err = controlRuntime.Close(); err != nil {
		t.Fatal(err)
	}
	authorityOffline = true
	if _, err = controlClient.SetDrain(ctx, cfg.NodeID, "authority-offline", false); err == nil {
		t.Fatal("unavailable authority accepted mutation on live transport")
	}
	if _, err = controlClient.Status(ctx, cfg.NodeID); err != nil {
		t.Fatal("authority failure stopped status transport")
	}
	if err = agent.Close(); err != nil {
		t.Fatal(err)
	}
}

func TestLazyAuthorityCloseInterruptsHandshake(t *testing.T) {
	namespace(t)
	cfg, _ := fixtureConfig(t)
	signer, _, trust := receiverSigner(t)
	listener, err := net.Listen("tcp", "10.77.0.10:0")
	if err != nil {
		t.Fatal(err)
	}
	defer listener.Close()
	cfg.AuthorityReader.Endpoint = "tls://" + listener.Addr().String()
	lazy, err := nodeauthority.NewLazyRegionalCommandAuthorizer(cfg.AuthorityReader, cfg.NodeID, "ORCH_LEADERS", trust, map[string]string{signer.PublicKeyID(): "gru-controller-" + cfg.Instance})
	if err != nil {
		t.Fatal(err)
	}
	accepted := make(chan net.Conn, 2)
	go func() {
		for i := 0; i < 2; i++ {
			c, e := listener.Accept()
			if e != nil {
				return
			}
			accepted <- c
		}
	}()
	done := make(chan error, 1)
	for attempt := 0; attempt < 2; attempt++ {
		ctx, cancel := context.WithCancel(t.Context())
		defer cancel()
		go func() { _, e := lazy.Authorize(ctx, "subject", nil); done <- e }()
		select {
		case c := <-accepted:
			defer c.Close()
		case <-time.After(time.Second):
			t.Fatal("dial did not start or previous cancellation poisoned retry")
		}
		if attempt == 0 {
			cancel()
			select {
			case err := <-done:
				if err == nil {
					t.Fatal("cancelled request authorized")
				}
			case <-time.After(time.Second):
				t.Fatal("request cancellation did not interrupt handshake")
			}
		}
	}
	started := time.Now()
	if err = lazy.Close(); err != nil {
		t.Fatal(err)
	}
	if time.Since(started) > time.Second {
		t.Fatal("Close did not interrupt handshake")
	}
	select {
	case err := <-done:
		if err == nil {
			t.Fatal("late dial authorized")
		}
	case <-time.After(time.Second):
		t.Fatal("authorization survived owner close")
	}
}

func TestLazyAuthorityRejectsUnsafeMaterial(t *testing.T) {
	namespace(t)
	cfg, _ := fixtureConfig(t)
	signer, _, trust := receiverSigner(t)
	root := filepath.Dir(cfg.AuthorityReader.CAFile)
	for _, kind := range []string{"fifo", "ancestor-symlink", "writable-ancestor", "nonroot", "hardlink"} {
		t.Run(kind, func(t *testing.T) {
			dir := filepath.Join(root, kind)
			if err := os.Mkdir(dir, 0700); err != nil {
				t.Fatal(err)
			}
			file := filepath.Join(dir, "ca.pem")
			data, err := os.ReadFile(cfg.AuthorityReader.CAFile)
			if err != nil {
				t.Fatal(err)
			}
			if kind == "fifo" {
				err = unix.Mkfifo(file, 0600)
			} else {
				err = os.WriteFile(file, data, 0400)
			}
			if err != nil {
				t.Fatal(err)
			}
			switch kind {
			case "ancestor-symlink":
				link := dir + "-link"
				if err := os.Symlink(dir, link); err != nil {
					t.Fatal(err)
				}
				file = filepath.Join(link, "ca.pem")
			case "writable-ancestor":
				if err := os.Chmod(dir, 0777); err != nil {
					t.Fatal(err)
				}
			case "nonroot":
				if err := os.Chown(file, 65534, 65534); err != nil {
					t.Fatal(err)
				}
			case "hardlink":
				if err := os.Link(file, file+".copy"); err != nil {
					t.Fatal(err)
				}
			}
			reader := cfg.AuthorityReader
			reader.CAFile = file
			lazy, err := nodeauthority.NewLazyRegionalCommandAuthorizer(reader, cfg.NodeID, "ORCH_LEADERS", trust, map[string]string{signer.PublicKeyID(): "gru-controller-" + cfg.Instance})
			if err != nil {
				t.Fatal(err)
			}
			defer lazy.Close()
			started := time.Now()
			if _, err := lazy.Authorize(t.Context(), "subject", nil); err == nil {
				t.Fatal("unsafe credential accepted")
			}
			if time.Since(started) > time.Second {
				t.Fatal("unsafe credential read blocked")
			}
		})
	}
}
