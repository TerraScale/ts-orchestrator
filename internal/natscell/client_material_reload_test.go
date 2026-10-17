package natscell

import (
	"bytes"
	"context"
	"crypto/tls"
	"os"
	"path/filepath"
	"strings"
	"sync/atomic"
	"testing"
	"time"

	"github.com/nats-io/nats.go"
	"github.com/nats-io/nkeys"
)

func applyOptions(t *testing.T, options []nats.Option) nats.Options {
	t.Helper()
	applied := nats.GetDefaultOptions()
	for _, option := range options {
		if err := option(&applied); err != nil {
			t.Fatal(err)
		}
	}
	return applied
}

// A renewed credentials file whose seed block is intact but whose JWT is
// corrupt must fall back to the startup files instead of failing every
// handshake.
func TestClientMaterialSourceRejectsCorruptReloadedJWT(t *testing.T) {
	root := t.TempDir()
	region := productionTestRegion(t, "gru", "broker-a")
	account, accountID := region.cell, region.cellID
	user, _ := nkeys.CreateUser()
	userID, _ := user.PublicKey()
	startup := filepath.Join(root, "startup.creds")
	corrupt := filepath.Join(root, "corrupt.creds")
	writeExpiringUserCredentials(t, startup, account, accountID, user, time.Now().Add(time.Hour))
	writeExpiringUserCredentials(t, corrupt, account, accountID, user, time.Now().Add(time.Hour))
	data, err := os.ReadFile(corrupt)
	if err != nil {
		t.Fatal(err)
	}
	// Truncate the JWT block: its begin marker stays, its body and end go.
	begin := bytes.Index(data, []byte("-----BEGIN NATS USER JWT-----"))
	seed := bytes.Index(data, []byte("************************* IMPORTANT"))
	if begin < 0 || seed < 0 || seed < begin {
		t.Fatalf("unexpected credentials layout:\n%s", data)
	}
	broken := append(append([]byte{}, data[:begin]...), []byte("-----BEGIN NATS USER JWT-----\neyJ0\n\n")...)
	broken = append(broken, data[seed:]...)
	if err := os.WriteFile(corrupt, broken, 0o600); err != nil {
		t.Fatal(err)
	}
	if _, err := nkeys.ParseDecoratedUserNKey(broken); err != nil {
		t.Fatalf("fixture lost its seed block: %v", err)
	}
	source := newClientMaterialSource(Config{CredentialsFile: startup, ReloadClientMaterial: func() (ClientMaterial, error) {
		return ClientMaterial{CredentialsFile: corrupt}, nil
	}}, userID)
	if got := source.current().CredentialsFile; got != startup {
		t.Fatalf("credentials with a corrupt JWT were accepted: %s", got)
	}
	ctx, cancel := context.WithTimeout(t.Context(), 20*time.Second)
	defer cancel()
	broker, err := openTestBroker(t, ctx, region.cfg)
	if err != nil {
		t.Fatal(err)
	}
	cfg := Config{Cell: "gru", Instance: "host-a", Replicas: 1, ClientRole: "host",
		URL: broker.URL(), CredentialsFile: startup, TLS: region.cfg.TLS}
	var reloads atomic.Int32
	cfg.ReloadClientMaterial = func() (ClientMaterial, error) {
		reloads.Add(1)
		return ClientMaterial{CredentialsFile: corrupt, TLS: cfg.TLS}, nil
	}
	client, err := Start(ctx, cfg)
	if err != nil {
		t.Fatalf("corrupt renewal did not fall back during JWT/mTLS handshake: %v", err)
	}
	defer client.Close()
	if err := client.Conn().FlushWithContext(ctx); err != nil {
		t.Fatal(err)
	}
	if reloads.Load() == 0 {
		t.Fatal("real handshake did not resolve renewed material")
	}
}

// When both the reloaded and the startup TLS material fail, the error keeps
// the startup failure in its chain and names the reloaded cause.
func TestClientMaterialSourceTLSFallbackErrorNamesBothCauses(t *testing.T) {
	root := t.TempDir()
	good := testBridgeTLS(t, filepath.Join(root, "good"))
	missing := TLSFiles{CAFile: filepath.Join(root, "none", "ca"), CertFile: filepath.Join(root, "none", "cert"),
		KeyFile: filepath.Join(root, "none", "key")}
	reloaded := good
	reloaded.KeyFile = filepath.Join(root, "renewed-missing.key")
	source := newClientMaterialSource(Config{TLS: missing, ReloadClientMaterial: func() (ClientMaterial, error) {
		return ClientMaterial{TLS: reloaded}, nil
	}}, "")
	_, err := source.tlsConfig()
	if err == nil || !strings.HasPrefix(err.Error(), "NATS client TLS (reloaded material: ") ||
		!strings.Contains(err.Error(), "NATS TLS private key") || !os.IsNotExist(unwrapAll(err)) {
		t.Fatalf("fallback error = %v", err)
	}
}

func unwrapAll(err error) error {
	for {
		next, ok := err.(interface{ Unwrap() error })
		if !ok || next.Unwrap() == nil {
			return err
		}
		err = next.Unwrap()
	}
}

// Both seed-only option construction and JWT clients resolve renewed TLS material per handshake.
func TestClientOptionsReloadTLSWithoutCredentialsFileAndInLab(t *testing.T) {
	root := t.TempDir()
	startupTLS := testBridgeTLS(t, filepath.Join(root, "startup"))
	renewedTLS := testBridgeTLS(t, filepath.Join(root, "renewed"))
	_, seed := newUserIdentity(t)
	reloads := 0
	reload := func() (ClientMaterial, error) {
		reloads++
		return ClientMaterial{TLS: renewedTLS}, nil
	}
	options, err := clientOptions(Config{Cell: "gru", Instance: "host-a", Replicas: 1, ClientRole: "host",
		URL: "tls://127.0.0.1:4222", NKeySeedFile: seed, TLS: startupTLS, ReloadClientMaterial: reload})
	if err != nil {
		t.Fatal(err)
	}
	dialer, ok := applyOptions(t, options).CustomDialer.(*tlsFirstDialer)
	if !ok || dialer.reload == nil {
		t.Fatal("an NKey-seed client does not reload its TLS material")
	}
	renewed, err := dialer.reload()
	if err != nil {
		t.Fatal(err)
	}
	want, err := tls.LoadX509KeyPair(renewedTLS.CertFile, renewedTLS.KeyFile)
	if err != nil {
		t.Fatal(err)
	}
	if !bytes.Equal(renewed.Certificates[0].Certificate[0], want.Certificate[0]) {
		t.Fatal("the NKey-seed client did not resolve the renewed certificate")
	}

	region := productionTestRegion(t, "lab", "broker-a")
	cfg, _ := productionTestUser(t, region, "host-a", "host", false)
	cfg.URL, cfg.TLS = "tls://127.0.0.1:4222", startupTLS
	cfg.ReloadClientMaterial = func() (ClientMaterial, error) {
		reloads++
		return ClientMaterial{CredentialsFile: cfg.CredentialsFile, TLS: renewedTLS}, nil
	}
	options, err = clientOptions(cfg)
	if err != nil {
		t.Fatal(err)
	}
	lab, ok := applyOptions(t, options).CustomDialer.(*tlsFirstDialer)
	if !ok || lab.reload == nil {
		t.Fatal("a JWT client keeps its startup certificate for the connection's life")
	}
	before := reloads
	presented, err := lab.reload()
	if err != nil || reloads == before || !bytes.Equal(presented.Certificates[0].Certificate[0], want.Certificate[0]) {
		t.Fatalf("JWT handshake did not present the renewed certificate: %v", err)
	}
}
