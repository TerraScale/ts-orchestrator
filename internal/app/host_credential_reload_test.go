package app

import (
	"crypto/ed25519"
	"crypto/rand"
	"encoding/base64"
	"os"
	"path/filepath"
	"testing"

	"git.terrascale.tech/TerraScale/ts-orchestrator/internal/natscell"
	"git.terrascale.tech/TerraScale/ts-orchestrator/internal/protocol"
)

func TestHostCredentialReloaderAcceptsOnlyRenewedCredentialPaths(t *testing.T) {
	root := t.TempDir()
	_, identity, err := ed25519.GenerateKey(rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	_, foreignIdentity, err := ed25519.GenerateKey(rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	credentialConfig := func(dir string, key ed25519.PrivateKey) Config {
		t.Helper()
		credentialRoot := filepath.Join(root, dir)
		if err := os.MkdirAll(credentialRoot, 0o700); err != nil {
			t.Fatal(err)
		}
		keyFile := filepath.Join(credentialRoot, "host-identity.key")
		if err := os.WriteFile(keyFile, []byte(base64.StdEncoding.EncodeToString(key)+"\n"), 0o600); err != nil {
			t.Fatal(err)
		}
		return Config{NATS: natscell.Config{Cell: "gru", Instance: "host-a", Replicas: 3, URL: "tls://10.0.0.2:4222",
			CredentialsFile: filepath.Join(credentialRoot, "host-nats.creds"),
			TLS: natscell.TLSFiles{CAFile: filepath.Join(credentialRoot, "ca.pem"),
				CertFile: filepath.Join(credentialRoot, "host-tls-cert.pem"), KeyFile: filepath.Join(credentialRoot, "host-tls-key.pem")}},
			Host: HostConfig{Node: "host-a", Environment: "production", Roles: []string{"terrabase"},
				IdentityKeyFile: keyFile, InstallRoot: "/opt/ts", StateRoot: "/var/lib/ts", ManagedRuntimeRoot: "/srv/ts-managed",
				TerraBaseRoot: "/srv/ts-managed/terrabase", TSAuthRoot: "/srv/ts-managed/ts-auth", WorkloadUID: 2000, WorkloadGID: 2000}}
	}
	path := filepath.Join(root, "host.json")
	install := func(cfg Config) {
		t.Helper()
		wire, err := protocol.EncodeJSON(cfg)
		if err != nil {
			t.Fatal(err)
		}
		if err := os.WriteFile(path, wire, 0o600); err != nil {
			t.Fatal(err)
		}
	}
	running := credentialConfig("host-credentials-old", identity)
	running.NATS.ClientRole = "host"
	reload := hostCredentialReloader(path, running, identity)

	renewed := credentialConfig("host-credentials-new", identity)
	install(renewed)
	material, err := reload()
	if err != nil {
		t.Fatal(err)
	}
	if material.CredentialsFile != renewed.NATS.CredentialsFile || material.TLS != renewed.NATS.TLS {
		t.Fatalf("renewed paths were not returned: %+v", material)
	}
	for _, seconds := range []int{0, 15, 60} {
		withInterval, renewedWithInterval := running, renewed
		withInterval.Host.LoadTelemetrySeconds = new(seconds)
		renewedWithInterval.Host.LoadTelemetrySeconds = new(seconds)
		install(renewedWithInterval)
		material, err := hostCredentialReloader(path, withInterval, identity)()
		if err != nil {
			t.Fatalf("reload with unchanged interval %d: %v", seconds, err)
		}
		if material.CredentialsFile != renewed.NATS.CredentialsFile || material.TLS != renewed.NATS.TLS {
			t.Fatalf("renewed paths with interval %d were not returned: %+v", seconds, material)
		}
	}

	moved := renewed
	moved.Host.StateRoot = "/var/lib/other"
	install(moved)
	if _, err := reload(); err == nil {
		t.Fatal("a non-credential host change was hot-reloaded")
	}
	retargetedWorkload := renewed
	retargetedWorkload.Host.TSAuthRoot = "/srv/other/ts-auth"
	install(retargetedWorkload)
	if _, err := reload(); err == nil {
		t.Fatal("a ts-auth root change was hot-reloaded")
	}
	retargeted := renewed
	retargeted.NATS.URL = "tls://10.0.0.9:4222"
	install(retargeted)
	if _, err := reload(); err == nil {
		t.Fatal("a NATS endpoint change was hot-reloaded")
	}
	install(credentialConfig("host-credentials-foreign", foreignIdentity))
	if _, err := reload(); err == nil {
		t.Fatal("a different host identity was hot-reloaded")
	}
}

func TestSameHostIdentityConfigLoadTelemetryPresence(t *testing.T) {
	shared := new(60)
	for _, tt := range []struct {
		name              string
		running, reloaded *int
		changed           bool
	}{
		{name: "both omitted"},
		{name: "same pointer", running: shared, reloaded: shared},
		{name: "distinct off pointers", running: new(0), reloaded: new(0)},
		{name: "distinct default pointers", running: new(15), reloaded: new(15)},
		{name: "distinct custom pointers", running: new(60), reloaded: new(60)},
		{name: "custom changed", running: new(60), reloaded: new(45), changed: true},
		{name: "omitted to off", reloaded: new(0), changed: true},
		{name: "off to omitted", running: new(0), changed: true},
		{name: "omitted to explicit default", reloaded: new(15), changed: true},
		{name: "explicit default to omitted", running: new(15), changed: true},
	} {
		t.Run(tt.name, func(t *testing.T) {
			err := sameHostIdentityConfig(Config{Host: HostConfig{LoadTelemetrySeconds: tt.running}},
				Config{Host: HostConfig{LoadTelemetrySeconds: tt.reloaded}})
			if (err != nil) != tt.changed {
				t.Fatalf("identity comparison = %v; want changed=%v", err, tt.changed)
			}
		})
	}
}
