package app

import (
	"bytes"
	"context"
	"encoding/base64"
	"encoding/json/v2"
	"os"
	"path/filepath"
	"strings"
	"testing"

	"github.com/TerraScale/ts-orchestrator/internal/cellspec"
	"github.com/TerraScale/ts-orchestrator/internal/hostboot"
	"github.com/TerraScale/ts-orchestrator/internal/hostenroll"
	"github.com/TerraScale/ts-orchestrator/internal/netbird"
	"github.com/TerraScale/ts-orchestrator/internal/netbird/client"
	"github.com/TerraScale/ts-orchestrator/internal/protocol"
	"github.com/nats-io/jwt/v2"
	"github.com/nats-io/nkeys"
)

func TestHostEnrollmentOnlySeedsUnmanagedFirstBootstrapNetBirdConfig(t *testing.T) {
	account, _ := nkeys.CreateAccount()
	user, _ := nkeys.CreateUser()
	userID, _ := user.PublicKey()
	seed, _ := user.Seed()
	token, err := jwt.NewUserClaims(userID).Encode(account)
	if err != nil {
		t.Fatal(err)
	}
	bundle := hostenroll.PublicBundle{Cell: "gru", Environment: "production", NATSURLs: []string{"tls://10.0.0.1:4222"},
		InstallRoot: "/opt/terrascale", StateRoot: "/var/lib/terrascale"}
	pending := pendingHostEnrollment{IdentityKey: "identity", NATSUserSeed: base64.StdEncoding.EncodeToString(seed), TLSPrivateKey: "key"}
	previous := cellspec.NetBird{Pin: netbirdArtifactTestPin(t), Enrollment: netbird.Config{
		ManagementURL: netbird.DefaultManagementURL, ManagementIP: "10.250.0.1", Region: "sa-saopaulo-1",
		SetupKeySecretID: "ocid1.vaultsecret.oc1.sa-saopaulo-1.previous"}}
	next := previous
	next.Pin.Version = "0.80.1"
	next.Pin.Archives.Arm64.URL = strings.ReplaceAll(next.Pin.Archives.Arm64.URL, "0.80.0", "0.80.1")
	next.Pin.Archives.AMD64.URL = strings.ReplaceAll(next.Pin.Archives.AMD64.URL, "0.80.0", "0.80.1")
	if err := client.ValidatePin(next.Pin); err != nil {
		t.Fatal(err)
	}
	next.Enrollment.ManagementIP = "10.250.0.2"
	next.Enrollment.SetupKeySecretID = "ocid1.vaultsecret.oc1.sa-saopaulo-1.next"
	for _, test := range []struct {
		name, operation string
		host, managed   bool
	}{
		{name: "image-default-first-enrollment", operation: "enroll"},
		{name: "credential-renewal", operation: "renew", host: true},
		{name: "renewal-with-missing-host-config", operation: "renew"},
		{name: "rename-with-existing-host-config", operation: "enroll", host: true},
		{name: "managed-history-with-missing-host-config", operation: "enroll", managed: true},
		{name: "managed-history-with-first-local-renewal", operation: "renew", managed: true},
	} {
		t.Run(test.name, func(t *testing.T) {
			root := t.TempDir()
			if err := os.Chmod(root, 0700); err != nil {
				t.Fatal(err)
			}
			before := map[string][]byte{}
			for name, value := range map[string]any{"netbird-pin.json": previous.Pin, "netbird.json": previous.Enrollment} {
				wire, err := protocol.EncodeJSON(value)
				if err != nil {
					t.Fatal(err)
				}
				before[name] = wire
				if err := os.WriteFile(filepath.Join(root, name), wire, 0644); err != nil {
					t.Fatal(err)
				}
			}
			if test.host {
				if err := os.WriteFile(filepath.Join(root, "host.json"), []byte(`{"version":2,"host":{"node":"old-node"}}`), 0600); err != nil {
					t.Fatal(err)
				}
			}
			calls := 0
			writer := func(_ context.Context, target string, pin client.Pin, cfg netbird.Config) (bool, error) {
				calls++
				if test.managed {
					return false, nil
				}
				for name, value := range map[string]any{"netbird-pin.json": pin, "netbird.json": cfg} {
					wire, err := protocol.EncodeJSON(value)
					if err != nil {
						return false, err
					}
					if err := writeAtomicHostFile(filepath.Join(target, name), wire, 0644); err != nil {
						return false, err
					}
				}
				return true, nil
			}
			response := hostenroll.Response{Operation: test.operation, NATSUserJWT: token, TLSCertificatePEM: "renewed-cert", NetBird: &next}
			if err := installHostEnrollment(t.Context(), root, root, bundle, hostboot.Descriptor{Node: "node-a"}, pending, response, uint32(os.Getuid()), writer); err != nil {
				t.Fatal(err)
			}
			called := !test.host
			if (calls == 1) != called || calls > 1 {
				t.Fatalf("NetBird bootstrap installer calls=%d, want called=%t", calls, called)
			}
			for name, value := range map[string]any{"netbird-pin.json": next.Pin, "netbird.json": next.Enrollment} {
				want := before[name]
				if called && !test.managed {
					want, err = protocol.EncodeJSON(value)
					if err != nil {
						t.Fatal(err)
					}
				}
				actual, err := os.ReadFile(filepath.Join(root, name))
				if err != nil || !bytes.Equal(actual, want) {
					t.Fatalf("enrollment bypassed fenced ownership of %s: %v", name, err)
				}
			}
			wire, err := os.ReadFile(filepath.Join(root, "host.json"))
			if err != nil {
				t.Fatal(err)
			}
			var config Config
			if err := json.Unmarshal(wire, &config); err != nil || config.Host.Node != "node-a" {
				t.Fatalf("NetBird ownership blocked host credential installation: %v", err)
			}
			if _, err := os.Stat(config.NATS.TLS.CertFile); err != nil {
				t.Fatal(err)
			}
		})
	}
}
