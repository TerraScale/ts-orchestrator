package app

import (
	"bytes"
	"context"
	"crypto/ed25519"
	"encoding/base64"
	"encoding/json/v2"
	"errors"
	"io"
	"os"
	"path/filepath"
	"slices"
	"strings"
	"testing"
	"time"

	"git.terrascale.tech/TerraScale/ts-orchestrator/internal/cellspec"
	"git.terrascale.tech/TerraScale/ts-orchestrator/internal/entityid"
	"git.terrascale.tech/TerraScale/ts-orchestrator/internal/hostenroll"
	"git.terrascale.tech/TerraScale/ts-orchestrator/internal/netbird"
	"git.terrascale.tech/TerraScale/ts-orchestrator/internal/netbird/client"
	"git.terrascale.tech/TerraScale/ts-orchestrator/internal/protocol"
)

func TestHostSetupSeedsNetBirdWhenFirstInstalledResponseIsRenewal(t *testing.T) {
	ctx, cancel := context.WithTimeout(t.Context(), 30*time.Second)
	defer cancel()
	lab := startStaticEnrollmentLab(t, ctx, staticTerraBaseWorkloads())
	metadata := lab.launch(t, "ocid1.instance.oc1.sa-saopaulo-1.lost-response", "gru-1-db-1", "10.251.0.21")
	root := t.TempDir()
	image := cellspec.NetBird{Pin: netbirdArtifactTestPin(t), Enrollment: netbird.Config{
		ManagementURL: netbird.DefaultManagementURL, ManagementIP: "10.250.10.154", Region: "sa-saopaulo-1",
		SetupKeySecretID: "ocid1.vaultsecret.oc1.sa-saopaulo-1.image"}}
	desired := image
	desired.Pin.Version = "0.80.1"
	desired.Pin.Archives.Arm64.URL = strings.ReplaceAll(desired.Pin.Archives.Arm64.URL, "0.80.0", "0.80.1")
	desired.Pin.Archives.AMD64.URL = strings.ReplaceAll(desired.Pin.Archives.AMD64.URL, "0.80.0", "0.80.1")
	desired.Enrollment.ManagementIP = "10.250.10.155"
	desired.Enrollment.SetupKeySecretID = "ocid1.vaultsecret.oc1.sa-saopaulo-1.signed"
	lab.enrollment.services.current.NetBird = &desired
	for name, value := range map[string]any{"netbird-pin.json": image.Pin, "netbird.json": image.Enrollment} {
		wire, err := protocol.EncodeJSON(value)
		if err != nil {
			t.Fatal(err)
		}
		if err := writeAtomicHostFile(filepath.Join(root, name), wire, 0644); err != nil {
			t.Fatal(err)
		}
	}
	pending, err := readOrCreateHostEnrollment(t.Context(), root, metadata, nil)
	if err != nil {
		t.Fatal(err)
	}
	request, err := parsePersistedHostRequest(pending.Request)
	if err != nil {
		t.Fatal(err)
	}
	identity, err := base64.StdEncoding.DecodeString(pending.IdentityKey)
	if err != nil {
		t.Fatal(err)
	}
	defer clear(identity)
	request.IssuedAt = time.Now().UTC().Add(-6 * time.Minute)
	if err := request.Sign(ed25519.PrivateKey(identity)); err != nil {
		t.Fatal(err)
	}
	pending.Request, err = protocol.EncodeJSON(request)
	if err != nil {
		t.Fatal(err)
	}
	wire, err := protocol.EncodeJSON(pending)
	if err != nil {
		t.Fatal(err)
	}
	if err := writeAtomicHostFile(filepath.Join(root, pendingHostEnrollmentFile), wire, 0600); err != nil {
		t.Fatal(err)
	}
	var operations []string
	lost, installed := true, 0
	runner := hostSetupRuntime{ownerUID: uint32(os.Geteuid()),
		post: func(_ context.Context, _ hostenroll.PublicBundle, wire []byte) ([]byte, error) {
			request, err := parsePersistedHostRequest(wire)
			if err != nil {
				return nil, err
			}
			operations = append(operations, request.Operation)
			response, err := lab.post(wire, "10.251.0.21")
			if err == nil && lost {
				lost = false
				return nil, errors.New("test initial response lost after commit")
			}
			return response, err
		},
		netbird: func(_ context.Context, target string, pin client.Pin, cfg netbird.Config) (bool, error) {
			installed++
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
		}}
	if err := runHostSetupWithMetadata(ctx, lab.bundle, metadata, root, io.Discard, runner); err == nil || !strings.Contains(err.Error(), "response lost") {
		t.Fatalf("first setup did not leave its committed response unapplied: %v", err)
	}
	if _, err := os.Stat(filepath.Join(root, "host.json")); !errors.Is(err, os.ErrNotExist) || installed != 0 {
		t.Fatalf("lost response installed local config: bootstrap calls=%d err=%v", installed, err)
	}
	grant, revision, err := lab.enrollment.grants.Read(ctx, metadata.InstanceID)
	if err != nil || !bytes.Equal(grant.Request, pending.Request) || len(grant.Response) == 0 {
		t.Fatalf("initial response was not durably committed: %v", err)
	}
	// Age the signed cached response without sleeping through its lifetime.
	var expired hostenroll.Response
	if err := json.Unmarshal(grant.Response, &expired); err != nil {
		t.Fatal(err)
	}
	expired.ExpiresAt = time.Now().Add(-time.Minute)
	if err := expired.Sign(lab.enrollment.responseKey); err != nil {
		t.Fatal(err)
	}
	grant.Response, err = protocol.EncodeJSON(expired)
	if err != nil {
		t.Fatal(err)
	}
	wire, err = json.Marshal(grant)
	if err != nil {
		t.Fatal(err)
	}
	kv, err := lab.js.KeyValue(ctx, hostenroll.GrantBucket)
	if err != nil {
		t.Fatal(err)
	}
	key := entityid.Derive("host-enrollment", metadata.InstanceID)
	if _, err := kv.Update(ctx, key, wire, revision); err != nil {
		t.Fatal(err)
	}
	if err := runHostSetupWithMetadata(ctx, lab.bundle, metadata, root, io.Discard, runner); err != nil {
		t.Fatalf("renewal could not finish the lost initial enrollment: %v", err)
	}
	if installed != 1 || !slices.Equal(operations, []string{"enroll", "enroll", "renew"}) {
		t.Fatalf("first renewal did not install signed bootstrap inputs: operations=%v installs=%d", operations, installed)
	}
	body, err := os.ReadFile(filepath.Join(root, "netbird-pin.json"))
	var read client.Pin
	if err != nil || json.Unmarshal(body, &read, json.RejectUnknownMembers(true)) != nil || read != desired.Pin {
		t.Fatalf("first renewal kept the image pin instead of its signed pin: %v", err)
	}
	config, err := netbird.LoadConfig(filepath.Join(root, "netbird.json"))
	if err != nil || config.ManagementIP != desired.Enrollment.ManagementIP || config.SetupKeySecretID != desired.Enrollment.SetupKeySecretID {
		t.Fatalf("first renewal kept the image enrollment settings: %v", err)
	}
	before := map[string][]byte{}
	for _, name := range []string{"netbird-pin.json", "netbird.json"} {
		before[name], err = os.ReadFile(filepath.Join(root, name))
		if err != nil {
			t.Fatal(err)
		}
	}
	amended := desired
	amended.Enrollment.ManagementIP = "10.250.10.156"
	lab.enrollment.services.mu.Lock()
	lab.enrollment.services.current.NetBird = &amended
	lab.enrollment.services.mu.Unlock()
	if err := runHostSetupWithMetadata(ctx, lab.bundle, metadata, root, io.Discard, runner); err != nil {
		t.Fatalf("subsequent credential renewal failed: %v", err)
	}
	if installed != 1 || !slices.Equal(operations, []string{"enroll", "enroll", "renew", "renew"}) {
		t.Fatalf("credential renewal reseeded bootstrap inputs: operations=%v installs=%d", operations, installed)
	}
	for name, expected := range before {
		actual, err := os.ReadFile(filepath.Join(root, name))
		if err != nil || !bytes.Equal(actual, expected) {
			t.Fatalf("credential renewal replaced rollout-owned %s: %v", name, err)
		}
	}
}
