package nodebootstrap_test

import (
	"bytes"
	"context"
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/x509"
	"encoding/json"
	"encoding/pem"
	"errors"
	"strings"
	. "terrascale.tech/orchestrator/src/orchestrator/hostagent"
	"terrascale.tech/orchestrator/src/orchestrator/nodeauthority"
	"terrascale.tech/orchestrator/src/orchestrator/security"
	"testing"
	"time"
)

type unusedRegionalAuthority struct{}

func (unusedRegionalAuthority) Authorize(context.Context, string, []byte) (nodeauthority.CommandAuthorization, error) {
	return nodeauthority.CommandAuthorization{}, errors.New("not used by bootstrap crypto tests")
}
func bootstrapTestGrant(t *testing.T, manifest HostManifest) (*security.CommandSignatureSigner, []byte, []byte, BootstrapGrant) {
	t.Helper()
	key, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	signer, err := security.NewCommandSignatureSignerFromKey(key)
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = signer.Close() })
	public, err := x509.MarshalPKIXPublicKey(&key.PublicKey)
	if err != nil {
		t.Fatal(err)
	}
	grant := BootstrapGrant{Version: 1, GrantID: "owner-grant-1", NodeID: "gru-1", Manifest: manifest, IssuedAt: time.Now().UTC().Add(-time.Minute), ExpiresAt: time.Now().UTC().Add(time.Hour)}
	wire, err := SignBootstrapGrant(signer, grant)
	if err != nil {
		t.Fatal(err)
	}
	return signer, pem.EncodeToMemory(&pem.Block{Type: "PUBLIC KEY", Bytes: public}), wire, grant
}
func TestBootstrapGrantBindsFullManifestHostAndFiniteCommands(t *testing.T) {
	spec := ComponentSpec{Name: "terrabase", Version: "1.0.0", ArtifactURL: "https://releases.example/terrabase", SignatureURL: "https://releases.example/terrabase.sig", Sha256: strings.Repeat("a", 64), User: "terrabase", DataVolume: "/var/lib/terrascale/terrabase", CPUWeight: 100, MemoryMaxBytes: 67108864, IOWeight: 100}
	signer, public, wire, grant := bootstrapTestGrant(t, HostManifest{Components: []ComponentSpec{spec}})
	authority, err := NewBootstrapAuthority(unusedRegionalAuthority{}, "gru-1", public, wire)
	if err != nil {
		t.Fatal(err)
	}
	commands, err := BootstrapCommands(grant)
	if err != nil || len(commands) != 3 {
		t.Fatalf("commands=%d err=%v", len(commands), err)
	}
	for _, step := range commands {
		issued := time.Now().UTC()
		signed, err := SignBootstrapCommand(signer, wire, step.Subject, step.Command, issued, issued.Add(20*time.Second))
		if err != nil {
			t.Fatal(err)
		}
		authorized, err := authority.Authorize(context.Background(), step.Subject, signed)
		if err != nil || !bytes.Equal(authorized.Command, step.Command) || authorized.Epoch != 0 || authorized.LeaseID != "" || authorized.BootstrapGrantSHA256 == "" {
			t.Fatalf("authorization=%+v err=%v", authorized, err)
		}
		if _, err = authority.Authorize(context.Background(), step.Subject+".foreign", signed); err == nil {
			t.Fatal("foreign subject admitted")
		}
		document, _ := decodeBootstrapDocument(signed)
		document.Payload = bytes.Replace(document.Payload, []byte("gru-1"), []byte("gru-2"), 1)
		tampered, _ := json.Marshal(document)
		if _, err = authority.Authorize(context.Background(), step.Subject, tampered); err == nil {
			t.Fatal("tampered command admitted")
		}
	}
	if _, err = NewBootstrapAuthority(unusedRegionalAuthority{}, "gru-2", public, wire); err == nil {
		t.Fatal("foreign host grant admitted")
	}
	for _, field := range []string{"Arguments", "Configuration", "User", "DataVolume"} {
		t.Run(field, func(t *testing.T) {
			var document bootstrapSignedDocument
			_ = json.Unmarshal(wire, &document)
			var changed BootstrapGrant
			_ = json.Unmarshal(document.Payload, &changed)
			switch field {
			case "Arguments":
				changed.Manifest.Components[0].Arguments = "--altered"
			case "User":
				changed.Manifest.Components[0].User = "foreign"
			case "DataVolume":
				changed.Manifest.Components[0].DataVolume = "/var/lib/foreign"
			case "Configuration":
				changed.Manifest.Components[0].Configuration = "altered"
			}
			document.Payload, _ = json.Marshal(changed)
			tampered, _ := json.Marshal(document)
			if _, err := NewBootstrapAuthority(unusedRegionalAuthority{}, "gru-1", public, tampered); err == nil {
				t.Fatal("modified manifest admitted")
			}
		})
	}
	other, _, _, _ := bootstrapTestGrant(t, grant.Manifest)
	issued := time.Now().UTC()
	forged, err := SignBootstrapCommand(other, wire, commands[0].Subject, commands[0].Command, issued, issued.Add(time.Second))
	if err != nil {
		t.Fatal(err)
	}
	if _, err = authority.Authorize(context.Background(), commands[0].Subject, forged); err == nil {
		t.Fatal("untrusted signer admitted")
	}
	rollback, _ := NewRollbackCommand("bootstrap-rollback", "terrabase")
	if _, err = SignBootstrapCommand(signer, wire, commands[0].Subject, rollback, issued, issued.Add(time.Second)); err == nil {
		t.Fatal("rollback admitted")
	}
	if _, err = SignBootstrapCommand(signer, wire, commands[0].Subject, commands[0].Command, issued, issued.Add(time.Minute)); err == nil {
		t.Fatal("unbounded command admitted")
	}
	expired, err := SignBootstrapCommand(signer, wire, commands[0].Subject, commands[0].Command, issued.Add(-20*time.Second), issued.Add(-time.Second))
	if err != nil {
		t.Fatal(err)
	}
	if _, err = authority.Authorize(context.Background(), commands[0].Subject, expired); err == nil {
		t.Fatal("expired command admitted")
	}
}

type bootstrapSignedDocument struct {
	Payload   json.RawMessage `json:"payload"`
	Signature []byte          `json:"signature"`
}

func decodeBootstrapDocument(wire []byte) (bootstrapSignedDocument, error) {
	var document bootstrapSignedDocument
	err := json.Unmarshal(wire, &document)
	return document, err
}
