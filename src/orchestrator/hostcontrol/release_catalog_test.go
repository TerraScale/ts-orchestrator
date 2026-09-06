package hostcontrol

import (
	"crypto/ed25519"
	"crypto/rand"
	"encoding/json/v2"
	"golang.org/x/sys/unix"
	"os"
	"path/filepath"
	"strings"
	"testing"

	"terrascale.tech/orchestrator/src/orchestrator/hostmanifest"
	runtimeplan "terrascale.tech/orchestrator/src/orchestrator/runtime"
)

func TestSignedReleaseCatalog(t *testing.T) {
	pub, private, err := ed25519.GenerateKey(rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	release := releaseFixture(t, "1.0", strings.Repeat("c", 64))
	canonical, err := hostmanifest.CanonicalHostManifestJSON(release.Manifest)
	if err != nil {
		t.Fatal(err)
	}
	entry := ReleaseCatalogEntry{HostID: "gru-1", Architecture: "X64", Service: "terrabase", Version: "1.0", ArtifactSHA256: strings.Repeat("c", 64), ExpectedManifestSHA256: strings.Repeat("a", 64), Manifest: canonical}
	path := filepath.Join(t.TempDir(), "catalog.json")
	resolver, err := NewSignedReleaseCatalog(path, map[string]ed25519.PublicKey{"release": pub})
	if err != nil {
		t.Fatal(err)
	}
	var plan runtimeplan.HostRuntimePlan
	if err := json.Unmarshal(deliveryPlan(t, entry.ArtifactSHA256), &plan); err != nil {
		t.Fatal(err)
	}
	write := func(payload []byte) {
		t.Helper()
		data, err := json.Marshal(SignedReleaseCatalogEnvelope{KeyID: "release", Payload: payload, Signature: ed25519.Sign(private, payload)})
		if err != nil {
			t.Fatal(err)
		}
		if err := os.WriteFile(path, data, 0600); err != nil {
			t.Fatal(err)
		}
	}
	marshal := func(entries ...ReleaseCatalogEntry) []byte {
		t.Helper()
		data, err := json.Marshal(ReleaseCatalogPayload{SchemaVersion: 1, Releases: entries})
		if err != nil {
			t.Fatal(err)
		}
		return data
	}
	write(marshal(entry))
	if err := resolver.Validate(t.Context()); err != nil {
		t.Fatal(err)
	}
	got, err := resolver.ResolveRelease(t.Context(), "gru-1", plan)
	if err != nil {
		t.Fatal(err)
	}
	if got.Manifest.Components[0].Version != "1.0" || got.ExpectedManifestSHA != entry.ExpectedManifestSHA256 {
		t.Fatal("wrong release")
	}
	if _, err := resolver.ResolveRelease(t.Context(), "other-host", plan); err == nil {
		t.Fatal("accepted other host")
	}
	other := plan
	other.Architecture = runtimeplan.HostArchitectureArm64
	if _, err := resolver.ResolveRelease(t.Context(), "gru-1", other); err == nil {
		t.Fatal("accepted other architecture")
	}
	other = plan
	other.ArtifactDigest.Value = strings.Repeat("d", 64)
	if _, err := resolver.ResolveRelease(t.Context(), "gru-1", other); err == nil {
		t.Fatal("accepted other artifact")
	}
	for _, tc := range []struct {
		name    string
		payload []byte
	}{
		{"duplicate entries", marshal(entry, entry)},
		{"unknown payload field", []byte(`{"schemaVersion":1,"releases":[],"unknown":true}`)},
		{"duplicate JSON field", []byte(`{"schemaVersion":1,"schemaVersion":1,"releases":[]}`)},
		{"trailing document", append(marshal(entry), []byte(`{}`)...)},
	} {
		t.Run(tc.name, func(t *testing.T) {
			write(tc.payload)
			if _, err := resolver.ResolveRelease(t.Context(), "gru-1", plan); err == nil {
				t.Fatal("accepted malformed signed catalog")
			}
		})
	}
	bad := entry
	bad.Version = "2.0"
	write(marshal(bad))
	if _, err := resolver.ResolveRelease(t.Context(), "gru-1", plan); err == nil {
		t.Fatal("accepted version mismatch")
	}
	write(marshal(entry))
	data, err := os.ReadFile(path)
	if err != nil {
		t.Fatal(err)
	}
	var envelope SignedReleaseCatalogEnvelope
	if err := json.Unmarshal(data, &envelope); err != nil {
		t.Fatal(err)
	}
	envelope.Payload = append(envelope.Payload, ' ')
	data, err = json.Marshal(envelope)
	if err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(path, data, 0600); err != nil {
		t.Fatal(err)
	}
	if _, err := resolver.ResolveRelease(t.Context(), "gru-1", plan); err == nil {
		t.Fatal("accepted tampered exact payload")
	}
	if err := resolver.Validate(t.Context()); err == nil {
		t.Fatal("startup accepted tampered catalog")
	}
	// Replacing the file is observed on the next resolve, without reconstructing.
	write(marshal(entry))
	if _, err := resolver.ResolveRelease(t.Context(), "gru-1", plan); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(path, []byte(strings.Repeat(" ", MaximumReleaseCatalogBytes+1)), 0600); err != nil {
		t.Fatal(err)
	}
	if _, err := resolver.ResolveRelease(t.Context(), "gru-1", plan); err == nil {
		t.Fatal("accepted oversized catalog")
	}
}

func TestReleaseCatalogValidationRejectsUnsafeSources(t *testing.T) {
	public, _, err := ed25519.GenerateKey(rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	path := filepath.Join(t.TempDir(), "catalog")
	catalog, err := NewSignedReleaseCatalog(path, map[string]ed25519.PublicKey{"key": public})
	if err != nil {
		t.Fatal(err)
	}
	if err := catalog.Validate(t.Context()); err == nil {
		t.Fatal("accepted absent source")
	}
	if err := unix.Mkfifo(path, 0600); err != nil {
		t.Fatal(err)
	}
	if err := catalog.Validate(t.Context()); err == nil {
		t.Fatal("accepted FIFO source")
	}
}
