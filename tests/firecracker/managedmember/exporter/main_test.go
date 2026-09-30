package main

import (
	"crypto/ed25519"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json/v2"
	"os"
	"os/exec"
	"path/filepath"
	"strings"
	"testing"

	"git.terrascale.tech/TerraScale/ts-orchestrator/internal/host"
	"git.terrascale.tech/TerraScale/ts-orchestrator/internal/managedmaterial"
)

func TestAuthoritySeedRequiresProtectedFileAndIndependentPin(t *testing.T) {
	seed := make([]byte, ed25519.SeedSize)
	for index := range seed {
		seed[index] = byte(index)
	}
	private := ed25519.NewKeyFromSeed(seed)
	publicHash := sha256.Sum256(private.Public().(ed25519.PublicKey))
	path := filepath.Join(t.TempDir(), "authority.seed")
	if err := os.WriteFile(path, seed, 0600); err != nil {
		t.Fatal(err)
	}
	cfg := options{authoritySeedFile: path, authorityPublicSHA256: hex.EncodeToString(publicHash[:])}
	loaded, err := loadAuthoritySigner(cfg)
	if err != nil {
		t.Fatal(err)
	}
	if !loaded.Equal(private) {
		t.Fatal("loaded authority key differs from pinned seed")
	}
	clear(loaded)
	clear(private)

	badPin := cfg
	badPin.authorityPublicSHA256 = hex.EncodeToString(make([]byte, sha256.Size))
	if _, err := loadAuthoritySigner(badPin); err == nil {
		t.Fatal("accepted authority seed with mismatched public key pin")
	}

	if err := os.Chmod(path, 0644); err != nil {
		t.Fatal(err)
	}
	if _, err := loadAuthoritySigner(cfg); err == nil {
		t.Fatal("accepted group-readable authority seed")
	}
	if err := os.Chmod(path, 0600); err != nil {
		t.Fatal(err)
	}
	link := filepath.Join(filepath.Dir(path), "authority.link")
	if err := os.Symlink(path, link); err != nil {
		t.Fatal(err)
	}
	cfg.authoritySeedFile = link
	if _, err := loadAuthoritySigner(cfg); err == nil {
		t.Fatal("accepted symlinked authority seed")
	}
}

func TestEmptyCatalogSchemaDigest(t *testing.T) {
	catalog, err := managedmaterial.InitialCatalog(collectionID, nil)
	if err != nil {
		t.Fatal(err)
	}
	const expected = "b659dc901eba8b60728633fc4cbd0d532e179f2307784ba518b5a1baffb9fdbb"
	if got := catalog.SchemaDigest; got != expected {
		t.Fatalf("empty schema digest = %s, want %s", got, expected)
	}
}

func TestLocalS3Target(t *testing.T) {
	valid := options{s3Endpoint: fixtureS3Endpoint, s3Bucket: "managed-member-test", s3Region: fixtureS3Region}
	target, config, digest, err := localS3Target(valid)
	if err != nil {
		t.Fatal(err)
	}
	if target.Credential.SecretOCID != fixtureS3SecretOCID || target.Credential.VersionNumber != 1 {
		t.Fatalf("unexpected credential reference: %+v", target.Credential)
	}
	if want, err := target.Digest(); err != nil || digest != want {
		t.Fatalf("target digest = %q, want %q: %v", digest, want, err)
	}
	var decoded map[string]any
	if err := json.Unmarshal(config, &decoded); err != nil {
		t.Fatal(err)
	}
	if len(decoded) != 5 || decoded["version"] != float64(1) || decoded["ack_profile"] != "object_durable" ||
		decoded["endpoint"] != valid.s3Endpoint || decoded["bucket"] != valid.s3Bucket || decoded["region"] != fixtureS3Region {
		t.Fatalf("unexpected nonsecret config: %s", config)
	}
	for name, change := range map[string]func(*options){
		"missing endpoint":  func(cfg *options) { cfg.s3Endpoint = "" },
		"HTTP endpoint":     func(cfg *options) { cfg.s3Endpoint = "http://rustfs.terrabase.test:9000" },
		"other HTTPS host":  func(cfg *options) { cfg.s3Endpoint = "https://other.terrabase.test:9000" },
		"endpoint path":     func(cfg *options) { cfg.s3Endpoint += "/bucket" },
		"wrong region":      func(cfg *options) { cfg.s3Region = "us-east-1" },
		"missing bucket":    func(cfg *options) { cfg.s3Bucket = "" },
		"short bucket":      func(cfg *options) { cfg.s3Bucket = "ab" },
		"long bucket":       func(cfg *options) { cfg.s3Bucket = strings.Repeat("a", 64) },
		"uppercase bucket":  func(cfg *options) { cfg.s3Bucket = "Managed-member-test" },
		"underscore bucket": func(cfg *options) { cfg.s3Bucket = "managed_member_test" },
		"double dot bucket": func(cfg *options) { cfg.s3Bucket = "managed..member.test" },
		"leading hyphen":    func(cfg *options) { cfg.s3Bucket = "-managed-member" },
		"trailing dot":      func(cfg *options) { cfg.s3Bucket = "managed-member." },
	} {
		t.Run(name, func(t *testing.T) {
			invalid := valid
			change(&invalid)
			if _, _, _, err := localS3Target(invalid); err == nil {
				t.Fatal("accepted invalid local S3 target")
			}
		})
	}
}

func TestExportMemberIncludesLiveS3MaterialAndPins(t *testing.T) {
	if _, err := exec.LookPath("mkfs.ext4"); err != nil {
		t.Skip("mkfs.ext4 is unavailable")
	}
	target, config, targetDigest, err := localS3Target(options{
		s3Endpoint: fixtureS3Endpoint, s3Bucket: "managed-member-test", s3Region: fixtureS3Region,
	})
	if err != nil {
		t.Fatal(err)
	}
	member := memberCertificate{chain: []byte("server chain"), key: []byte("server key"), leaf: []byte("server leaf")}
	client := memberCertificate{chain: []byte("client chain"), key: []byte("client key")}
	packet, err := exportMember(t.TempDir(), 0, []byte("authority"), make([]byte, ed25519.PublicKeySize),
		"configuration ID", "schema digest", member, client, []byte("member CA"), []byte("client CA"),
		[]byte("registry"), "token", "source digest", target, config, targetDigest)
	if err != nil {
		t.Fatal(err)
	}
	if len(packet.Inputs) != 15 {
		t.Fatalf("exported %d inputs, want 15", len(packet.Inputs))
	}
	entry := packet.Inputs["signed_v2_s3_config"]
	if filepath.Base(entry.Path) != "signed-v2-s3-config.json" {
		t.Fatalf("unexpected config path: %q", entry.Path)
	}
	stored, err := os.ReadFile(entry.Path)
	if err != nil {
		t.Fatal(err)
	}
	hash := sha256.Sum256(config)
	if string(stored) != string(config) || entry.SHA256 != hex.EncodeToString(hash[:]) {
		t.Fatal("exported S3 config differs from its pin")
	}
	runtime, ok := packet.GuestConfig["runtime"].(host.ManagedRuntimePins)
	if !ok || runtime.LiveS3ConfigSHA256 != entry.SHA256 || runtime.LiveS3TargetSHA256 != targetDigest ||
		runtime.LiveS3Credential != target.Credential {
		t.Fatalf("runtime S3 pins differ from exported material: %+v", packet.GuestConfig["runtime"])
	}
	encoded, err := json.Marshal(packet.GuestConfig)
	if err != nil {
		t.Fatal(err)
	}
	var wire struct {
		Runtime struct {
			ConfigSHA256 string `json:"live_s3_config_sha256"`
			TargetSHA256 string `json:"live_s3_target_sha256"`
			Credential   struct {
				SecretOCID    string `json:"secret_ocid"`
				VersionNumber int64  `json:"version_number"`
			} `json:"live_s3_credential"`
		} `json:"runtime"`
	}
	if err := json.Unmarshal(encoded, &wire); err != nil {
		t.Fatal(err)
	}
	if wire.Runtime.ConfigSHA256 != entry.SHA256 || wire.Runtime.TargetSHA256 != targetDigest ||
		wire.Runtime.Credential.SecretOCID != fixtureS3SecretOCID || wire.Runtime.Credential.VersionNumber != 1 {
		t.Fatalf("runtime wire pins differ from exported material: %s", encoded)
	}
}
