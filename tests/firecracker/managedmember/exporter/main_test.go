package main

import (
	"crypto/ed25519"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json/v2"
	"os"
	"os/exec"
	"path/filepath"

	"testing"

	"github.com/TerraScale/ts-orchestrator/internal/host"
)

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
