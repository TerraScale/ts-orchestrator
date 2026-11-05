package bootstrapmaterial

import (
	"bytes"
	"encoding/json/v2"
	"os"
	"path/filepath"
	"reflect"
	"slices"
	"strings"
	"testing"
	"time"

	"github.com/TerraScale/ts-orchestrator/internal/bootstrap"
	"github.com/TerraScale/ts-orchestrator/internal/release"
)

func testConfig() Config {
	return Config{Environment: "production", Region: "sa-saopaulo-1", Cell: "gru",
		DeploymentID: "0000000000XXVM2FA4QBBHZBKD", ClusterID: "00000000000C2KQX35BT9P1FFG", SubnetCIDR: "10.251.0.0/24",
		Slots:         []Slot{{"controller-a", "10.251.0.10"}, {"controller-b", "10.251.0.11"}, {"controller-c", "10.251.0.12"}},
		ValidityHours: 48}
}

func TestGenerateStableAndProductionValid(t *testing.T) {
	if testing.Short() {
		t.Skip("heavy provisioning, recovery or multi-node integration runs in Slow")
	}
	directory := filepath.Join(t.TempDir(), "material")
	now := time.Now().UTC().Truncate(time.Second)
	first, err := Generate(directory, testConfig(), now)
	if err != nil {
		t.Fatal(err)
	}
	if err := ValidateLive(directory, first); err != nil {
		t.Fatal(err)
	}
	second, err := Generate(directory, testConfig(), now.Add(time.Minute))
	if err != nil || !reflect.DeepEqual(first, second) {
		t.Fatalf("rerun changed material: %v", err)
	}
	if len(first.Files) != 37 || first.Public.PeerSignerPublicKey == first.Public.LedgerSignerPublicKey {
		t.Fatal("incomplete or reused signing identities")
	}
	for _, name := range expectedNames() {
		info, err := os.Lstat(filepath.Join(directory, name))
		if err != nil || info.Mode().Perm() != 0o600 {
			t.Fatalf("%s is not owner-only: %v", name, err)
		}
	}
	t.Run("prospective attestor data format only", func(t *testing.T) {
		cfg := testConfig()
		authorization := testAdmissionAuthorization(t, cfg)
		path := filepath.Join(t.TempDir(), "candidate")
		record, err := GenerateAdmissionCandidate(path, cfg, authorization, now)
		if err != nil || len(record.Files) != len(first.Files)+3 || !dedicatedAdmissionKey(record.Public) || ValidateLive(path, record) != nil {
			t.Fatalf("dedicated candidate format: %v", err)
		}
		metadata, err := os.ReadFile(filepath.Join(path, metadataName))
		if err != nil {
			t.Fatal(err)
		}
		for _, slot := range cfg.Slots {
			if !slices.ContainsFunc(record.Files, func(file File) bool {
				return file.Name == slot.Name+"-admission.key" && file.Purpose == bootstrap.SecretController && file.Slot == slot.Name
			}) {
				t.Fatalf("missing exact dedicated private slot %s", slot.Name)
			}
		}
		replayed, err := GenerateAdmissionCandidate(path, cfg, authorization, now.Add(time.Minute))
		actual, readErr := os.ReadFile(filepath.Join(path, metadataName))
		if err != nil || readErr != nil || !reflect.DeepEqual(record, replayed) || !bytes.Equal(actual, metadata) {
			t.Fatalf("candidate replay changed original bytes: %v %v", err, readErr)
		}
		changed := authorization
		changed.SourceRegistrationSHA256 = strings.Repeat("b", 64)
		if _, err := GenerateAdmissionCandidate(path, cfg, changed, now); err == nil {
			t.Fatal("different authorization adopted the original candidate")
		}
		noncanonical := record
		noncanonical.Public.AdmissionAttestor.PublicKey = record.Public.LedgerSignerPublicKey[:8] + "\n" + record.Public.LedgerSignerPublicKey[8:]
		if noncanonical.Public.AdmissionAttestor.Validate() == nil || dedicatedAdmissionKey(noncanonical.Public) || ValidateAdmissionInventory(noncanonical) == nil {
			t.Fatal("noncanonical reused ledger key passed public-only inventory checks")
		}
		reused := record.Public
		reused.AdmissionAttestor.PublicKey = record.Public.LedgerSignerPublicKey
		reused.LedgerSignerPublicKey = record.Public.LedgerSignerPublicKey[:8] + "\r\n" + record.Public.LedgerSignerPublicKey[8:]
		if dedicatedAdmissionKey(reused) {
			t.Fatal("different encodings of the same issuer key defeated separation")
		}
		for name, mutate := range map[string]func(*testing.T, string, *Record){
			"wrong private key with matching digest": func(t *testing.T, p string, r *Record) {
				wire, err := os.ReadFile(filepath.Join(p, "controller-a-response.key"))
				if err != nil {
					t.Fatal(err)
				}
				if err := os.WriteFile(filepath.Join(p, "controller-a-admission.key"), wire, 0o600); err != nil {
					t.Fatal(err)
				}
				for index := range r.Files {
					if r.Files[index].Name == "controller-a-admission.key" {
						r.Files[index].SHA256 = digest(wire)
						r.Files[index].MaxBytes = int64(len(wire))
					}
				}
			},
		} {
			t.Run(name, func(t *testing.T) {
				copyPath := t.TempDir()
				entries, err := os.ReadDir(path)
				if err != nil {
					t.Fatal(err)
				}
				for _, entry := range entries {
					wire, err := os.ReadFile(filepath.Join(path, entry.Name()))
					if err != nil {
						t.Fatal(err)
					}
					if err := os.WriteFile(filepath.Join(copyPath, entry.Name()), wire, 0o600); err != nil {
						t.Fatal(err)
					}
				}
				candidate := record
				candidate.Files = slices.Clone(record.Files)
				mutate(t, copyPath, &candidate)
				wire, err := json.Marshal(candidate)
				if err != nil {
					t.Fatal(err)
				}
				if err := os.WriteFile(filepath.Join(copyPath, metadataName), wire, 0o600); err != nil {
					t.Fatal(err)
				}
				if err := os.WriteFile(filepath.Join(copyPath, readyName), []byte(digest(wire)+"\n"), 0o600); err != nil {
					t.Fatal(err)
				}
				if _, err := Load(copyPath); err == nil {
					t.Fatal("invalid dedicated material loaded")
				}
			})
		}
	})
}

func testAdmissionAuthorization(t *testing.T, cfg Config) release.AdmissionAttestorAuthorization {
	t.Helper()
	wire, err := json.Marshal(cfg, json.Deterministic(true))
	if err != nil {
		t.Fatal(err)
	}
	return release.AdmissionAttestorAuthorization{Schema: release.AdmissionAttestorAuthorizationSchema, Domain: "terrascale.release.container-admission", Action: "reserve", SourceBinding: "original-source-inventory.v1", TenancyID: "ocid1.tenancy.oc1..test", InstallationID: "0000000000YTR4D9RJ6W8NG1HC", DeploymentID: cfg.DeploymentID, ClusterID: cfg.ClusterID, Cell: strings.ToUpper(cfg.Cell), Environment: cfg.Environment, Generation: 1,
		ControllerSlots: [3]string{"controller-a", "controller-b", "controller-c"}, Roles: [3]string{"function-worker", "terrabase", "ts-auth"}, PlanSHA256: digest(wire), WorkloadGenesisSHA256: strings.Repeat("a", 64), SourceRegistrationSHA256: strings.Repeat("c", 64), SourceNamespace: "ns", SourceBucket: "gru-1-head", SourceObject: "bootstrap/bootstrap/v2/material-source/" + strings.Repeat("d", 64) + ".json"}
}
