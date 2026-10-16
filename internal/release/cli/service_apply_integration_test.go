package cli

import (
	"bytes"
	"crypto/ed25519"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json/v2"
	"errors"
	"fmt"
	"io"
	"net/http"
	"net/http/httptest"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"github.com/oracle/oci-go-sdk/v65/objectstorage"

	"github.com/TerraScale/ts-orchestrator/internal/delivery"
	"github.com/TerraScale/ts-orchestrator/internal/protocol"
	"github.com/TerraScale/ts-orchestrator/internal/release"
	"github.com/TerraScale/ts-orchestrator/internal/releasechannel"
	"github.com/TerraScale/ts-orchestrator/internal/trust"
)

// Real Go/Git artifacts, Ed25519 delegation and OCI SDK requests cross local
// filesystem and HTTP boundaries; the endpoint does not qualify live OCI.
func TestSignedServiceApplyHTTPRecovery(t *testing.T) {
	base := newApplyHTTPFixture(t)
	for _, role := range []string{"terrabase", "ts-auth"} {
		t.Run(role, func(t *testing.T) {
			f := newServiceApplyHTTPFixture(t, base, role)
			t.Run("source producer emits reusable signed bundle", func(t *testing.T) {
				f.reset("")
				wire, err := os.ReadFile(filepath.Join(f.directory, "GRU", "service.json"))
				if err != nil {
					t.Fatal(err)
				}
				var template serviceBundle
				if err := json.Unmarshal(wire, &template); err != nil {
					t.Fatal(err)
				}
				inputs := t.TempDir()
				delegationPath, migrationPath := filepath.Join(inputs, "delegation.json"), filepath.Join(inputs, "migration.json")
				writeFixtureFile(t, delegationPath, template.Delegation, 0o600)
				writeFixtureFile(t, migrationPath, template.Migration, 0o600)
				outputDirectory := t.TempDir()
				args := []string{"--dir", outputDirectory, "--binary", base.binaryPath, "--role", role,
					"--repository", "https://source.example.invalid/" + role, "--commit", base.binary.SourceRevision,
					"--source-checkout", base.sourceDir, "--environment", "production", "--root-key", base.rootPath,
					"--update-delegation", delegationPath, "--sequence-migration", migrationPath, "--signing-key", base.leafPath,
					"--production-evidence-dir", filepath.Join(f.directory, "production"), "--cell", "GRU", "--cell", "SFO", "--cell", "FRA"}
				c := command{ctx: t.Context(), output: io.Discard}
				if err := c.serviceBundleWith(args, f.env); err != nil {
					t.Fatal(err)
				}
				if err := c.serviceApplyWith([]string{"--dir", outputDirectory, "--root-key", base.rootPath, "--namespace", "ns"}, f.env); err != nil {
					t.Fatal(err)
				}
				// Renew root qualification while retaining the same durable content sequence.
				for _, cell := range []string{"FRA", "GRU", "SFO"} {
					wire, err := os.ReadFile(filepath.Join(f.directory, cell, "service.json"))
					if err != nil {
						t.Fatal(err)
					}
					var bundle serviceBundle
					if err := json.Unmarshal(wire, &bundle); err != nil {
						t.Fatal(err)
					}
					record, err := bundle.verify(t.Context(), base.roots, cell, time.Now().UTC())
					if err != nil {
						t.Fatal(err)
					}
					candidate, err := serviceProductionCandidate(bundle, record)
					if err != nil {
						t.Fatal(err)
					}
					path := filepath.Join(f.directory, "production", cell, "amd64", "production.json")
					previous, err := os.ReadFile(path)
					if err != nil {
						t.Fatal(err)
					}
					defer os.WriteFile(path, previous, 0o600)
					qualification := writeProductionEvidence(t, filepath.Join(f.directory, "production"), candidate)
					writeProductionRecord(t, path, qualification, base.rootPrivate, time.Now().UTC().Add(-30*time.Second), time.Now().UTC().Add(time.Hour))
				}
				renewedDirectory := t.TempDir()
				args[1] = renewedDirectory
				if err := c.serviceBundleWith(args, f.env); err != nil {
					t.Fatal(err)
				}
				if err := c.serviceApplyWith([]string{"--dir", renewedDirectory, "--root-key", base.rootPath, "--namespace", "ns"}, f.env); err != nil {
					t.Fatalf("renewed proof at original sequence: %v", err)
				}
				// Missing evidence must reject the exact candidate before opening the key.
				for index, argument := range args {
					if argument == "--signing-key" {
						args[index+1] = filepath.Join(inputs, "absent.key")
					}
					if argument == "--production-evidence-dir" {
						args[index+1] = t.TempDir()
					}
				}
				if err := c.serviceBundleWith(args, f.env); !errors.Is(err, release.ErrProductionQualification) {
					t.Fatalf("key read before qualification: %v", err)
				}
			})
			for _, failure := range []string{"missing", "environment", "architecture", "storage", "qualification"} {
				t.Run(failure, func(t *testing.T) {
					f.reset(failure)
					qualificationPath := filepath.Join(f.directory, "production", "SFO", "amd64", "production.json")
					proof, err := os.ReadFile(qualificationPath)
					if err != nil {
						t.Fatal(err)
					}
					if failure == "qualification" {
						if err := os.Remove(qualificationPath); err != nil {
							t.Fatal(err)
						}
					}
					var output bytes.Buffer
					c := command{ctx: t.Context(), output: &output}
					if err := c.serviceApplyWith(f.args, f.env); err == nil || !strings.Contains(err.Error(), "SFO") {
						t.Fatalf("missing independent failure: %v\n%s", err, output.String())
					}
					f.mu.Lock()
					for _, cell := range []string{"FRA", "GRU"} {
						if f.channelWrites[cell] != 1 {
							t.Errorf("healthy %s not published: %v", cell, f.channelWrites)
						}
					}
					if f.channelWrites["SFO"] != 0 {
						t.Errorf("refused region published: %v", f.channelWrites)
					}
					f.failure = ""
					f.mu.Unlock()
					if failure == "qualification" {
						if err := os.WriteFile(qualificationPath, proof, 0o600); err != nil {
							t.Fatal(err)
						}
					}
					if err := c.serviceApplyWith(f.args, f.env); err != nil {
						t.Fatalf("same signed bundle retry: %v\n%s", err, output.String())
					}
					f.mu.Lock()
					defer f.mu.Unlock()
					for _, cell := range []string{"FRA", "GRU", "SFO"} {
						if f.binaryCreates[cell] != 1 {
							t.Errorf("retry duplicated %s bytes: %v", cell, f.binaryCreates)
						}
					}
				})
			}
			t.Run("apply without source checkout or signing key", func(t *testing.T) {
				f.reset("")
				t.Setenv("PATH", t.TempDir())
				gitPath := filepath.Join(base.sourceDir, ".git")
				if err := os.Rename(gitPath, gitPath+".retained"); err != nil {
					t.Fatal(err)
				}
				defer os.Rename(gitPath+".retained", gitPath)
				if err := os.Rename(base.leafPath, base.leafPath+".retained"); err != nil {
					t.Fatal(err)
				}
				defer os.Rename(base.leafPath+".retained", base.leafPath)
				if err := (command{ctx: t.Context(), output: io.Discard}).serviceApplyWith(f.args, f.env); err != nil {
					t.Fatal(err)
				}
			})
			t.Run("regional consumer verifies root proof and retained bytes", func(t *testing.T) {
				f.reset("")
				c := command{ctx: t.Context(), output: io.Discard}
				if err := c.serviceApplyWith(f.args, f.env); err != nil {
					t.Fatal(err)
				}
				wire, err := os.ReadFile(filepath.Join(f.directory, "GRU", "service.json"))
				if err != nil {
					t.Fatal(err)
				}
				var bundle serviceBundle
				if err := json.Unmarshal(wire, &bundle); err != nil {
					t.Fatal(err)
				}
				record, err := bundle.verify(t.Context(), base.roots, "GRU", time.Now().UTC())
				if err != nil {
					t.Fatal(err)
				}
				candidate, err := serviceProductionCandidate(bundle, record)
				if err != nil {
					t.Fatal(err)
				}
				location, err := channelLocation(f.env, "GRU", "ns")
				if err != nil {
					t.Fatal(err)
				}
				if err := releasechannel.VerifyServiceQualification(t.Context(), location, base.roots, candidate, record.ProductionQualificationSHA256, time.Now().UTC()); err != nil {
					t.Fatal(err)
				}
				f.mu.Lock()
				var evidenceName string
				for name := range f.objects["GRU"] {
					if strings.Contains(name, "/qualifications/") && strings.Contains(name, "/objects/") {
						evidenceName = name
						break
					}
				}
				original := f.objects["GRU"][evidenceName]
				f.objects["GRU"][evidenceName] = []byte("tampered evidence")
				f.mu.Unlock()
				if err := releasechannel.VerifyServiceQualification(t.Context(), location, base.roots, candidate, record.ProductionQualificationSHA256, time.Now().UTC()); err == nil {
					t.Fatal("consumer admitted tampered retained evidence")
				}
				f.mu.Lock()
				f.objects["GRU"][evidenceName] = original
				f.mu.Unlock()
			})
			t.Run("expired fresh admission refuses but completed retry reuses state", func(t *testing.T) {
				f.reset("")
				path := filepath.Join(f.directory, "GRU", "service.json")
				original, err := os.ReadFile(path)
				if err != nil {
					t.Fatal(err)
				}
				defer os.WriteFile(path, original, 0o600)
				var bundle serviceBundle
				if err := json.Unmarshal(original, &bundle); err != nil {
					t.Fatal(err)
				}
				record, err := bundle.verify(t.Context(), base.roots, "GRU", time.Now().UTC())
				if err != nil {
					t.Fatal(err)
				}
				private, err := readDelegatedPrivateKey(base.leafPath)
				if err != nil {
					t.Fatal(err)
				}
				actor, err := release.DelegatedReleaseActor(private.Public().(ed25519.PublicKey))
				if err != nil {
					t.Fatal(err)
				}
				issued := time.Now().UTC().Add(-10 * time.Minute)
				// Keep the root delegation and sequence migration valid at issuance.
				delegation, err := trust.DecodeEnvelope(bundle.Delegation)
				if err != nil {
					t.Fatal(err)
				}
				delegation.IssuedAt = issued.Add(-time.Minute)
				var grant release.BinaryUpdateDelegation
				if err := json.Unmarshal(delegation.Payload, &grant); err != nil {
					t.Fatal(err)
				}
				delegation, err = release.SignUpdateDelegation(grant, delegation.IssuedAt, delegation.ExpiresAt, base.rootPrivate)
				if err != nil {
					t.Fatal(err)
				}
				bundle.Delegation, err = trust.EncodeEnvelope(delegation)
				if err != nil {
					t.Fatal(err)
				}
				migrationEnvelope, err := trust.DecodeEnvelope(bundle.Migration)
				if err != nil {
					t.Fatal(err)
				}
				var migration release.SequenceMigration
				if err := json.Unmarshal(migrationEnvelope.Payload, &migration); err != nil {
					t.Fatal(err)
				}
				migrationEnvelope, err = release.SignSequenceMigration(migration, issued.Add(-time.Minute), base.rootPrivate)
				if err != nil {
					t.Fatal(err)
				}
				bundle.Migration, err = trust.EncodeEnvelope(migrationEnvelope)
				if err != nil {
					t.Fatal(err)
				}
				migrationDigest, err := trust.Fingerprint(migrationEnvelope)
				if err != nil {
					t.Fatal(err)
				}
				record, err = delivery.NewArtifactRecord(delivery.ArtifactClaimRequest{Source: record.Source, Cell: record.Cell, Role: record.Role, Environment: record.Environment,
					ReleaseSequence: record.ReleaseSequence, SequenceMigrationSHA256: migrationDigest, ProductionQualificationSHA256: record.ProductionQualificationSHA256}, record.Digest, record.Size)
				if err != nil {
					t.Fatal(err)
				}
				codec := delivery.Ed25519Codec{Cell: record.Cell, Actor: actor, PrivateKey: private, Lifetime: 5 * time.Minute, MaxLifetime: 5 * time.Minute, Now: func() time.Time { return issued }}
				bundle.Claim, err = codec.SignArtifact(t.Context(), record)
				if err != nil {
					t.Fatal(err)
				}
				wire, err := json.Marshal(bundle)
				if err != nil {
					t.Fatal(err)
				}
				writeFixtureFile(t, path, wire, 0o600)
				c := command{ctx: t.Context(), output: io.Discard}
				if err := c.serviceApplyWith(f.args, f.env); !errors.Is(err, protocol.ErrExpired) {
					t.Fatalf("expired fresh admission: %v", err)
				}
				binary, err := os.ReadFile(base.binaryPath)
				if err != nil {
					t.Fatal(err)
				}
				f.mu.Lock()
				f.objects["GRU"][releasechannel.ServiceReleaseObject(role)] = bundle.Claim
				f.objects["GRU"][releasechannel.ServiceBinaryObject(role, record.Digest)] = binary
				f.mu.Unlock()
				if err := c.serviceApplyWith(f.args, f.env); err != nil {
					t.Fatalf("completed expired retry: %v", err)
				}
			})
			for _, tamper := range []string{"bytes", "claim", "role", "region", "migration"} {
				t.Run("reject "+tamper+" before remote writes", func(t *testing.T) {
					f.reset("")
					path := filepath.Join(f.directory, "GRU", "service.json")
					original, err := os.ReadFile(path)
					if err != nil {
						t.Fatal(err)
					}
					binaryPath := filepath.Join(f.directory, "binaries", base.binary.SHA256)
					binary, err := os.ReadFile(binaryPath)
					if err != nil {
						t.Fatal(err)
					}
					defer os.WriteFile(path, original, 0o600)
					defer os.WriteFile(binaryPath, binary, 0o600)
					var bundle serviceBundle
					if err := json.Unmarshal(original, &bundle); err != nil {
						t.Fatal(err)
					}
					switch tamper {
					case "bytes":
						changed := bytes.Clone(binary)
						changed[0] ^= 1
						if err := os.WriteFile(binaryPath, changed, 0o600); err != nil {
							t.Fatal(err)
						}
					case "claim":
						bundle.Claim = bytes.Replace(bundle.Claim, []byte(`"signature":"`), []byte(`"signature":"a`), 1)
					case "role":
						bundle.Role = "other"
					case "region":
						bundle.Cell = "SFO"
					case "migration":
						bundle.Migration = nil
					}
					wire, err := json.Marshal(bundle)
					if err != nil {
						t.Fatal(err)
					}
					if err := os.WriteFile(path, wire, 0o600); err != nil {
						t.Fatal(err)
					}
					if err := (command{ctx: t.Context(), output: io.Discard}).serviceApplyWith(f.args, f.env); err == nil {
						t.Fatal("tampered service bundle admitted")
					}
					f.mu.Lock()
					defer f.mu.Unlock()
					if len(f.channelWrites) != 0 || len(f.binaryCreates) != 0 {
						t.Fatal("local tampering detected after mutation")
					}
				})
			}
		})
	}
}

type serviceApplyHTTPFixture struct {
	*applyHTTPFixture
	directory string
	role      string
}

func newServiceApplyHTTPFixture(t *testing.T, base *applyHTTPFixture, role string) *serviceApplyHTTPFixture {
	t.Helper()
	directory := t.TempDir()
	f := &serviceApplyHTTPFixture{applyHTTPFixture: &applyHTTPFixture{binary: base.binary}, directory: directory, role: role}
	f.reset("")
	leaf, err := readDelegatedPrivateKey(base.leafPath)
	if err != nil {
		t.Fatal(err)
	}
	public := leaf.Public().(ed25519.PublicKey)
	keyID, _ := trust.KeyID(public)
	encodedPublic, _ := trust.EncodeDelegatedPublicKey(public)
	now := time.Now().UTC()
	repository := "https://source.example.invalid/" + role
	delegation, err := release.SignUpdateDelegation(release.BinaryUpdateDelegation{
		Schema: release.UpdateDelegationSchema, SubjectKeyID: keyID, SubjectPublicKey: encodedPublic,
		Environment: "production", Architectures: []string{"amd64"},
		Services:   []release.ServiceGrant{{Role: role, Repository: repository}},
		Repository: release.QualificationRepository, Workflow: release.QualificationWorkflow,
		Ref: release.LineageRef, LineageBase: base.binary.SourceRevision,
	}, now.Add(-time.Minute), now.Add(time.Hour), base.rootPrivate)
	if err != nil {
		t.Fatal(err)
	}
	delegationWire, _ := trust.EncodeEnvelope(delegation)
	migrationWire := serviceMigrationFixture(t, base, role, public, now)
	migration, err := trust.DecodeEnvelope(migrationWire)
	if err != nil {
		t.Fatal(err)
	}
	migrationDigest, err := trust.Fingerprint(migration)
	if err != nil {
		t.Fatal(err)
	}
	actor, _ := release.DelegatedReleaseActor(public)
	tree, err := release.SourceTreeDigest(t.Context(), base.sourceDir, base.binary.SourceRevision)
	if err != nil {
		t.Fatal(err)
	}
	for _, cell := range []string{"FRA", "GRU", "SFO"} {
		record, err := delivery.NewArtifactRecord(delivery.ArtifactClaimRequest{
			Source: delivery.ArtifactSource{Repository: repository, Commit: base.binary.SourceRevision, TreeDigest: tree},
			Cell:   strings.ToLower(cell), Role: role, Environment: "production", ReleaseSequence: 2,
			SequenceMigrationSHA256: migrationDigest}, base.binary.SHA256, base.binary.Bytes)
		if err != nil {
			t.Fatal(err)
		}
		codec := delivery.Ed25519Codec{Cell: record.Cell, Actor: actor, PrivateKey: leaf,
			Lifetime: 5 * time.Minute, MaxLifetime: 5 * time.Minute}
		claim, err := codec.SignArtifact(t.Context(), record)
		if err != nil {
			t.Fatal(err)
		}
		bundle := serviceBundle{Schema: serviceBundleSchema, Cell: cell, Role: role, Environment: "production",
			Architecture: "amd64", Delegation: delegationWire, Migration: migrationWire, Claim: claim}
		if err := os.MkdirAll(filepath.Join(directory, cell), 0o700); err != nil {
			t.Fatal(err)
		}
		wire, _ := json.Marshal(bundle)
		writeFixtureFile(t, filepath.Join(directory, cell, "service.json"), wire, 0o600)
		candidate, err := serviceProductionCandidate(bundle, record)
		if err != nil {
			t.Fatal(err)
		}
		qualification := writeProductionEvidence(t, filepath.Join(directory, "production"), candidate)
		writeProductionRecord(t, filepath.Join(directory, "production", cell, "amd64", "production.json"), qualification,
			base.rootPrivate, now.Add(-time.Minute), now.Add(time.Hour))
		qualificationWire, err := os.ReadFile(filepath.Join(directory, "production", cell, "amd64", "production.json"))
		if err != nil {
			t.Fatal(err)
		}
		qualificationEnvelope, err := trust.DecodeEnvelope(qualificationWire)
		if err != nil {
			t.Fatal(err)
		}
		qualificationSHA256, err := trust.Fingerprint(qualificationEnvelope)
		if err != nil {
			t.Fatal(err)
		}
		record, err = delivery.NewArtifactRecord(delivery.ArtifactClaimRequest{Source: record.Source, Cell: record.Cell, Role: record.Role, Environment: record.Environment,
			ReleaseSequence: record.ReleaseSequence, SequenceMigrationSHA256: record.SequenceMigrationSHA256, ProductionQualificationSHA256: qualificationSHA256}, record.Digest, record.Size)
		if err != nil {
			t.Fatal(err)
		}
		bundle.Claim, err = codec.SignArtifact(t.Context(), record)
		if err != nil {
			t.Fatal(err)
		}
		wire, err = json.Marshal(bundle)
		if err != nil {
			t.Fatal(err)
		}
		writeFixtureFile(t, filepath.Join(directory, cell, "service.json"), wire, 0o600)
	}
	if err := os.Mkdir(filepath.Join(directory, "binaries"), 0o700); err != nil {
		t.Fatal(err)
	}
	binary, err := os.ReadFile(base.binaryPath)
	if err != nil {
		t.Fatal(err)
	}
	writeFixtureFile(t, filepath.Join(directory, "binaries", base.binary.SHA256), binary, 0o600)
	server := httptest.NewServer(http.HandlerFunc(f.serve))
	t.Cleanup(server.Close)
	clientInterface, err := base.env.storage("GRU")
	if err != nil {
		t.Fatal(err)
	}
	client := clientInterface.(objectstorage.ObjectStorageClient)
	client.Host, client.HTTPClient = server.URL, applyHTTPDispatcher{server}
	f.args = []string{"--dir", directory, "--root-key", base.rootPath, "--namespace", "ns"}
	f.env = deployEnv{timeout: 500 * time.Millisecond, storage: func(string) (releasechannel.ObjectClient, error) { return client, nil }}
	return f
}

func (f *serviceApplyHTTPFixture) serve(w http.ResponseWriter, r *http.Request) {
	parts := strings.SplitN(r.URL.Path, "/", 7)
	if len(parts) != 7 || r.Header.Get("Authorization") == "" {
		w.WriteHeader(http.StatusBadRequest)
		return
	}
	cell, _, _ := strings.Cut(strings.ToUpper(parts[4]), "-")
	name := parts[6]
	f.mu.Lock()
	defer f.mu.Unlock()
	if f.objects[cell] == nil {
		f.objects[cell] = make(map[string][]byte)
	}
	if r.Method == http.MethodPut {
		if cell == "SFO" && f.failure == "storage" {
			w.WriteHeader(http.StatusForbidden)
			return
		}
		old, exists := f.objects[cell][name]
		if r.Header.Get("If-None-Match") == "*" && exists || r.Header.Get("If-Match") != "" && r.Header.Get("If-Match") != fmt.Sprintf("%x", len(old)) {
			w.WriteHeader(http.StatusPreconditionFailed)
			return
		}
		data, err := io.ReadAll(r.Body)
		if err != nil {
			w.WriteHeader(http.StatusBadRequest)
			return
		}
		f.objects[cell][name] = data
		if name == releasechannel.ServiceReleaseObject(f.role) {
			f.channelWrites[cell]++
		} else if strings.Contains(name, "/binaries/") {
			f.binaryCreates[cell]++
		}
		w.Header().Set("etag", fmt.Sprintf("%x", len(data)))
		return
	}
	data, exists := f.objects[cell][name]
	if name == releasechannel.StatusObject {
		status := releasechannel.Status{Schema: releasechannel.StatusSchema, Cell: cell, Environment: "production",
			Architectures: []string{"amd64"}, UpdatedAt: time.Now().UTC()}
		if cell == "SFO" {
			switch f.failure {
			case "missing":
				w.WriteHeader(http.StatusNotFound)
				return
			case "environment":
				status.Environment = "canary"
			case "architecture":
				status.Architectures = []string{"arm64"}
			}
		}
		data, _ = json.Marshal(status)
		exists = true
	}
	if name == releasechannel.ServiceStatusObject(f.role) {
		if claim, ok := f.objects[cell][releasechannel.ServiceReleaseObject(f.role)]; ok {
			issued, _ := releasechannel.ClaimIssuedAt(claim)
			binary := f.objects[cell][releasechannel.ServiceBinaryObject(f.role, f.binary.SHA256)]
			sum := sha256.Sum256(binary)
			status := releasechannel.ServiceStatus{Schema: releasechannel.ServiceStatusSchema, Cell: cell, Role: f.role,
				Digest: hex.EncodeToString(sum[:]), IssuedAt: issued, ReleaseSequence: 2, State: releasechannel.StateComplete, UpdatedAt: time.Now().UTC()}
			data, _ = json.Marshal(status)
			exists = true
		}
	}
	if !exists {
		w.WriteHeader(http.StatusNotFound)
		return
	}
	w.Header().Set("etag", fmt.Sprintf("%x", len(data)))
	w.Header().Set("Content-Type", "application/json")
	_, _ = w.Write(data)
}

func serviceMigrationFixture(t *testing.T, base *applyHTTPFixture, role string, public ed25519.PublicKey, now time.Time) []byte {
	t.Helper()
	keyID, err := trust.KeyID(public)
	if err != nil {
		t.Fatal(err)
	}
	encoded, err := trust.EncodeDelegatedPublicKey(public)
	if err != nil {
		t.Fatal(err)
	}
	migration := release.SequenceMigration{Schema: release.SequenceMigrationSchema, Namespace: "ns", Bucket: "gru-1-head", Region: "GRU",
		SignerKeyID: keyID, SignerPublicKey: encoded, Role: role, Environment: "production", SequenceFloor: 1}
	for _, cell := range []string{"FRA", "GRU", "SFO"} {
		migration.Regions = append(migration.Regions, release.SequenceFloor{Cell: cell, RunNumber: 1, IssuedAt: now.Add(-time.Minute), EvidenceSHA256: base.binary.SHA256})
	}
	envelope, err := release.SignSequenceMigration(migration, now.Add(-time.Minute), base.rootPrivate)
	if err != nil {
		t.Fatal(err)
	}
	wire, err := trust.EncodeEnvelope(envelope)
	if err != nil {
		t.Fatal(err)
	}
	return wire
}
