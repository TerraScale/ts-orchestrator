package attempt

import (
	"bytes"
	"context"
	"crypto/ed25519"
	"crypto/rand"
	"crypto/rsa"
	"crypto/sha256"
	"crypto/x509"
	"encoding/hex"
	"encoding/json/v2"
	"encoding/pem"
	"fmt"
	"io"
	"net/http"
	"net/http/httptest"
	"os"
	"path/filepath"
	"slices"
	"strings"
	"sync/atomic"
	"testing"
	"time"

	"github.com/TerraScale/ts-orchestrator/internal/ociclient"
	"github.com/TerraScale/ts-orchestrator/internal/ociregion/imageimport/imageimporttest"
	"github.com/TerraScale/ts-orchestrator/internal/release"
	releasecli "github.com/TerraScale/ts-orchestrator/internal/release/cli"
	"github.com/TerraScale/ts-orchestrator/internal/trust"
	"github.com/oracle/oci-go-sdk/v65/common"
)

func TestAttemptFinalImageQualificationPrecedesOCIMutations(t *testing.T) {
	if os.Getenv("TS_ATTEMPT_IMAGE_PROOF_PROCESS") == "1" {
		separator := slices.Index(os.Args, "--")
		if separator < 0 {
			os.Exit(2)
		}
		args := os.Args[separator+1:]
		var err error
		switch {
		case len(args) > 1 && args[0] == "release":
			err = releasecli.Run(t.Context(), args[1:], os.Stdout)
		default:
			err = fmt.Errorf("unexpected project CLI invocation: %v", args)
		}
		if err != nil {
			fmt.Fprintln(os.Stderr, err)
			os.Exit(1)
		}
		os.Exit(0)
	}
	ociKey, err := rsa.GenerateKey(rand.Reader, 2048)
	if err != nil {
		t.Fatal(err)
	}
	ociPEM := string(pem.EncodeToMemory(&pem.Block{Type: "RSA PRIVATE KEY", Bytes: x509.MarshalPKCS1PrivateKey(ociKey)}))
	for _, phase := range []string{"image", "members"} {
		for _, scenario := range []string{"qualified disk", "different disk", "missing retained evidence", "unsigned proof", "expired proof", "old signed receipt without proof", "wrong OCI image", "wrong environment", "wrong cell", "wrong architecture"} {
			if phase == "image" && (scenario == "old signed receipt without proof" || scenario == "wrong OCI image") {
				continue
			}
			t.Run(phase+"/"+scenario, func(t *testing.T) {
				ctx, cancel := context.WithTimeout(t.Context(), 10*time.Second)
				defer cancel()
				directory := t.TempDir()
				write := func(path string, data []byte) {
					t.Helper()
					if err := os.MkdirAll(filepath.Dir(path), 0700); err != nil {
						t.Fatal(err)
					}
					if err := os.WriteFile(path, data, 0600); err != nil {
						t.Fatal(err)
					}
				}
				marshal := func(value any) []byte {
					t.Helper()
					data, err := json.Marshal(value)
					if err != nil {
						t.Fatal(err)
					}
					return data
				}
				hash := func(data []byte) string {
					sum := sha256.Sum256(data)
					return hex.EncodeToString(sum[:])
				}
				public, private, err := ed25519.GenerateKey(rand.Reader)
				if err != nil {
					t.Fatal(err)
				}
				der, err := x509.MarshalPKIXPublicKey(public)
				if err != nil {
					t.Fatal(err)
				}
				root := filepath.Join(directory, "root.pem")
				write(root, pem.EncodeToMemory(&pem.Block{Type: "PUBLIC KEY", Bytes: der}))
				work := filepath.Join(directory, "work")
				source := strings.Repeat("a", 40)
				config := filepath.Join(directory, "attempt.json")
				write(config, marshal(map[string]any{"workdir": work, "deployment_id": "0000000000F9PR1WNVDTEXS31Z",
					"prefix": "bootstrap/proof", "namespace": "ns", "tools": map[string]any{},
					"orchestrator": map[string]any{"source_revision": source, "ci_run_id": 42},
					"image":        map[string]any{"bucket": "images"}, "trust": map[string]any{"root_public": root}}))
				var output bytes.Buffer
				a, err := New(ctx, config, &output, &output)
				if err != nil {
					t.Fatal(err)
				}
				write(a.Plan(), marshal(map[string]any{"cell": "GRU", "hosts": []map[string]string{{"slot": "member-a"}},
					"resource_ids": map[string]string{"control_compartment": "ocid1.compartment.oc1..proof", "workload_compartment": "ocid1.compartment.oc1..workload"}}))
				disk := []byte("QFI\xfbretained final disk bytes")
				qcow2 := a.Path("image", "terrascale-arm64.qcow2")
				write(qcow2, disk)
				write(a.Path("image", "image-qualification.json"), marshal(map[string]any{"schema": "terrascale.image.qualification.v2",
					"image": map[string]string{"architecture": "arm64", "sha256": hash(disk)}}))
				qualification := release.Qualification{Schema: release.QualificationSchema, Repository: release.QualificationRepository,
					SourceRevision: source, SourceTree: strings.Repeat("b", 40), GoVersion: release.DefaultGoVersion,
					GoModSHA256: strings.Repeat("c", 64), GoSumSHA256: strings.Repeat("d", 64),
					Verification: release.QualificationCheck{Workflow: release.QualificationWorkflow, Job: release.QualificationJob,
						RunID: 42, RunNumber: 1, Conclusion: "success"},
					Artifacts: []release.QualifiedArtifact{
						{Architecture: "amd64", Name: "terrascale-orchestrator-linux-amd64", Bytes: 1, SHA256: strings.Repeat("e", 64)},
						{Architecture: "arm64", Name: "terrascale-orchestrator-linux-arm64", Bytes: 1, SHA256: strings.Repeat("f", 64)},
					}}
				qualificationWire := marshal(qualification)
				write(a.Path("release", "qualification.json"), qualificationWire)
				expected := release.ProductionExpectation{SourceRevision: source, ArtifactSHA256: hash(disk),
					QualificationSHA256: hash(qualificationWire), Cell: "GRU", Environment: "canary",
					Runtime: release.ProductionRuntime, Architecture: "arm64", Role: "orchestrator"}
				switch scenario {
				case "different disk":
					expected.ArtifactSHA256 = strings.Repeat("0", 64)
				case "wrong environment":
					expected.Environment = "production"
				case "wrong cell":
					expected.Cell = "SFO"
				case "wrong architecture":
					expected.Architecture = "amd64"
				}
				proof := release.ProductionQualification{Schema: release.ProductionQualificationSchema, Candidate: expected}
				for _, gate := range []string{"runtime-ha", "workload-safety"} {
					data := []byte(gate + " retained gate result")
					digest := hash(data)
					proof.Evidence = append(proof.Evidence, release.ProductionGateEvidence{Gate: gate, SHA256: digest,
						Bytes: int64(len(data)), CompletedAt: time.Now().Add(-2 * time.Hour)})
					if scenario != "missing retained evidence" {
						write(a.Path("release", "image-production", "objects", digest), data)
					}
				}
				payload, err := trust.EncodePayload(proof)
				if err != nil {
					t.Fatal(err)
				}
				issued, expires := time.Now().Add(-time.Minute), time.Now().Add(time.Hour)
				if scenario == "expired proof" {
					issued, expires = time.Now().Add(-2*time.Hour), time.Now().Add(-time.Hour)
				}
				envelope, err := trust.Sign(payload, release.ProductionQualificationScope(expected), issued, expires, private)
				if err != nil {
					t.Fatal(err)
				}
				proofWire, err := trust.EncodeEnvelope(envelope)
				if err != nil {
					t.Fatal(err)
				}
				if scenario == "unsigned proof" {
					proofWire = payload
				}
				write(a.Path("release", "image-production", "GRU", "arm64", "production.json"), proofWire)
				imageID := "ocid1.image.oc1.sa-saopaulo-1.proof"
				if phase == "members" {
					receipt := release.ImageReceipt{Schema: release.ImageSchema, SourceRevision: source, GoVersion: release.DefaultGoVersion,
						Architecture: "arm64", BinaryBytes: 1, BinarySHA256: strings.Repeat("f", 64), QualificationSHA256: hash(qualificationWire),
						BaseImageOCID: "ocid1.image.oc1.sa-saopaulo-1.base", BaseImageRegion: "GRU", BaseImageSHA256: strings.Repeat("1", 64),
						KernelRelease: "6.1.0-proof", KernelSHA256: strings.Repeat("2", 64), ImageFormat: "qcow2", ImageBytes: int64(len(disk)),
						ImageSHA256: hash(disk), OCIImageOCID: imageID, OCIRegion: "GRU", Production: &release.ProductionProof{Qualification: proofWire}}
					if scenario == "old signed receipt without proof" {
						receipt.Production = nil
					}
					public, signer, err := ed25519.GenerateKey(rand.Reader)
					if err != nil {
						t.Fatal(err)
					}
					keyID, err := trust.KeyID(public)
					if err != nil {
						t.Fatal(err)
					}
					publicWire, err := trust.EncodeDelegatedPublicKey(public)
					if err != nil {
						t.Fatal(err)
					}
					scope := release.ImageScope(receipt, "canary")
					delegation, err := trust.SignDelegation(trust.Delegation{SchemaVersion: trust.SchemaVersion, SubjectKeyID: keyID, SubjectPublicKey: publicWire,
						Capabilities: []trust.Capability{{Domain: scope.Domain, DeploymentID: scope.DeploymentID, Cell: scope.Cell,
							Environment: scope.Environment, Role: scope.Role, Slots: []string{scope.Slot}, Actions: []string{"sign"}}}},
						time.Now().Add(-time.Hour), time.Now().Add(24*time.Hour), private)
					if err != nil {
						t.Fatal(err)
					}
					delegationWire, err := trust.EncodeEnvelope(delegation)
					if err != nil {
						t.Fatal(err)
					}
					write(a.Path("image", "image-delegation.signed.json"), delegationWire)
					receiptPayload, err := trust.EncodePayload(receipt)
					if err != nil {
						t.Fatal(err)
					}
					// An older delegated signer can produce a valid signature without a production proof.
					signed, err := trust.Sign(receiptPayload, scope, time.Now().Add(-time.Minute), time.Now().Add(time.Hour), signer)
					if err != nil {
						t.Fatal(err)
					}
					receiptWire, err := trust.EncodeEnvelope(signed)
					if err != nil {
						t.Fatal(err)
					}
					write(a.ImageReceipt(), receiptWire)
					if scenario == "wrong OCI image" {
						imageID = "ocid1.image.oc1.sa-saopaulo-1.other"
					}
					write(a.Path("image", "import.json"), marshal(map[string]string{"image_id": imageID}))
				}
				var requests, mutations atomic.Int64
				provider := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
					requests.Add(1)
					if !strings.HasPrefix(r.Header.Get("Authorization"), "Signature ") {
						t.Error("OCI boundary received an unsigned request")
					}
					if r.Method != http.MethodGet {
						mutations.Add(1)
					}
					w.Header().Set("Content-Type", "application/json")
					if phase == "members" && r.Method == http.MethodGet && r.URL.Path == "/20160918/instances" {
						_, _ = io.WriteString(w, "[]")
						return
					}
					w.WriteHeader(http.StatusForbidden)
					_, _ = io.WriteString(w, `{"code":"NotAuthorizedOrNotFound","message":"isolated admission observation"}`)
				}))
				defer provider.Close()
				a.imageImporter = imageimporttest.Importer(provider.URL)
				executable, err := os.Executable()
				if err != nil {
					t.Fatal(err)
				}
				write(a.BootstrapTool(), []byte("#!/bin/sh\nexec \"$TS_ATTEMPT_IMAGE_PROOF_EXECUTABLE\" -test.run '^TestAttemptFinalImageQualificationPrecedesOCIMutations$' -- \"$@\"\n"))
				if err := os.Chmod(a.BootstrapTool(), 0700); err != nil {
					t.Fatal(err)
				}
				a.Executable = a.BootstrapTool()
				a.Env = append(a.Env, "TS_ATTEMPT_IMAGE_PROOF_PROCESS=1", "TS_ATTEMPT_IMAGE_PROOF_EXECUTABLE="+executable)
				if phase == "members" {
					factory, err := ociclient.New(common.NewRawConfigurationProvider("ocid1.tenancy.oc1..proof", "ocid1.user.oc1..proof", "sa-saopaulo-1",
						"00:00:00:00:00:00:00:00:00:00:00:00:00:00:00:00", ociPEM, nil),
						ociclient.Options{Region: "sa-saopaulo-1", Retry: ociclient.RetryOptions{MaxAttempts: 1}})
					if err != nil {
						t.Fatal(err)
					}
					compute, err := factory.Compute()
					if err != nil {
						t.Fatal(err)
					}
					compute.Host = provider.URL
					a.Cloud = &sdkCloud{compute: compute}
					runner := a.Runner
					a.Runner = func(ctx context.Context, command Command) (string, error) {
						args := command.Args
						if slices.Contains(args, "preview") {
							index := slices.Index(args, "--out")
							if index < 0 || index+1 >= len(args) {
								return "", fmt.Errorf("preview fixture lacks output: %v", args)
							}
							out := args[index+1]
							switch {
							case slices.Contains(args, "inventory"):
								return "", os.WriteFile(out, []byte("{}"), 0600)
							case slices.Contains(args, "admit"):
								return "", os.WriteFile(out, marshal(map[string]string{"expires_at": time.Now().Add(time.Hour).Format(time.RFC3339Nano)}), 0600)
							case slices.Contains(args, "member-launch"):
								launch := map[string]any{"availabilityDomain": "AD-1", "faultDomain": "FAULT-DOMAIN-1", "compartmentId": "ocid1.compartment.oc1..workload",
									"displayName": "gru-1-db-1", "shape": "VM.Standard.A1.Flex", "shapeConfig": map[string]any{"ocpus": 1, "memoryInGBs": 6},
									"sourceDetails": map[string]any{"sourceType": "image", "imageId": imageID, "bootVolumeSizeInGBs": 50, "bootVolumeVpusPerGB": 10},
									"subnetId":      "ocid1.subnet.oc1..proof", "privateIp": "10.0.0.11", "nsgIds": []string{"ocid1.networksecuritygroup.oc1..proof"},
									"assignPublicIp": false, "metadata": map[string]string{"user_data": "Y2xvdWQtaW5pdA=="}, "freeformTags": map[string]string{"BootstrapCreateKey": "member-a"}}
								return "", os.WriteFile(out, marshal(launch), 0600)
							}
						}
						return runner(ctx, command)
					}
				}
				if err := a.Phase(phase); err == nil {
					t.Fatalf("attempt unexpectedly passed isolated OCI refusal: %s", output.String())
				}
				if scenario == "qualified disk" {
					wantRequests, wantMutations := int64(1), int64(0)
					if phase == "members" {
						wantRequests, wantMutations = 2, 1
					}
					if requests.Load() != wantRequests || mutations.Load() != wantMutations || !strings.Contains(output.String()+a.Err().Error(), "isolated admission observation") {
						t.Fatalf("qualified disk did not reach signed SDK boundary: requests=%d mutations=%d err=%v\n%s", requests.Load(), mutations.Load(), a.Err(), output.String())
					}
				} else {
					wantRequests := int64(0)
					if phase == "members" {
						wantRequests = 1
					}
					if requests.Load() != wantRequests || mutations.Load() != 0 || !strings.Contains(output.String(), "verify-image-production") {
						t.Fatalf("unqualified disk reached OCI mutation: requests=%d mutations=%d err=%v\n%s", requests.Load(), mutations.Load(), a.Err(), output.String())
					}
				}
			})
		}
	}
}
