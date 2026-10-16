package cli

import (
	"bytes"
	"context"
	"crypto/ed25519"
	"crypto/rand"
	"crypto/rsa"
	"crypto/tls"
	"crypto/x509"
	"encoding/base64"
	"encoding/pem"
	"fmt"
	"io"
	"net"
	"net/http"
	"net/http/httptest"
	"os"
	"path/filepath"
	"strings"
	"sync"
	"testing"
	"time"

	"github.com/TerraScale/ts-orchestrator/internal/bootstrap"
	"github.com/TerraScale/ts-orchestrator/internal/bootstrapmaterial"
	"github.com/TerraScale/ts-orchestrator/internal/ociclient"
	"github.com/TerraScale/ts-orchestrator/internal/ociregion/catalog"
	"github.com/TerraScale/ts-orchestrator/internal/protocol"
	"github.com/TerraScale/ts-orchestrator/internal/region"
	"github.com/TerraScale/ts-orchestrator/internal/release"
	"github.com/TerraScale/ts-orchestrator/internal/releasechannel"
	"github.com/TerraScale/ts-orchestrator/internal/trust"
	"github.com/oracle/oci-go-sdk/v65/common"
)

// This scenario crosses the actual filesystem, OCI SDK HTTP, retained evidence,
// image signatures, automatic plan derivation and offline root CLI boundaries.
func TestFoundationPreparationSDKToOfflineCeremony(t *testing.T) {
	rootPublic, root, err := ed25519.GenerateKey(rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	roots, err := trust.ParseKeyring(rootPublic)
	if err != nil {
		t.Fatal(err)
	}
	leafPublic, leaf, err := ed25519.GenerateKey(rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	now := time.Now().UTC().Truncate(time.Second)
	host := region.FoundationHostApproval{OCPUs: 1, MemoryGB: 6, BootGB: 50, MonthlyLimitMinor: 1000}
	signers, err := protocol.EncodeJSON([]map[string]any{{"actor": "scenario", "public_key": base64.StdEncoding.EncodeToString(leafPublic), "roles": []string{"terrabase"}, "environments": []string{"production"}}})
	if err != nil {
		t.Fatal(err)
	}
	approval := region.FoundationPreparationInput{TenancyID: "ocid1.tenancy.oc1..test", ParentCompartmentID: "ocid1.compartment.oc1..parent", SharedCompartmentID: "ocid1.compartment.oc1..shared",
		Currency: "USD", MonthlyLimitMinor: 12000, InfrastructureMonthlyLimitMinor: 10000, BootstrapReservedMinor: 4000, CleanupOwner: "scenario",
		HomeStorageDomain: bootstrap.StorageDomain{Namespace: "ns", HeadBucket: "gru-1-head", LedgerBucket: "gru-1-ledger", HeadKMSKeyOCID: "ocid1.key.oc1.sa-saopaulo-1.head", LedgerKMSKeyOCID: "ocid1.key.oc1.sa-saopaulo-1.ledger", Prefix: "bootstrap"},
		SourceVaultTarget: bootstrapmaterial.VaultTarget{CompartmentOCID: "ocid1.compartment.oc1..control", VaultOCID: "ocid1.vault.oc1.sa-saopaulo-1.home", KMSKeyOCID: "ocid1.key.oc1.sa-saopaulo-1.head"},
		TrustedSigners:    signers, OCIRRepositoryName: "terrascale/terrabase", OCIRPrincipalName: "terrascale-pull", OCIRPrincipalEmail: "terrascale-pull@terrascale.tech", OCIRSecretName: "gru-orch-ocir-pull",
		GRUController: host, SFOController: host, FRAController: host, NetBirdManager: host}
	objects := map[string][]byte{}
	var mu sync.Mutex
	reads, writes := 0, 0
	server := httptest.NewTLSServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		mu.Lock()
		defer mu.Unlock()
		if !strings.HasPrefix(r.Header.Get("Authorization"), "Signature ") {
			t.Error("OCI SDK request omitted caller signature")
		}
		w.Header().Set("Content-Type", "application/json")
		if r.Method == http.MethodGet {
			reads++
		}
		switch {
		case strings.HasSuffix(r.URL.Path, "/availabilityDomains"):
			fmt.Fprint(w, `[{"name":"scenario:AD-1"}]`)
		case strings.HasSuffix(r.URL.Path, "/services"):
			fmt.Fprint(w, `[{"id":"ocid1.service.oc1..services","cidrBlock":"all-scenario-services-in-oracle-services-network"}]`)
		case r.URL.Path == "/n/ns":
			fmt.Fprint(w, `"ns"`)
		case strings.Contains(r.URL.Path, "/o/"):
			_, name, _ := strings.Cut(r.URL.Path, "/b/")
			bucket, name, _ := strings.Cut(name, "/o/")
			key := bucket + "/" + name
			if r.Method == http.MethodPut {
				writes++
				body, readErr := io.ReadAll(r.Body)
				if readErr != nil {
					t.Error(readErr)
				}
				objects[key] = body
				w.Header().Set("etag", `"fixture"`)
				return
			}
			if wire, found := objects[key]; found {
				w.Header().Set("etag", `"fixture"`)
				w.Write(wire)
				return
			}
			w.WriteHeader(http.StatusNotFound)
			fmt.Fprint(w, `{"code":"ObjectNotFound","message":"missing fixture object"}`)
		case r.URL.Path == "/n/ns/b/gru-1-head" || r.URL.Path == "/n/ns/b/gru-1-ledger":
			bucket := strings.TrimPrefix(r.URL.Path, "/n/ns/b/")
			key := approval.HomeStorageDomain.HeadKMSKeyOCID
			if bucket == "gru-1-ledger" {
				key = approval.HomeStorageDomain.LedgerKMSKeyOCID
			}
			fmt.Fprintf(w, `{"name":%q,"compartmentId":%q,"kmsKeyId":%q}`, bucket, approval.SourceVaultTarget.CompartmentOCID, key)
		default:
			t.Errorf("unexpected OCI request %s %s", r.Method, r.URL)
			w.WriteHeader(http.StatusBadRequest)
		}
	}))
	defer server.Close()
	original := http.DefaultTransport
	transport := original.(*http.Transport).Clone()
	transport.Proxy = nil
	transport.DialTLSContext = func(ctx context.Context, network, _ string) (net.Conn, error) {
		return (&tls.Dialer{Config: server.Client().Transport.(*http.Transport).TLSClientConfig}).DialContext(ctx, network, strings.TrimPrefix(server.URL, "https://"))
	}
	http.DefaultTransport = transport
	t.Cleanup(func() { http.DefaultTransport = original; transport.CloseIdleConnections() })
	key, err := rsa.GenerateKey(rand.Reader, 2048)
	if err != nil {
		t.Fatal(err)
	}
	provider := common.NewRawConfigurationProvider(approval.TenancyID, "ocid1.user.oc1..test", "sa-saopaulo-1", "test", string(pem.EncodeToMemory(&pem.Block{Type: "RSA PRIVATE KEY", Bytes: x509.MarshalPKCS1PrivateKey(key)})), nil)
	factory, err := ociclient.New(provider, ociclient.Options{Region: "sa-saopaulo-1", Retry: ociclient.RetryOptions{MaxAttempts: 1}})
	if err != nil {
		t.Fatal(err)
	}
	for _, item := range []struct{ cell, role string }{{"GRU", "controller"}, {"SFO", "controller"}, {"FRA", "controller"}, {"GRU", "netbird-manager"}} {
		image, delegation, evidence := foundationPreparationImage(t, root, leaf, roots, item.cell, item.role, now)
		bucket, err := releasechannel.BucketName(item.cell)
		if err != nil {
			t.Fatal(err)
		}
		mu.Lock()
		for digest, wire := range evidence {
			objects[bucket+"/"+releasechannel.ImageProductionEvidenceObject(digest)] = wire
		}
		mu.Unlock()
		regional, err := factory.ForRegion(catalog.OCIRegion(item.cell))
		if err != nil {
			t.Fatal(err)
		}
		client, err := regional.ObjectStorage()
		if err != nil {
			t.Fatal(err)
		}
		if err := releasechannel.PublishCurrentImage(t.Context(), releasechannel.Location{Client: client, Namespace: "ns", Bucket: bucket}, image, delegation, roots,
			releasechannel.CurrentImageExpectation{Cell: item.cell, Environment: "production", Architecture: "arm64", Role: item.role}, now); err != nil {
			t.Fatal(err)
		}
	}
	directory := t.TempDir()
	approvalPath, candidatePath := filepath.Join(directory, "approval.json"), filepath.Join(directory, "foundation.json")
	wire, err := protocol.EncodeJSON(approval)
	if err != nil {
		t.Fatal(err)
	}
	writeFixture(t, approvalPath, wire, 0o644)
	mu.Lock()
	beforeWrites := writes
	mu.Unlock()
	command := command{ctx: t.Context(), output: io.Discard}
	if err := command.prepareFoundationWith([]string{"--approval", approvalPath, "--out", candidatePath}, factory, roots); err != nil {
		t.Fatal(err)
	}
	wire, err = os.ReadFile(candidatePath)
	if err != nil {
		t.Fatal(err)
	}
	var prepared region.FoundationPreparation
	if err := protocol.DecodeStrict(wire, &prepared, maxFoundationBundleBytes); err != nil {
		t.Fatal(err)
	}
	if len(prepared.Grant.Regions) != 3 || len(prepared.Grant.InfrastructureSpend.Bootstrap.Slots) != 4 || prepared.Anchor.FoundationScope.GrantSHA256 != "" {
		t.Fatal("preparation did not preserve unsigned fixed footprint")
	}
	mu.Lock()
	observedWrites, observedReads := writes, reads
	mu.Unlock()
	if observedWrites != beforeWrites || observedReads == 0 {
		t.Fatal("preparation mutated OCI or did not read real SDK metadata")
	}
	chainPath, rootPath, privatePath := filepath.Join(directory, "root-chain.json"), filepath.Join(directory, "root.pub"), filepath.Join(directory, "root.key")
	chain, err := trust.EncodeRootChain(trust.RootChain{Version: 1})
	if err != nil {
		t.Fatal(err)
	}
	writeFixture(t, chainPath, chain, 0o644)
	publicDER, _ := x509.MarshalPKIXPublicKey(rootPublic)
	privateDER, _ := x509.MarshalPKCS8PrivateKey(root)
	writeFixture(t, rootPath, pem.EncodeToMemory(&pem.Block{Type: "PUBLIC KEY", Bytes: publicDER}), 0o644)
	writeFixture(t, privatePath, pem.EncodeToMemory(&pem.Block{Type: "PRIVATE KEY", Bytes: privateDER}), 0o600)
	outputPath := filepath.Join(directory, "signed.json")
	if err := command.signFoundationAt([]string{"--candidate", candidatePath, "--root-chain", chainPath, "--root-key", rootPath, "--signing-key", privatePath, "--out", outputPath}, now); err != nil {
		t.Fatal(err)
	}
	signed, err := os.ReadFile(outputPath)
	if err != nil {
		t.Fatal(err)
	}
	var bundle region.RetainedFoundation
	if err := protocol.DecodeStrict(signed, &bundle, maxFoundationBundleBytes); err != nil || len(bundle.AnchorWire) == 0 || len(bundle.GrantWire) == 0 || !bytes.Equal(bundle.RootChainWire, chain) {
		t.Fatalf("offline root ceremony did not return exact public signed bundle: %v", err)
	}
	t.Run("allocation cannot replace the startup recipe", func(t *testing.T) {
		prepared.Grant.InfrastructureSpend.Bootstrap.Slots[0].ProfileSHA256 = strings.Repeat("0", 64)
		wire, err := protocol.EncodeJSON(prepared)
		if err != nil {
			t.Fatal(err)
		}
		writeFixture(t, candidatePath, wire, 0o644)
		refused := filepath.Join(directory, "refused-signature.json")
		if err := command.signFoundationAt([]string{"--candidate", candidatePath, "--root-chain", chainPath, "--root-key", rootPath, "--signing-key", privatePath, "--out", refused}, now); err == nil {
			t.Fatal("different allocation profile was signed")
		}
		if _, err := os.Stat(refused); !os.IsNotExist(err) {
			t.Fatalf("rejected allocation left signed output: %v", err)
		}
	})
	t.Run("corrupt retained evidence cannot prepare a candidate", func(t *testing.T) {
		mu.Lock()
		for key := range objects {
			if strings.Contains(key, "/releases/images/production/objects/") {
				objects[key] = []byte("corrupt retained fixture evidence")
				break
			}
		}
		mu.Unlock()
		refused := filepath.Join(directory, "refused-preparation.json")
		if err := command.prepareFoundationWith([]string{"--approval", approvalPath, "--out", refused}, factory, roots); err == nil {
			t.Fatal("different retained evidence prepared a candidate")
		}
		if _, err := os.Stat(refused); !os.IsNotExist(err) {
			t.Fatalf("rejected evidence left prepared output: %v", err)
		}
	})
}

func foundationPreparationImage(t *testing.T, root, leaf ed25519.PrivateKey, roots trust.Keyring, cell, role string, now time.Time) ([]byte, []byte, map[string][]byte) {
	t.Helper()
	image := release.ImageReceipt{Schema: release.ImageSchema, SourceRevision: strings.Repeat("a", 40), GoVersion: release.DefaultGoVersion, Architecture: "arm64", BinaryBytes: 13,
		BinarySHA256: strings.Repeat("b", 64), QualificationSHA256: strings.Repeat("c", 64), BaseImageOCID: "ocid1.image.oc1." + catalog.OCIRegion(cell) + ".base", BaseImageRegion: cell,
		BaseImageSHA256: strings.Repeat("d", 64), KernelRelease: "6.1.0", KernelSHA256: strings.Repeat("e", 64), ImageFormat: "qcow2", ImageBytes: 1024,
		ImageSHA256: strings.Repeat("f", 64), OCIImageOCID: "ocid1.image.oc1." + catalog.OCIRegion(cell) + ".qualified", OCIRegion: cell}
	qualifiedRole, runtime := "orchestrator", release.ProductionRuntime
	gates := []string{"runtime-ha", "workload-safety"}
	if role == "netbird-manager" {
		qualifiedRole, runtime, gates = role, release.NetBirdProductionRuntime, []string{"netbird-foundation", "netbird-recovery"}
	}
	qualification := release.ProductionQualification{Schema: release.ProductionQualificationSchema, Candidate: release.ProductionExpectation{SourceRevision: image.SourceRevision, ArtifactSHA256: image.ImageSHA256,
		QualificationSHA256: image.QualificationSHA256, Cell: cell, Environment: "production", Architecture: image.Architecture, Role: qualifiedRole, Runtime: runtime}}
	evidence := map[string][]byte{}
	for _, gate := range gates {
		wire := []byte("test-only retained " + cell + " " + qualifiedRole + " " + gate)
		sum := digest(wire)
		evidence[sum] = wire
		qualification.Evidence = append(qualification.Evidence, release.ProductionGateEvidence{Gate: gate, SHA256: sum, Bytes: int64(len(wire)), CompletedAt: now.Add(-time.Minute)})
	}
	payload, err := trust.EncodePayload(qualification)
	if err != nil {
		t.Fatal(err)
	}
	qualified, err := trust.Sign(payload, release.ProductionQualificationScope(qualification.Candidate), now.Add(-time.Second), now.Add(time.Hour), root)
	if err != nil {
		t.Fatal(err)
	}
	proof := release.ProductionProof{Qualification: encodeEnvelope(t, qualified)}
	if role == "netbird-manager" {
		image.HostProduction = map[string]release.ProductionProof{role: proof}
	} else {
		image.Production = &proof
	}
	scope := release.ImageScope(image, "production")
	if role == "netbird-manager" {
		scope = release.NetBirdImageScope(image, "production")
	}
	public := leaf.Public().(ed25519.PublicKey)
	keyID, _ := trust.KeyID(public)
	keyWire, _ := trust.EncodeDelegatedPublicKey(public)
	delegation, err := trust.SignDelegation(trust.Delegation{SchemaVersion: trust.SchemaVersion, SubjectKeyID: keyID, SubjectPublicKey: keyWire,
		Capabilities: []trust.Capability{{Domain: scope.Domain, DeploymentID: scope.DeploymentID, Cell: scope.Cell, Environment: scope.Environment, Role: scope.Role, Slots: []string{scope.Slot}, Actions: []string{"sign"}}}}, now.Add(-time.Minute), now.Add(2*time.Hour), root)
	if err != nil {
		t.Fatal(err)
	}
	var signed trust.Envelope
	if role == "netbird-manager" {
		signed, err = release.SignNetBirdImageReceipt(image, "production", delegation, roots, leaf, now, time.Hour)
	} else {
		signed, err = release.SignImageReceipt(image, "production", delegation, roots, leaf, now, time.Hour)
	}
	if err != nil {
		t.Fatal(err)
	}
	return encodeEnvelope(t, signed), encodeEnvelope(t, delegation), evidence
}
