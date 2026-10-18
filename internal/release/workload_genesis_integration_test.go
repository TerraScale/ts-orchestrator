package release

import (
	"bytes"
	"context"
	"crypto/ed25519"
	"crypto/rand"
	"crypto/rsa"
	"crypto/sha256"
	"crypto/x509"
	"encoding/base64"
	"encoding/json/v2"
	"encoding/pem"
	"fmt"
	"io"
	"net/http"
	"net/http/httptest"
	"os"
	"path/filepath"
	"strings"
	"sync"
	"sync/atomic"
	"testing"
	"time"

	"github.com/TerraScale/ts-orchestrator/internal/entityid"
	"github.com/TerraScale/ts-orchestrator/internal/trust"
	"github.com/oracle/oci-go-sdk/v65/common"
	"github.com/oracle/oci-go-sdk/v65/objectstorage"
)

// This wire fixture avoids the region -> release import cycle. Every original
// entry and every role's complete delegation is inside the same root signature.
type workloadGenesisGrantFixture struct {
	SchemaVersion      int                               `json:"schemaVersion"`
	Generation         uint64                            `json:"generation"`
	TenancyID          string                            `json:"tenancyId"`
	InstallationID     string                            `json:"installationId"`
	CleanupOwner       string                            `json:"cleanupOwner"`
	WorkloadGenesis    []WorkloadGenesis                 `json:"workloadGenesis"`
	Regions            []workloadGenesisRegionFixture    `json:"regions"`
	ReleaseAuthorities []workloadGenesisAuthorityFixture `json:"releaseAuthorities"`
}

type workloadGenesisRegionFixture struct {
	Plan struct {
		Cell string `json:"cell"`
	} `json:"plan"`
	BootstrapMaterial struct {
		InstallationID string `json:"installationId"`
		Config         struct {
			DeploymentID string `json:"deploymentId"`
			ClusterID    string `json:"clusterId"`
			Cell         string `json:"cell"`
			Environment  string `json:"environment"`
		} `json:"config"`
	} `json:"bootstrapMaterial"`
}

type workloadGenesisAuthorityFixture struct {
	Role                  string   `json:"role"`
	Environment           string   `json:"environment"`
	Cells                 []string `json:"cells"`
	Architectures         []string `json:"architectures"`
	DelegationWire        []byte   `json:"delegationWire"`
	SequenceMigrationWire []byte   `json:"sequenceMigrationWire,omitempty"`
}

type workloadGenesisFixture struct {
	now         time.Time
	root        ed25519.PrivateKey
	roots       trust.Keyring
	scope       trust.Scope
	grant       workloadGenesisGrantFixture
	wire        []byte
	signers     map[string]ed25519.PrivateKey
	delegations map[string]trust.Envelope
}

func newWorkloadGenesisFixture(t *testing.T) workloadGenesisFixture {
	t.Helper()
	public, root, err := ed25519.GenerateKey(rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	roots, err := trust.ParseKeyring(public)
	if err != nil {
		t.Fatal(err)
	}
	f := workloadGenesisFixture{now: time.Now().UTC().Truncate(time.Second), root: root, roots: roots,
		signers: make(map[string]ed25519.PrivateKey), delegations: make(map[string]trust.Envelope)}
	f.grant = workloadGenesisGrantFixture{SchemaVersion: 3, Generation: 1,
		TenancyID: "ocid1.tenancy.oc1..genesisfixture", InstallationID: entityid.Derive("genesis-fixture", "installation"), CleanupOwner: "foundation-fixture"}
	for _, cell := range []string{"GRU", "SFO", "FRA"} {
		region := workloadGenesisRegionFixture{}
		region.Plan.Cell = cell
		region.BootstrapMaterial.InstallationID = f.grant.InstallationID
		config := &region.BootstrapMaterial.Config
		config.DeploymentID = entityid.Derive("genesis-fixture-deployment", cell)
		config.ClusterID = entityid.Derive("genesis-fixture-cluster", cell)
		config.Cell, config.Environment = strings.ToLower(cell), "production"
		f.grant.Regions = append(f.grant.Regions, region)
		for _, role := range []string{"terrabase", "ts-auth", "function-worker"} {
			f.grant.WorkloadGenesis = append(f.grant.WorkloadGenesis, WorkloadGenesis{Schema: WorkloadGenesisSchema,
				TenancyID: f.grant.TenancyID, InstallationID: f.grant.InstallationID, DeploymentID: config.DeploymentID,
				ClusterID: config.ClusterID, Cell: cell, Environment: config.Environment, Role: role, Namespace: "fixture", Bucket: "gru-1-head"})
		}
	}
	gru := f.grant.Regions[0].BootstrapMaterial.Config
	f.scope = trust.Scope{Domain: "terrascale.foundation.scope", DeploymentID: gru.DeploymentID,
		Cell: "GRU", Environment: "production", Role: "foundation", Slot: gru.ClusterID}
	for _, role := range []string{"terrabase", "ts-auth", "function-worker"} {
		public, signer, err := ed25519.GenerateKey(rand.Reader)
		if err != nil {
			t.Fatal(err)
		}
		keyID, err := trust.KeyID(public)
		if err != nil {
			t.Fatal(err)
		}
		delegation := trust.Delegation{SchemaVersion: trust.SchemaVersion, SubjectKeyID: keyID, SubjectPublicKey: base64.RawURLEncoding.EncodeToString(public)}
		for _, cell := range []string{"GRU", "SFO", "FRA"} {
			scope := ContainerScope(ContainerTarget{Cell: cell, Environment: "production", Role: role, Architecture: "arm64"})
			delegation.Capabilities = append(delegation.Capabilities, trust.Capability{Domain: scope.Domain, DeploymentID: scope.DeploymentID,
				Cell: cell, Environment: scope.Environment, Role: role, Slots: []string{"linux-amd64", "linux-arm64"}, Actions: []string{"sign"}})
		}
		envelope, err := trust.SignDelegation(delegation, f.now, f.now.Add(time.Hour), root)
		if err != nil {
			t.Fatal(err)
		}
		f.signers[role], f.delegations[role] = signer, envelope
		f.grant.ReleaseAuthorities = append(f.grant.ReleaseAuthorities, workloadGenesisAuthorityFixture{Role: role, Environment: "production",
			Cells: []string{"GRU", "SFO", "FRA"}, Architectures: []string{"amd64", "arm64"}, DelegationWire: encodeEnvelope(t, envelope)})
	}
	f.wire = f.signGrant(t, f.grant)
	return f
}

func (f workloadGenesisFixture) signGrant(t *testing.T, grant workloadGenesisGrantFixture) []byte {
	t.Helper()
	return encodeEnvelope(t, signDirect(t, grant, f.scope, f.root, f.now, f.now.Add(24*time.Hour)))
}

func (f workloadGenesisFixture) verifyAll(t *testing.T, wire []byte, grant workloadGenesisGrantFixture) map[string]VerifiedWorkloadGenesis {
	t.Helper()
	verified := make(map[string]VerifiedWorkloadGenesis)
	var fingerprint string
	for _, origin := range grant.WorkloadGenesis {
		proof, err := VerifyWorkloadGenesis(wire, f.roots, f.scope, origin)
		if err != nil {
			t.Fatalf("verify complete original %s/%s: %v", origin.Cell, origin.Role, err)
		}
		if !proof.IsVerified() || proof.Origin() != origin || proof.SignerKeyID() == "" {
			t.Fatal("original identity was not retained")
		}
		if fingerprint != "" && proof.Fingerprint() != fingerprint {
			t.Fatal("cells or roles split the full-grant ordering fingerprint")
		}
		fingerprint = proof.Fingerprint()
		for _, arch := range []string{"amd64", "arm64"} {
			if !proof.Allows(ContainerTarget{Cell: origin.Cell, Environment: origin.Environment, Role: origin.Role, Architecture: arch}) {
				t.Fatalf("original authority lost %s/%s/%s", origin.Cell, origin.Role, arch)
			}
		}
		verified[origin.Cell+"/"+origin.Role] = proof
	}
	envelope, err := trust.DecodeEnvelope(wire)
	if err != nil {
		t.Fatal(err)
	}
	want, err := trust.Fingerprint(envelope)
	if err != nil || fingerprint != want {
		t.Fatalf("fingerprint does not cover the entire original grant: %v", err)
	}
	return verified
}

func TestWorkloadGenesisCompleteOriginalAuthority(t *testing.T) {
	f := newWorkloadGenesisFixture(t)
	proofs := f.verifyAll(t, f.wire, f.grant)
	selected := proofs["GRU/ts-auth"]
	mutations := []struct {
		name   string
		mutate func(*workloadGenesisGrantFixture)
	}{
		{"missing ninth original", func(g *workloadGenesisGrantFixture) { g.WorkloadGenesis = g.WorkloadGenesis[:8] }},
		{"duplicate original", func(g *workloadGenesisGrantFixture) { g.WorkloadGenesis[8] = g.WorkloadGenesis[7] }},
		{"unselected cell store", func(g *workloadGenesisGrantFixture) { g.WorkloadGenesis[8].Namespace = "other" }},
		{"unselected regional binding", func(g *workloadGenesisGrantFixture) {
			g.Regions[2].BootstrapMaterial.Config.ClusterID = entityid.Derive("wrong-cluster")
		}},
		{"missing original authority", func(g *workloadGenesisGrantFixture) { g.ReleaseAuthorities = g.ReleaseAuthorities[:2] }},
		{"root used as online signer", func(g *workloadGenesisGrantFixture) {
			var delegation trust.Delegation
			if err := json.Unmarshal(f.delegations["terrabase"].Payload, &delegation); err != nil {
				t.Fatal(err)
			}
			public := f.root.Public().(ed25519.PublicKey)
			var err error
			delegation.SubjectKeyID, err = trust.KeyID(public)
			if err != nil {
				t.Fatal(err)
			}
			delegation.SubjectPublicKey = base64.RawURLEncoding.EncodeToString(public)
			envelope, err := trust.SignDelegation(delegation, f.now, f.now.Add(time.Hour), f.root)
			if err != nil {
				t.Fatal(err)
			}
			g.ReleaseAuthorities[0].DelegationWire = encodeEnvelope(t, envelope)
		}},
		{"unselected authority missing architecture", func(g *workloadGenesisGrantFixture) { g.ReleaseAuthorities[0].Architectures = []string{"arm64"} }},
		{"unselected authority missing cell", func(g *workloadGenesisGrantFixture) { g.ReleaseAuthorities[2].Cells = []string{"GRU", "SFO", "SFO"} }},
		{"legacy migration mixed into original", func(g *workloadGenesisGrantFixture) { g.ReleaseAuthorities[0].SequenceMigrationWire = []byte("legacy") }},
	}
	for _, test := range mutations {
		t.Run(test.name, func(t *testing.T) {
			wire, err := json.Marshal(f.grant)
			if err != nil {
				t.Fatal(err)
			}
			var changed workloadGenesisGrantFixture
			if err := json.Unmarshal(wire, &changed); err != nil {
				t.Fatal(err)
			}
			test.mutate(&changed)
			if _, err := VerifyWorkloadGenesis(f.signGrant(t, changed), f.roots, f.scope, selected.Origin()); err == nil {
				t.Fatal("root-signed incomplete or mismatched original grant accepted")
			}
		})
	}
	for _, field := range []string{"store", "installation", "deployment", "role", "cell"} {
		t.Run("expected "+field, func(t *testing.T) {
			expected := selected.Origin()
			switch field {
			case "store":
				expected.Namespace = "other"
			case "installation":
				expected.InstallationID = entityid.Derive("other-installation")
			case "deployment":
				expected.DeploymentID = entityid.Derive("other-deployment")
			case "role":
				expected.Role = "orchestrator"
			case "cell":
				expected.Cell = "AMS"
			}
			if _, err := VerifyWorkloadGenesis(f.wire, f.roots, f.scope, expected); err == nil {
				t.Fatal("wrong permanent target accepted")
			}
		})
	}
	wrongScope := f.scope
	wrongScope.Slot = entityid.Derive("wrong-original-scope")
	if _, err := VerifyWorkloadGenesis(f.wire, f.roots, wrongScope, selected.Origin()); err == nil {
		t.Fatal("wrong original foundation scope accepted")
	}
	otherPublic, _, err := ed25519.GenerateKey(rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	otherRoots, err := trust.ParseKeyring(otherPublic)
	if err != nil {
		t.Fatal(err)
	}
	if _, err := VerifyWorkloadGenesis(f.wire, otherRoots, f.scope, selected.Origin()); err == nil {
		t.Fatal("wrong original root accepted")
	}
	standalone := encodeEnvelope(t, signDirect(t, selected.Origin(), f.scope, f.root, f.now, f.now.Add(time.Hour)))
	if _, err := VerifyWorkloadGenesis(standalone, f.roots, f.scope, selected.Origin()); err == nil {
		t.Fatal("standalone signed genesis replaced complete original grant")
	}
}

func TestWorkloadGenesisHTTPOrderingAndContainerProvenance(t *testing.T) {
	ctx, cancel := context.WithTimeout(t.Context(), 30*time.Second)
	defer cancel()
	f := newWorkloadGenesisFixture(t)
	proofs := f.verifyAll(t, f.wire, f.grant)
	evidence := []byte("retained workload genesis container qualification evidence")
	evidenceSHA := fingerprintWire(t, evidence)
	directory := t.TempDir()
	var lock sync.Mutex
	var reads, writes, conflicts atomic.Uint64
	var conflictNext atomic.Bool
	pathFor := func(name string) string {
		return filepath.Join(directory, fmt.Sprintf("%x", sha256.Sum256([]byte(name))))
	}
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.URL.Path == "/evidence/"+evidenceSHA {
			_, _ = w.Write(evidence)
			return
		}
		if r.Header.Get("Authorization") == "" {
			http.Error(w, "unsigned OCI request", http.StatusUnauthorized)
			return
		}
		const prefix = "/n/fixture/b/gru-1-head/o/"
		if !strings.HasPrefix(r.URL.Path, prefix) {
			http.NotFound(w, r)
			return
		}
		name := strings.TrimPrefix(r.URL.Path, prefix)
		lock.Lock()
		defer lock.Unlock()
		current, err := os.ReadFile(pathFor(name))
		if err != nil && !os.IsNotExist(err) {
			http.Error(w, err.Error(), 500)
			return
		}
		found := err == nil
		etag := fmt.Sprintf(`"%x"`, sha256.Sum256(current))
		switch r.Method {
		case http.MethodGet:
			reads.Add(1)
			if !found {
				http.NotFound(w, r)
				return
			}
			w.Header().Set("ETag", etag)
			_, _ = w.Write(current)
		case http.MethodPut:
			writes.Add(1)
			isHead := name == SequenceObject("terrabase", "production") || name == SequenceObject("ts-auth", "production") || name == SequenceObject("function-worker", "production")
			if !isHead && (r.Header.Get("If-None-Match") != "*" || r.Header.Get("If-Match") != "") {
				http.Error(w, "reservation is immutable", 400)
				return
			}
			if r.Header.Get("If-None-Match") == "" && r.Header.Get("If-Match") == "" {
				http.Error(w, "missing CAS", 400)
				return
			}
			if isHead && r.Header.Get("If-Match") != "" && conflictNext.CompareAndSwap(true, false) {
				conflicts.Add(1)
				w.WriteHeader(http.StatusPreconditionFailed)
				return
			}
			if r.Header.Get("If-None-Match") == "*" && found || r.Header.Get("If-Match") != "" && (!found || r.Header.Get("If-Match") != etag) {
				w.WriteHeader(http.StatusPreconditionFailed)
				return
			}
			wire, err := io.ReadAll(r.Body)
			if err != nil {
				http.Error(w, err.Error(), 400)
				return
			}
			if err := os.WriteFile(pathFor(name), wire, 0600); err != nil {
				http.Error(w, err.Error(), 500)
				return
			}
			w.WriteHeader(http.StatusOK)
		default:
			w.WriteHeader(http.StatusMethodNotAllowed)
		}
	}))
	defer server.Close()
	apiKey, err := rsa.GenerateKey(rand.Reader, 2048)
	if err != nil {
		t.Fatal(err)
	}
	keyPEM := pem.EncodeToMemory(&pem.Block{Type: "RSA PRIVATE KEY", Bytes: x509.MarshalPKCS1PrivateKey(apiKey)})
	newLocation := func(proof VerifiedWorkloadGenesis) SequenceLocation {
		t.Helper()
		client, err := objectstorage.NewObjectStorageClientWithConfigurationProvider(common.NewRawConfigurationProvider("tenancy", "user", "sa-saopaulo-1", "fingerprint", string(keyPEM), nil))
		if err != nil {
			t.Fatal(err)
		}
		client.Host, client.HTTPClient = server.URL, sequenceHTTPClient{server}
		policy := common.NoRetryPolicy()
		client.SetCustomClientConfiguration(common.CustomClientConfiguration{RetryPolicy: &policy})
		return SequenceLocation{Client: client, Namespace: "fixture", Bucket: "gru-1-head", Genesis: proof, Delegation: f.delegations[proof.Origin().Role]}
	}
	reader := func(ctx context.Context, digest string) (io.ReadCloser, error) {
		request, err := http.NewRequestWithContext(ctx, http.MethodGet, server.URL+"/evidence/"+digest, nil)
		if err != nil {
			return nil, err
		}
		response, err := server.Client().Do(request)
		if err != nil {
			return nil, err
		}
		if response.StatusCode != http.StatusOK {
			response.Body.Close()
			return nil, fmt.Errorf("evidence HTTP %d", response.StatusCode)
		}
		return response.Body, nil
	}
	claimFor := func(role, cell string) ContainerClaim {
		return ContainerClaim{Schema: ContainerGenesisClaimSchema, Image: "registry.example/platform/workload@sha256:" + strings.Repeat("a", 64),
			SourceRepository: "https://github.com/TerraScale/" + role, SourceRevision: strings.Repeat("c", 40), SourceTreeSHA256: strings.Repeat("e", 64),
			Cell: cell, Environment: "production", Role: role, Architecture: "arm64", QualificationSHA256: strings.Repeat("a", 64),
			WorkloadGenesisSHA256: proofs[cell+"/"+role].Fingerprint()}
	}
	identityFor := func(claim ContainerClaim) SequenceIdentity {
		t.Helper()
		family, err := claim.WorkerFamilyDigest()
		if err != nil {
			t.Fatal(err)
		}
		return SequenceIdentity{Role: claim.Role, Environment: claim.Environment, SourceRevision: claim.SourceRevision, ManifestSHA256: family}
	}
	bundleFor := func(claim ContainerClaim, sequence uint64, sequenceWire []byte) ContainerBundle {
		t.Helper()
		claim.ReleaseSequence = sequence
		candidate := ProductionExpectation{SourceRevision: claim.SourceRevision, ArtifactSHA256: strings.Repeat("a", 64), QualificationSHA256: claim.QualificationSHA256,
			Cell: claim.Cell, Environment: claim.Environment, Runtime: ProductionRuntime, Architecture: claim.Architecture, Role: claim.Role}
		qualification := ProductionQualification{Schema: ProductionQualificationSchema, Candidate: candidate}
		for _, gate := range []string{"runtime-ha", "workload-safety"} {
			qualification.Evidence = append(qualification.Evidence, ProductionGateEvidence{Gate: gate, SHA256: evidenceSHA, Bytes: int64(len(evidence)), CompletedAt: f.now})
		}
		claim.Production.Qualification = encodeEnvelope(t, signDirect(t, qualification, ProductionQualificationScope(candidate), f.root, f.now, f.now.Add(time.Hour)))
		target := ContainerTarget{Cell: claim.Cell, Environment: claim.Environment, Role: claim.Role, Architecture: claim.Architecture}
		return ContainerBundle{Claim: encodeEnvelope(t, signDirect(t, claim, ContainerScope(target), f.signers[claim.Role], f.now, f.now.Add(time.Hour))),
			Delegation: encodeEnvelope(t, f.delegations[claim.Role]), Sequence: bytes.Clone(sequenceWire)}
	}
	var firstEvidence []byte
	var firstBundle ContainerBundle
	var firstVerified VerifiedContainer
	for _, role := range []string{"terrabase", "ts-auth", "function-worker"} {
		proof := proofs["GRU/"+role]
		location := newLocation(proof)
		claim := claimFor(role, "GRU")
		identity := identityFor(claim)
		if _, _, err := location.AllocateWithEvidence(ctx, identity, f.roots, f.signers[role]); err != ErrSequenceMigrationRequired {
			t.Fatalf("unsigned zero for %s: %v", role, err)
		}
		for _, cell := range []string{"GRU", "SFO", "FRA"} {
			if err := newLocation(proofs[cell+"/"+role]).ImportGenesis(ctx, f.roots, role, "production", f.now); err != nil {
				t.Fatalf("import %s/%s: %v", cell, role, err)
			}
		}
		sequence, wire, err := location.AllocateWithEvidence(ctx, identity, f.roots, f.signers[role])
		if err != nil || sequence != 1 {
			t.Fatalf("first %s sequence = %d: %v", role, sequence, err)
		}
		retry, retryWire, err := newLocation(proofs["SFO/"+role]).AllocateWithEvidence(ctx, identity, f.roots, f.signers[role])
		if err != nil || retry != sequence || !bytes.Equal(wire, retryWire) {
			t.Fatalf("restart/cross-cell retry %s = %d: %v", role, retry, err)
		}
		for _, cell := range []string{"GRU", "SFO", "FRA"} {
			proof := proofs[cell+"/"+role]
			target := ContainerTarget{Cell: cell, Environment: "production", Role: role, Architecture: "arm64", Genesis: proof}
			bundle := bundleFor(claimFor(role, cell), sequence, wire)
			verified, err := VerifyContainerCurrent(ctx, bundle, f.roots, target, f.now, f.now.Add(time.Minute), reader, newLocation(proof))
			if err != nil {
				t.Fatalf("current %s/%s: %v", cell, role, err)
			}
			freshTarget := target
			freshTarget.Genesis = VerifiedWorkloadGenesis{}
			fromAllocation, err := VerifyContainerCurrent(ctx, bundle, f.roots, freshTarget, f.now, f.now.Add(time.Minute), reader, newLocation(proof))
			if err != nil || fromAllocation.Genesis() != proof {
				t.Fatalf("fresh target lost independently authenticated allocation origin %s/%s: %v", cell, role, err)
			}
			foreignCell := "GRU"
			if cell == foreignCell {
				foreignCell = "SFO"
			}
			foreignProof := proofs[foreignCell+"/"+role]
			if foreignProof.Fingerprint() != proof.Fingerprint() {
				t.Fatal("cross-cell substitution must exercise the same full-grant fingerprint")
			}
			if _, err := VerifyContainerCurrent(ctx, bundle, f.roots, target, f.now, f.now.Add(time.Minute), reader, newLocation(foreignProof)); err == nil {
				t.Fatal("allocation origin replaced an explicitly verified local origin")
			}
			if _, err := VerifyContainerCurrent(ctx, bundle, f.roots, freshTarget, f.now, f.now.Add(time.Minute), reader, newLocation(foreignProof)); err == nil {
				t.Fatal("fresh target admitted a same-fingerprint foreign-cell origin")
			}
			unproven := newLocation(proof)
			unproven.Genesis = VerifiedWorkloadGenesis{}
			if _, err := VerifyContainerCurrent(ctx, bundle, f.roots, freshTarget, f.now, f.now.Add(time.Minute), reader, unproven); err == nil {
				t.Fatal("missing original proof became an empty-proof fallback")
			}
			historical, err := VerifyContainerHistorical(bundle, f.roots, target)
			if err != nil || historical.Genesis().Origin() != proof.Origin() || historical.Genesis().Fingerprint() != proof.Fingerprint() {
				t.Fatalf("historical original %s/%s: %v", cell, role, err)
			}
			family, err := verified.WorkerFamilyEvidence()
			if err != nil || !bytes.Equal(family, wire) || VerifyWorkerFamilyEvidence(family, f.roots, verified) != nil {
				t.Fatalf("family provenance %s/%s: %v", cell, role, err)
			}
			if verified.Genesis().Fingerprint() != proof.Fingerprint() || !verified.Valid(f.now) {
				t.Fatal("current proof lost original authority")
			}
			if role == "ts-auth" && cell == "GRU" {
				firstEvidence, firstBundle, firstVerified = bytes.Clone(wire), bundle, verified
			}
		}
	}
	proof := proofs["GRU/ts-auth"]
	location := newLocation(proof)
	target := ContainerTarget{Cell: "GRU", Environment: "production", Role: "ts-auth", Architecture: "arm64", Genesis: proof}
	originalIdentity := identityFor(claimFor("ts-auth", "GRU"))
	next := originalIdentity
	next.ManifestSHA256 = strings.Repeat("b", 64)
	conflictNext.Store(true)
	sequence, _, err := newLocation(proofs["FRA/ts-auth"]).AllocateWithEvidence(ctx, next, f.roots, f.signers["ts-auth"])
	if err != nil || sequence != 2 || conflicts.Load() != 1 {
		t.Fatalf("CAS retry did not advance once: %d, conflicts %d: %v", sequence, conflicts.Load(), err)
	}
	if err := location.ImportGenesis(ctx, f.roots, "ts-auth", "production", f.now); err != nil {
		t.Fatal(err)
	}
	sequence, _, err = newLocation(proof).AllocateWithEvidence(ctx, next, f.roots, f.signers["ts-auth"])
	if err != nil || sequence != 2 {
		t.Fatalf("replayed original reset allocated progress: %d: %v", sequence, err)
	}
	if _, err := VerifyContainerHistorical(firstBundle, f.roots, target); err != nil {
		t.Fatalf("head advancement invalidated retained historical floor: %v", err)
	}
	if _, err := VerifyContainerCurrent(ctx, firstBundle, f.roots, target, f.now, f.now.Add(time.Minute), reader, newLocation(proof)); err != nil {
		t.Fatalf("immutable first family lost after restart: %v", err)
	}
	if err := VerifyWorkerFamilyEvidence(firstEvidence, f.roots, firstVerified); err != nil {
		t.Fatal(err)
	}

	// A valid same-key signature must not replace the retained family at sequence 1.
	var head sequenceHead
	if err := json.Unmarshal(firstEvidence, &head); err != nil {
		t.Fatal(err)
	}
	conflicting := head
	conflicting.Identity.ManifestSHA256 = strings.Repeat("d", 64)
	conflicting.Reservation = signDirect(t, sequenceReservation{Sequence: head.Sequence, Identity: conflicting.Identity, WorkloadGenesisSHA256: proof.Fingerprint()},
		sequenceReservationScope("ts-auth", "production"), f.signers["ts-auth"], f.now, f.now.Add(MaxReceiptLifetime))
	if _, err := location.retainReservation(ctx, conflicting, f.roots); err == nil {
		t.Fatal("same-sequence equivocation replaced immutable winner")
	}
	originalAfterConflict, err := location.retainReservation(ctx, head, f.roots)
	if err != nil || !bytes.Equal(originalAfterConflict, firstEvidence) {
		t.Fatal("equivocation changed retained winner")
	}
	changedFamily := firstBundle
	changedFamily.Sequence, err = json.Marshal(conflicting, json.Deterministic(true))
	if err != nil {
		t.Fatal(err)
	}
	if _, err := VerifyContainerHistorical(changedFamily, f.roots, target); err == nil {
		t.Fatal("different signed family accepted for original claim")
	}

	// Changing a signed, otherwise valid original grant preserves the online key.
	alternateGrant := f.grant
	alternateGrant.CleanupOwner = "different-original-owner"
	alternateWire := f.signGrant(t, alternateGrant)
	alternate := f.verifyAll(t, alternateWire, alternateGrant)["GRU/ts-auth"]
	if alternate.Fingerprint() == proof.Fingerprint() || alternate.SignerKeyID() != proof.SignerKeyID() {
		t.Fatal("alternate-origin control is invalid")
	}
	if err := newLocation(alternate).ImportGenesis(ctx, f.roots, "ts-auth", "production", f.now); err == nil {
		t.Fatal("same-key alternate grant reset existing head")
	}
	transplanted := head
	transplanted.WorkloadGenesisSHA256 = alternate.Fingerprint()
	transplantedWire, err := json.Marshal(transplanted, json.Deterministic(true))
	if err != nil {
		t.Fatal(err)
	}
	if _, err := verifySequenceHead(transplantedWire, f.roots, "ts-auth", "production", alternate); err == nil {
		t.Fatal("same-key reservation transplanted across original grants")
	}
	alternateClaim := claimFor("ts-auth", "GRU")
	alternateClaim.WorkloadGenesisSHA256 = alternate.Fingerprint()
	alternateBundle := bundleFor(alternateClaim, 1, transplantedWire)
	alternateTarget := target
	alternateTarget.Genesis = alternate
	if _, err := VerifyContainerHistorical(alternateBundle, f.roots, alternateTarget); err == nil {
		t.Fatal("same-key cross-origin container family accepted")
	}
	// Also exercise the transplanted reservation through the actual SDK head read.
	headPath := pathFor(SequenceObject("ts-auth", "production"))
	lock.Lock()
	advancedHead, readErr := os.ReadFile(headPath)
	if readErr == nil {
		readErr = os.WriteFile(headPath, transplantedWire, 0600)
	}
	lock.Unlock()
	if readErr != nil {
		t.Fatal(readErr)
	}
	if _, _, err := newLocation(alternate).AllocateWithEvidence(ctx, originalIdentity, f.roots, f.signers["ts-auth"]); err == nil {
		t.Fatal("SDK accepted transplanted same-key head")
	}
	lock.Lock()
	restoreErr := os.WriteFile(headPath, advancedHead, 0600)
	lock.Unlock()
	if restoreErr != nil {
		t.Fatal(restoreErr)
	}

	legacy := head
	legacy.Reservation = signDirect(t, sequenceReservation{Sequence: head.Sequence, Identity: head.Identity}, sequenceReservationScope("ts-auth", "production"),
		f.signers["ts-auth"], f.now, f.now.Add(MaxReceiptLifetime))
	legacyWire, err := json.Marshal(legacy, json.Deterministic(true))
	if err != nil {
		t.Fatal(err)
	}
	legacyBundle := firstBundle
	legacyBundle.Sequence = legacyWire
	if _, err := VerifyContainerHistorical(legacyBundle, f.roots, target); err == nil {
		t.Fatal("legacy signed reservation transplanted into genesis head")
	}
	if err := VerifyWorkerFamilyEvidence(legacyWire, f.roots, firstVerified); err == nil {
		t.Fatal("legacy reservation acquired genesis family provenance")
	}
	winnerPath := pathFor(SequenceReservationObject("ts-auth", "production", proof.Fingerprint(), 1))
	lock.Lock()
	writeErr := os.WriteFile(winnerPath, legacyWire, 0600)
	lock.Unlock()
	if writeErr != nil {
		t.Fatal(writeErr)
	}
	if _, err := VerifyContainerCurrent(ctx, firstBundle, f.roots, target, f.now, f.now.Add(time.Minute), reader, location); err == nil {
		t.Fatal("SDK accepted legacy reservation in durable genesis winner")
	}
	lock.Lock()
	writeErr = os.WriteFile(winnerPath, firstEvidence, 0600)
	lock.Unlock()
	if writeErr != nil {
		t.Fatal(writeErr)
	}
	if _, err := VerifyContainerCurrent(ctx, firstBundle, f.roots, target, f.now, f.now.Add(time.Minute), reader, newLocation(proof)); err != nil {
		t.Fatalf("restored immutable winner lost admission: %v", err)
	}

	beforeReads := reads.Load()
	for _, field := range []string{"namespace", "bucket"} {
		wrong := newLocation(proof)
		if field == "namespace" {
			wrong.Namespace = "other"
		} else {
			wrong.Bucket = "other"
		}
		if err := wrong.ImportGenesis(ctx, f.roots, "ts-auth", "production", f.now); err == nil {
			t.Fatal("wrong genesis store imported")
		}
		if _, err := VerifyContainerCurrent(ctx, firstBundle, f.roots, target, f.now, f.now.Add(time.Minute), reader, wrong); err == nil {
			t.Fatal("wrong store supplied family provenance")
		}
	}
	if reads.Load() != beforeReads {
		t.Fatal("wrong store was read before original location validation")
	}
	_, wrongSigner, err := ed25519.GenerateKey(rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	if _, _, err := location.AllocateWithEvidence(ctx, next, f.roots, wrongSigner); err == nil {
		t.Fatal("unapproved key reused valid reservation")
	}
	expired := location
	originalDelegation := f.delegations["ts-auth"]
	var delegation trust.Delegation
	if err := json.Unmarshal(originalDelegation.Payload, &delegation); err != nil {
		t.Fatal(err)
	}
	expired.Delegation = signDirect(t, delegation, originalDelegation.Scope, f.root, f.now.Add(-2*time.Hour), f.now.Add(-time.Hour))
	if err := expired.ImportGenesis(ctx, f.roots, "ts-auth", "production", f.now); err == nil {
		t.Fatal("expired current authority replayed original import")
	}
	if _, _, err := expired.AllocateWithEvidence(ctx, next, f.roots, f.signers["ts-auth"]); err == nil {
		t.Fatal("historical original granted current signer permission")
	}
	if _, err := VerifyContainerCurrent(ctx, firstBundle, f.roots, target, f.now.Add(2*time.Hour), f.now.Add(2*time.Hour+time.Minute), reader, location); err == nil {
		t.Fatal("historical genesis renewed expired container permission")
	}
	if _, err := VerifyContainerHistorical(firstBundle, f.roots, target); err != nil {
		t.Fatalf("historical provenance depended on current permission: %v", err)
	}
	delegation.Capabilities = delegation.Capabilities[:1]
	narrowed := location
	narrowed.Delegation = signDirect(t, delegation, originalDelegation.Scope, f.root, f.now, f.now.Add(time.Hour))
	if err := narrowed.ImportGenesis(ctx, f.roots, "ts-auth", "production", f.now); err == nil {
		t.Fatal("narrowed current delegation replaced original all-cell authority")
	}
	missingOriginal := target
	missingOriginal.Genesis = VerifiedWorkloadGenesis{}
	if _, err := VerifyContainerHistorical(firstBundle, f.roots, missingOriginal); err == nil {
		t.Fatal("genesis claim admitted without complete verified original")
	}
	if reads.Load() == 0 || writes.Load() == 0 {
		t.Fatal("fixture bypassed actual SDK object-store boundary")
	}
}
