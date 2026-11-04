package release

import (
	"crypto/ed25519"
	"crypto/rand"

	"encoding/base64"
	"encoding/json/v2"

	"strings"

	"testing"
	"time"

	"github.com/TerraScale/ts-orchestrator/internal/entityid"
	"github.com/TerraScale/ts-orchestrator/internal/trust"
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
	for _, cell := range []string{"GRU", "SJC", "FRA"} {
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
		for _, cell := range []string{"GRU", "SJC", "FRA"} {
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
			Cells: []string{"GRU", "SJC", "FRA"}, Architectures: []string{"amd64", "arm64"}, DelegationWire: encodeEnvelope(t, envelope)})
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
