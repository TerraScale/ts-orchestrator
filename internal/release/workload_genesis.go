package release

import (
	"crypto/ed25519"
	"crypto/sha256"
	"encoding/base64"
	"encoding/hex"
	"encoding/json/v2"
	"errors"
	"slices"
	"strings"
	"time"

	"github.com/TerraScale/ts-orchestrator/internal/entityid"
	"github.com/TerraScale/ts-orchestrator/internal/trust"
)

const WorkloadGenesisSchema = "terrascale.release.workload-genesis.v1"

// WorkloadGenesis commits a founding scope to a prospective container lineage.
// Only its original root-signed foundation grant authenticates this fact.
type WorkloadGenesis struct {
	Schema         string `json:"schema"`
	TenancyID      string `json:"tenancyId"`
	InstallationID string `json:"installationId"`
	DeploymentID   string `json:"deploymentId"`
	ClusterID      string `json:"clusterId"`
	Cell           string `json:"cell"`
	Environment    string `json:"environment"`
	Role           string `json:"role"`
	Namespace      string `json:"namespace"`
	Bucket         string `json:"bucket"`
}

func (origin WorkloadGenesis) Validate() error {
	if origin.Schema != WorkloadGenesisSchema || !entityid.Valid(origin.InstallationID) || !entityid.Valid(origin.DeploymentID) || !entityid.Valid(origin.ClusterID) ||
		!ValidRegion(origin.Cell) || !ValidEnvironment(origin.Environment) ||
		(origin.Role != "terrabase" && origin.Role != "ts-auth" && origin.Role != "function-worker") ||
		!strings.HasPrefix(origin.TenancyID, "ocid1.tenancy.oc1..") || len(origin.TenancyID) > 512 || strings.ContainsAny(origin.TenancyID, "/\\ \t\r\n") ||
		origin.Namespace == "" || len(origin.Namespace) > 128 || strings.ContainsAny(origin.Namespace, "/\\ \t\r\n") || origin.Bucket != "gru-1-head" {
		return errors.New("workload genesis lacks an exact founding lineage and home store")
	}
	return nil
}

// WorkloadGenesisObject identifies the permanent scope, independently of any
// installation or host identity. It grants no verification or storage authority.
func WorkloadGenesisObject(tenancy, cell, environment, role string) (string, error) {
	if !strings.HasPrefix(tenancy, "ocid1.tenancy.oc1..") || len(tenancy) > 512 || strings.ContainsAny(tenancy, "/\\ \t\r\n") ||
		!ValidRegion(cell) || !ValidEnvironment(environment) || (role != "terrabase" && role != "ts-auth" && role != "function-worker") {
		return "", errors.New("workload genesis object requires an exact permanent scope")
	}
	digest := sha256.Sum256([]byte(tenancy))
	return "orchestrator/workload-genesis/v1/" + hex.EncodeToString(digest[:]) + "/" + cell + "/" + environment + "/" + role + ".json", nil
}

// VerifiedWorkloadGenesis authenticates historical origin, never current permission.
// Its fingerprint covers the complete original grant and is shared across cells.
type VerifiedWorkloadGenesis struct {
	origin      WorkloadGenesis
	fingerprint string
	signerID    string
	public      [ed25519.PublicKeySize]byte
	scopes      [6]trust.Scope
	scopeCount  int
}

func (v VerifiedWorkloadGenesis) IsVerified() bool        { return v.fingerprint != "" }
func (v VerifiedWorkloadGenesis) Origin() WorkloadGenesis { return v.origin }
func (v VerifiedWorkloadGenesis) Fingerprint() string     { return v.fingerprint }
func (v VerifiedWorkloadGenesis) SignerKeyID() string     { return v.signerID }

// Allows checks cell membership independently from the global ordering identity.
func (v VerifiedWorkloadGenesis) Allows(target ContainerTarget) bool {
	return v.IsVerified() && target.Cell == v.origin.Cell && target.Environment == v.origin.Environment && target.Role == v.origin.Role && slices.Contains(v.scopes[:v.scopeCount], ContainerScope(target))
}

// VerifyCurrentDelegation separates present permission from permanent origin.
func (v VerifiedWorkloadGenesis) VerifyCurrentDelegation(envelope trust.Envelope, roots trust.Keyring, now time.Time) error {
	if !v.IsVerified() || now.IsZero() {
		return errors.New("workload genesis requires verified origin and current release authority")
	}
	delegation, err := trust.VerifyDelegationCurrent(envelope, roots, now, trust.Policy{MaxLifetime: MaxUpdateReceiptLifetime})
	if err != nil {
		return err
	}
	if delegation.SubjectKeyID() != v.signerID || !genesisDelegationScopes(delegation, v.scopes[:v.scopeCount]) {
		return trust.ErrCapabilityDenied
	}
	return nil
}

// VerifyWorkloadGenesis authenticates the entire original signed grant. The
// caller independently pins its original scope and permanent home object.
func VerifyWorkloadGenesis(wire []byte, roots trust.Keyring, originalScope trust.Scope, expected WorkloadGenesis) (VerifiedWorkloadGenesis, error) {
	deny := func() (VerifiedWorkloadGenesis, error) {
		return VerifiedWorkloadGenesis{}, errors.New("workload genesis differs from complete original root authority")
	}
	// Same bound as the region foundation grant reader.
	if len(wire) == 0 || len(wire) > 256<<10 || expected.Validate() != nil || expected.Environment != "production" || originalScope.Domain != "terrascale.foundation.scope" || originalScope.Cell != "GRU" || originalScope.Environment != expected.Environment || originalScope.Role != "foundation" || !entityid.Valid(originalScope.DeploymentID) || !entityid.Valid(originalScope.Slot) {
		return deny()
	}
	envelope, err := trust.DecodeEnvelope(wire)
	if err != nil {
		return VerifiedWorkloadGenesis{}, err
	}
	// Match bootstrap.BootstrapAnchorTrustPolicy without importing its release dependency.
	payload, err := trust.VerifyHistorical(envelope, originalScope, roots, trust.Policy{MaxLifetime: 365 * 24 * time.Hour, ClockSkew: time.Minute})
	if err != nil {
		return VerifiedWorkloadGenesis{}, err
	}
	var grant struct {
		SchemaVersion   int               `json:"schemaVersion"`
		TenancyID       string            `json:"tenancyId"`
		InstallationID  string            `json:"installationId"`
		WorkloadGenesis []WorkloadGenesis `json:"workloadGenesis"`
		Regions         []struct {
			Plan struct {
				Cell string `json:"cell"`
			} `json:"plan"`
			BootstrapMaterial *struct {
				InstallationID string `json:"installationId"`
				Config         struct {
					DeploymentID string `json:"deploymentId"`
					ClusterID    string `json:"clusterId"`
					Cell         string `json:"cell"`
					Environment  string `json:"environment"`
				} `json:"config"`
			} `json:"bootstrapMaterial"`
		} `json:"regions"`
		ReleaseAuthorities []struct {
			Role                  string   `json:"role"`
			Environment           string   `json:"environment"`
			Cells                 []string `json:"cells"`
			Architectures         []string `json:"architectures"`
			DelegationWire        []byte   `json:"delegationWire"`
			SequenceMigrationWire []byte   `json:"sequenceMigrationWire"`
		} `json:"releaseAuthorities"`
	}
	// Only this view is decoded here; the signature still covers every grant byte.
	if json.Unmarshal(payload, &grant) != nil || grant.SchemaVersion != 3 || grant.TenancyID != expected.TenancyID || grant.InstallationID != expected.InstallationID || len(grant.WorkloadGenesis) != 9 || len(grant.Regions) != 3 || len(grant.ReleaseAuthorities) != 3 {
		return deny()
	}
	origins := make(map[string]WorkloadGenesis, 9)
	for _, origin := range grant.WorkloadGenesis {
		key := origin.Cell + "/" + origin.Role
		if origin.Validate() != nil || origin.TenancyID != grant.TenancyID || origin.InstallationID != grant.InstallationID || origin.Namespace != expected.Namespace || origin.Bucket != expected.Bucket || origin.Environment != expected.Environment || origins[key] != (WorkloadGenesis{}) {
			return deny()
		}
		origins[key] = origin
	}
	if origins[expected.Cell+"/"+expected.Role] != expected {
		return deny()
	}
	cells := make(map[string]bool, 3)
	for _, region := range grant.Regions {
		material := region.BootstrapMaterial
		if material == nil || material.InstallationID != grant.InstallationID || cells[region.Plan.Cell] || strings.ToUpper(material.Config.Cell) != region.Plan.Cell || material.Config.Environment != expected.Environment {
			return deny()
		}
		cells[region.Plan.Cell] = true
		for _, role := range []string{"terrabase", "ts-auth", "function-worker"} {
			origin, found := origins[region.Plan.Cell+"/"+role]
			if !found || origin.DeploymentID != material.Config.DeploymentID || origin.ClusterID != material.Config.ClusterID || region.Plan.Cell == "GRU" && (origin.DeploymentID != originalScope.DeploymentID || origin.ClusterID != originalScope.Slot) {
				return deny()
			}
		}
	}
	if !cells["GRU"] || !cells["SJC"] || !cells["FRA"] {
		return deny()
	}
	var verified VerifiedWorkloadGenesis
	seen := make(map[string]bool, 3)
	for _, authority := range grant.ReleaseAuthorities {
		if seen[authority.Role] || authority.Environment != expected.Environment || len(authority.SequenceMigrationWire) != 0 || len(authority.Cells) != 3 || len(authority.Architectures) == 0 || len(authority.Architectures) > 2 {
			return deny()
		}
		seen[authority.Role] = true
		var scopes []trust.Scope
		for _, cell := range authority.Cells {
			if !cells[cell] || origins[cell+"/"+authority.Role] == (WorkloadGenesis{}) {
				return deny()
			}
			for _, arch := range authority.Architectures {
				scope := ContainerScope(ContainerTarget{Cell: cell, Environment: authority.Environment, Role: authority.Role, Architecture: arch})
				if arch != "amd64" && arch != "arm64" || slices.Contains(scopes, scope) {
					return deny()
				}
				scopes = append(scopes, scope)
			}
		}
		delegationEnvelope, err := trust.DecodeEnvelope(authority.DelegationWire)
		if err != nil {
			return VerifiedWorkloadGenesis{}, err
		}
		delegation, err := trust.VerifyDelegationHistorical(delegationEnvelope, roots, trust.Policy{MaxLifetime: MaxUpdateReceiptLifetime})
		if err != nil {
			return VerifiedWorkloadGenesis{}, err
		}
		if roots[delegation.SubjectKeyID()] != nil || !genesisDelegationScopes(delegation, scopes) {
			return deny()
		}
		if authority.Role == expected.Role {
			var public trust.Delegation
			if json.Unmarshal(delegationEnvelope.Payload, &public, json.RejectUnknownMembers(true)) != nil {
				return deny()
			}
			key, err := base64.RawURLEncoding.Strict().DecodeString(public.SubjectPublicKey)
			if err != nil || len(key) != ed25519.PublicKeySize {
				return deny()
			}
			verified = VerifiedWorkloadGenesis{origin: expected, signerID: delegation.SubjectKeyID(), public: [ed25519.PublicKeySize]byte(key), scopeCount: len(scopes)}
			copy(verified.scopes[:], scopes)
		}
	}
	if !seen["terrabase"] || !seen["ts-auth"] || !seen["function-worker"] || verified.signerID == "" {
		return deny()
	}
	verified.fingerprint, err = trust.Fingerprint(envelope)
	return verified, err
}

func genesisDelegationScopes(delegation trust.VerifiedDelegation, scopes []trust.Scope) bool {
	expected := make(map[trust.Scope]bool, len(scopes))
	for _, scope := range scopes {
		expected[scope] = true
	}
	for _, capability := range delegation.Capabilities() {
		if !slices.Equal(capability.Actions, []string{"sign"}) {
			return false
		}
		for _, slot := range capability.Slots {
			scope := trust.Scope{Domain: capability.Domain, DeploymentID: capability.DeploymentID, Cell: capability.Cell, Environment: capability.Environment, Role: capability.Role, Slot: slot}
			if !expected[scope] {
				return false
			}
			delete(expected, scope)
		}
	}
	return len(expected) == 0
}
