package release

import (
	"crypto/ed25519"
	"crypto/sha256"
	"encoding/base64"
	"encoding/hex"
	"encoding/json/v2"
	"errors"
	"strings"

	"github.com/TerraScale/ts-orchestrator/internal/entityid"
)

const AdmissionAttestorAuthorizationSchema = "terrascale.release.admission-attestor-authorization.v1"

// AdmissionAttestorAuthorization is DATA until checked against its complete
// original root-signed foundation grant. It selects no future key or archive.
type AdmissionAttestorAuthorization struct {
	Schema                   string    `json:"schema"`
	Domain                   string    `json:"domain"`
	Action                   string    `json:"action"`
	SourceBinding            string    `json:"sourceBinding"`
	TenancyID                string    `json:"tenancyId"`
	InstallationID           string    `json:"installationId"`
	DeploymentID             string    `json:"deploymentId"`
	ClusterID                string    `json:"clusterId"`
	Cell                     string    `json:"cell"`
	Environment              string    `json:"environment"`
	Generation               uint64    `json:"generation"`
	ControllerSlots          [3]string `json:"controllerSlots"`
	Roles                    [3]string `json:"roles"`
	PlanSHA256               string    `json:"planSha256"`
	WorkloadGenesisSHA256    string    `json:"workloadGenesisSha256"`
	SourceRegistrationSHA256 string    `json:"sourceRegistrationSha256"`
	SourceNamespace          string    `json:"sourceNamespace"`
	SourceBucket             string    `json:"sourceBucket"`
	SourceObject             string    `json:"sourceObject"`
}

func (a AdmissionAttestorAuthorization) Validate() error {
	if a.Schema != AdmissionAttestorAuthorizationSchema || a.Domain != "terrascale.release.container-admission" || a.Action != "reserve" || a.SourceBinding != "original-source-inventory.v1" ||
		!entityid.Valid(a.InstallationID) || !entityid.Valid(a.DeploymentID) || !entityid.Valid(a.ClusterID) || !ValidRegion(a.Cell) || !ValidEnvironment(a.Environment) || a.Generation == 0 ||
		a.ControllerSlots != [3]string{"controller-a", "controller-b", "controller-c"} || a.Roles != [3]string{"function-worker", "terrabase", "ts-auth"} ||
		!digestPattern.MatchString(a.PlanSHA256) || !digestPattern.MatchString(a.WorkloadGenesisSHA256) || !digestPattern.MatchString(a.SourceRegistrationSHA256) ||
		!strings.HasPrefix(a.TenancyID, "ocid1.tenancy.oc1..") || len(a.TenancyID) > 512 || strings.ContainsAny(a.TenancyID, "/\\ \t\r\n") ||
		a.SourceNamespace == "" || len(a.SourceNamespace) > 128 || strings.ContainsAny(a.SourceNamespace, "/\\ \t\r\n") || a.SourceBucket != "gru-1-head" ||
		a.SourceObject == "" || len(a.SourceObject) > 1024 || strings.ContainsAny(a.SourceObject, "\\ \t\r\n") || strings.Contains(a.SourceObject, "..") {
		return errors.New("admission attestor authorization lacks its fixed original scope")
	}
	return nil
}

func (a AdmissionAttestorAuthorization) Digest() (string, error) {
	if err := a.Validate(); err != nil {
		return "", err
	}
	wire, err := json.Marshal(a, json.Deterministic(true))
	if err != nil {
		return "", err
	}
	sum := sha256.Sum256(wire)
	return hex.EncodeToString(sum[:]), nil
}

// AdmissionAttestorMaterial describes public material, never signing authority.
type AdmissionAttestorMaterial struct {
	AuthorizationSHA256 string `json:"authorizationSha256"`
	PublicKey           string `json:"publicKey"`
}

func (m AdmissionAttestorMaterial) Validate() error {
	key, err := base64.StdEncoding.Strict().DecodeString(m.PublicKey)
	if err != nil || len(key) != ed25519.PublicKeySize || base64.StdEncoding.EncodeToString(key) != m.PublicKey || !digestPattern.MatchString(m.AuthorizationSHA256) {
		return errors.New("admission attestor public material is incomplete")
	}
	return nil
}

// AdmissionAttestorBinding describes an authenticated original selection only
// when returned by the concrete region verifier; these fields are not proof.
type AdmissionAttestorBinding struct {
	Material                AdmissionAttestorMaterial `json:"material"`
	SourceSHA256            string                    `json:"sourceSha256"`
	OriginalInventorySHA256 string                    `json:"originalInventorySha256"`
}
