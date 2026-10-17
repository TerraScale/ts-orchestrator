package release

import (
	"crypto/sha256"
	"encoding/hex"
	"errors"
	"strings"

	"github.com/TerraScale/ts-orchestrator/internal/entityid"
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
