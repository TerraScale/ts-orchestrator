package pullauth

import (
	"errors"

	ocisecrets "github.com/oracle/oci-go-sdk/v65/secrets"

	"github.com/TerraScale/ts-orchestrator/internal/vaultsecret"
)

var ErrPullAuth = errors.New("private OCIR pull authorization is unavailable or differs from admission")

// PullScope is derived from the verified release and authenticated workload
// admission. TaskPrincipal is its stable workload/service intent, not a future
// scheduler task ID; the executor also checks actual task and node admission.
type PullScope struct {
	RegistryHost  string `json:"registry_host"`
	Repository    string `json:"repository"`
	Digest        string `json:"digest"`
	TaskPrincipal string `json:"task_principal"`
}

// PullSecret is an independently root-approved credential binding. Repository
// includes the tenancy namespace. Ref holds an existing OCI-issued credential
// as Vault-only JSON {username,password};
// its IAM user must already have server-side read access limited to this repo.
// Naming a Vault secret does not prove that IAM policy or grant access to it.
type PullSecret struct {
	RegistryHost string          `json:"registry_host"`
	Repository   string          `json:"repository"`
	Ref          vaultsecret.Ref `json:"ref"`
}

// PullClaim is metadata for the existing authenticated release/task admission
// record, never a standalone authentication proof. Object storage may carry
// these refs, hashes and generations; credential bytes remain only in Vault.
type PullClaim struct {
	Scope      PullScope  `json:"scope"`
	Secret     PullSecret `json:"secret"`
	SecretID   string     `json:"secret_id"`
	Version    int64      `json:"version"`
	SHA256     string     `json:"sha256"`
	Generation uint64     `json:"generation"`
}

// PullSecrets reads the existing regional Vault using the admitted host's OCI
// principal. It never creates users, tokens, IAM policies or secrets.
type PullSecrets struct {
	client ocisecrets.SecretsClient
	region string
}
