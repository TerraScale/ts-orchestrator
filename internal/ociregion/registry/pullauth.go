package registry

import (
	"context"
	"crypto/sha256"
	"encoding/hex"
	"errors"
	"regexp"
	"strings"
	"time"

	ocisecrets "github.com/oracle/oci-go-sdk/v65/secrets"

	"github.com/TerraScale/ts-orchestrator/internal/ociclient"
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
// includes the tenancy namespace. Ref holds an existing OCI-issued auth token;
// its IAM user must already have server-side read access limited to this repo.
// Naming a Vault secret does not prove that IAM policy or grant access to it.
type PullSecret struct {
	RegistryHost string          `json:"registry_host"`
	Repository   string          `json:"repository"`
	Username     string          `json:"username"`
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

func NewPullSecrets(factory *ociclient.Factory) (*PullSecrets, error) {
	if factory == nil {
		return nil, ErrPullAuth
	}
	client, err := vaultsecret.SecretsClient(factory)
	if err != nil {
		return nil, ErrPullAuth
	}
	return &PullSecrets{client: client, region: factory.Region()}, nil
}

var ocirHost = regexp.MustCompile(`^[a-z0-9]+(?:-[a-z0-9]+)*\.ocir\.io$`)
var ocirPath = regexp.MustCompile(`^[a-z0-9]+(?:[._-][a-z0-9]+)*(?:/[a-z0-9]+(?:[._-][a-z0-9]+)*)+$`)

func (p *PullSecrets) validate(scope PullScope, owned PullSecret) error {
	parts := strings.Split(owned.Ref.Vault, ".")
	if p == nil || p.region == "" || len(parts) < 5 || parts[0] != "ocid1" || parts[1] != "vault" || parts[2] != "oc1" || parts[3] != p.region ||
		!ocirHost.MatchString(scope.RegistryHost) || len(scope.RegistryHost) > 253 ||
		!ocirPath.MatchString(scope.Repository) || len(scope.Repository) > 512 ||
		!validDigest(scope.Digest) || scope.TaskPrincipal == "" || len(scope.TaskPrincipal) > 256 || strings.ContainsAny(scope.TaskPrincipal, "\x00\t\r\n ") ||
		owned.RegistryHost != scope.RegistryHost || owned.Repository != scope.Repository || owned.Ref.Name == "" ||
		owned.Username == "" || len(owned.Username) > 512 || strings.ContainsAny(owned.Username, "\x00\t\r\n: ") {
		return ErrPullAuth
	}
	namespace, _, _ := strings.Cut(scope.Repository, "/")
	if user, ok := strings.CutPrefix(owned.Username, namespace+"/"); !ok || user == "" {
		return ErrPullAuth
	}
	return nil
}

func (p *PullSecrets) read(ctx context.Context, scope PullScope, owned PullSecret) (vaultsecret.Current, error) {
	if err := p.validate(scope, owned); err != nil {
		return vaultsecret.Current{}, err
	}
	ctx, cancel := context.WithTimeout(ctx, 30*time.Second)
	defer cancel()
	value, err := vaultsecret.ReadCurrent(ociclient.RequestContext(ctx), p.client, owned.Ref)
	if err != nil || value.Value() == "" || strings.ContainsAny(value.Value(), "\x00\r\n") {
		return vaultsecret.Current{}, errors.Join(ErrPullAuth, ctx.Err())
	}
	return value, nil
}

// Describe validates an already owned Vault credential and produces metadata
// for the existing authenticated admission. The caller must authenticate owned
// independently; a task or release payload cannot select its own Vault binding.
func (p *PullSecrets) Describe(ctx context.Context, scope PullScope, owned PullSecret, generation uint64) (PullClaim, error) {
	if generation == 0 {
		return PullClaim{}, ErrPullAuth
	}
	value, err := p.read(ctx, scope, owned)
	if err != nil {
		return PullClaim{}, err
	}
	sum := sha256.Sum256([]byte(value.Value()))
	return PullClaim{Scope: scope, Secret: owned, SecretID: value.ID, Version: value.Version, SHA256: hex.EncodeToString(sum[:]), Generation: generation}, nil
}

// PullCredentials is memory-only. Formatting and JSON never include values;
// keep it only for the synchronous pull, never in task/container metadata.
type PullCredentials struct {
	host     string
	username string
	password string
}

func (PullCredentials) String() string               { return "private OCIR pull credential" }
func (c PullCredentials) GoString() string           { return c.String() }
func (PullCredentials) MarshalJSON() ([]byte, error) { return []byte(`{}`), nil }

// ForHost refuses registry redirects and challenges from another origin.
func (c PullCredentials) ForHost(host string) (string, string, error) {
	if host != c.host || c.host == "" || c.username == "" || c.password == "" {
		return "", "", ErrPullAuth
	}
	return c.username, c.password, nil
}

// Resolve requires independent authenticated scope and owned binding, then
// rereads CURRENT and checks its exact secret identity, version and bytes.
// Rotation needs fresh authenticated admission metadata; there is no stale,
// anonymous, environment, task-password or cached credential fallback.
func (p *PullSecrets) Resolve(ctx context.Context, claim PullClaim, expected PullScope, owned PullSecret) (PullCredentials, error) {
	if claim.Generation == 0 || claim.Scope != expected || claim.Secret != owned || claim.SecretID == "" || claim.Version < 1 || len(claim.SHA256) != 64 {
		return PullCredentials{}, ErrPullAuth
	}
	value, err := p.read(ctx, expected, owned)
	if err != nil {
		return PullCredentials{}, err
	}
	sum := sha256.Sum256([]byte(value.Value()))
	if value.ID != claim.SecretID || value.Version != claim.Version || hex.EncodeToString(sum[:]) != claim.SHA256 {
		return PullCredentials{}, ErrPullAuth
	}
	return PullCredentials{host: expected.RegistryHost, username: owned.Username, password: value.Value()}, nil
}
