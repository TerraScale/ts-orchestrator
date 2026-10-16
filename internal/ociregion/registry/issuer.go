package registry

import (
	"context"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json/v2"
	"errors"
	"net/http"
	"os"
	"strings"
	"time"
	"uuid"

	"github.com/nats-io/nats.go/jetstream"
	"github.com/oracle/oci-go-sdk/v65/artifacts"
	"github.com/oracle/oci-go-sdk/v65/common"
	"github.com/oracle/oci-go-sdk/v65/identity"
	"github.com/oracle/oci-go-sdk/v65/objectstorage"
	ocisecrets "github.com/oracle/oci-go-sdk/v65/secrets"
	ocivault "github.com/oracle/oci-go-sdk/v65/vault"

	"github.com/TerraScale/ts-orchestrator/internal/ociclient"
	"github.com/TerraScale/ts-orchestrator/internal/ociregion/catalog"
	"github.com/TerraScale/ts-orchestrator/internal/region"
	"github.com/TerraScale/ts-orchestrator/internal/vaultsecret"
)

var ErrIssuer = errors.New("OCIR credential issuer requires current signed authority and recoverable owned resources")

const issuerLease = 2 * time.Minute
const tokenRotation = 30 * 24 * time.Hour

// Issuer creates only the service identity and repository pull credential in
// the same root-signed foundation scope. Credential bytes never enter its KV.
type Issuer struct {
	identity  identity.IdentityClient
	vault     ocivault.VaultsClient
	secrets   ocisecrets.SecretsClient
	artifacts artifacts.ArtifactsClient
	journal   jetstream.KeyValue
	scope     region.VerifiedOCIRIssuer
	guard     func(context.Context) error
	homeWrite func(context.Context) (context.Context, func(), error)
	host      string
}

// NewIssuer requires a guard that freshly verifies this exact grant digest,
// generation and expiry together with the current regional authority epoch.
// homeWrite is the existing tenancy-wide foundation IAM serialization lease.
func NewIssuer(ctx context.Context, factory *ociclient.Factory, journal jetstream.KeyValue,
	scope region.VerifiedOCIRIssuer, guard func(context.Context) error,
	homeWrite func(context.Context) (context.Context, func(), error)) (*Issuer, error) {
	if factory == nil || journal == nil || guard == nil || homeWrite == nil || !scope.IsVerified() ||
		!time.Now().Before(scope.ExpiresAt()) || factory.Region() != scope.Intent().OCIRegion {
		return nil, ErrIssuer
	}
	tenancy, err := factory.Provider().TenancyOCID()
	if err != nil || tenancy != scope.TenancyID() {
		return nil, ErrIssuer
	}
	if err := guard(ctx); err != nil {
		return nil, ErrIssuer
	}
	homeRegion, err := factory.HomeRegion(ociclient.RequestContext(ctx), tenancy)
	if err != nil {
		return nil, ErrIssuer
	}
	home, err := factory.ForRegion(homeRegion)
	if err != nil {
		return nil, ErrIssuer
	}
	iam, err := home.Identity()
	if err != nil {
		return nil, ErrIssuer
	}
	vault, err := ocivault.NewVaultsClientWithConfigurationProvider(factory.Provider())
	if err != nil {
		return nil, ErrIssuer
	}
	vault.SetRegion(factory.Region())
	factory.Configure(&vault.BaseClient, ociclient.Service("vault"))
	secrets, err := vaultsecret.SecretsClient(factory)
	if err != nil {
		return nil, ErrIssuer
	}
	artifactsClient, err := factory.Artifacts()
	if err != nil {
		return nil, ErrIssuer
	}
	storage, err := factory.ObjectStorage()
	if err != nil {
		return nil, ErrIssuer
	}
	namespace, err := storage.GetNamespace(ociclient.RequestContext(ctx), objectstorage.GetNamespaceRequest{CompartmentId: new(tenancy)})
	if err != nil || text(namespace.Value) != scope.Intent().RegistryNamespace {
		return nil, ErrIssuer
	}
	entry, ok := catalog.CellForOCIRegion(factory.Region())
	if !ok {
		return nil, ErrIssuer
	}
	i := &Issuer{identity: iam, vault: vault, secrets: secrets, artifacts: artifactsClient, journal: journal, scope: scope,
		guard: guard, homeWrite: homeWrite, host: strings.ToLower(entry.OCIRegionKey) + ".ocir.io"}
	// Every attempt also fences an expired grant, including SDK retries.
	for _, client := range []*common.BaseClient{&i.identity.BaseClient, &i.vault.BaseClient} {
		previous := client.Interceptor
		client.Interceptor = func(request *http.Request) error {
			if previous != nil {
				if err := previous(request); err != nil {
					return err
				}
			}
			if request.Method != http.MethodGet && request.Method != http.MethodHead {
				return i.authorized(request.Context())
			}
			return nil
		}
	}
	return i, nil
}

// issuerRecord contains only operation and OCI/Vault metadata. Lease ownership
// fences concurrent callers before a once-returned token can be requested.
type issuerRecord struct {
	ScopeHash      string    `json:"scope_hash"`
	Generation     uint64    `json:"generation"`
	GrantDigest    string    `json:"grant_digest"`
	OperationID    string    `json:"operation_id"`
	LeaseID        string    `json:"lease_id"`
	LeaseUntil     time.Time `json:"lease_until,omitzero"`
	UserID         string    `json:"user_id,omitempty"`
	RepositoryID   string    `json:"repository_id,omitempty"`
	GroupID        string    `json:"group_id,omitempty"`
	PolicyID       string    `json:"policy_id,omitempty"`
	MembershipID   string    `json:"membership_id,omitempty"`
	TokenID        string    `json:"token_id,omitempty"`
	PriorTokenID   string    `json:"prior_token_id,omitempty"`
	TokenOperation string    `json:"token_operation,omitempty"`
	TokenStarted   time.Time `json:"token_started,omitzero"`
	BeforeTokens   []string  `json:"before_tokens,omitempty"`
	PendingHash    string    `json:"pending_hash,omitempty"`
	SecretID       string    `json:"secret_id,omitempty"`
	Version        int64     `json:"version,omitzero"`
	Hash           string    `json:"hash,omitempty"`
	PublishedAt    time.Time `json:"published_at,omitzero"`
	Stage          string    `json:"stage"`
	revision       uint64
}

type issuerAttempt struct {
	issuer *Issuer
	state  issuerRecord
	key    string
	lease  string
}

func (i *Issuer) authorized(ctx context.Context) error {
	if err := ctx.Err(); err != nil {
		return err
	}
	if i == nil || !i.scope.IsVerified() || !time.Now().Before(i.scope.ExpiresAt()) {
		return ErrIssuer
	}
	for _, name := range ociclient.SecretUnsafeEnv {
		if _, set := os.LookupEnv(name); set {
			return ErrIssuer
		}
	}
	if err := i.guard(ctx); err != nil {
		return ErrIssuer
	}
	return nil
}

func (i *Issuer) begin(ctx context.Context) (*issuerAttempt, error) {
	if err := i.authorized(ctx); err != nil {
		return nil, err
	}
	status, err := i.journal.Status(ctx)
	if err != nil || status.Config().Storage != jetstream.FileStorage || status.Config().TTL != 0 {
		return nil, ErrIssuer
	}
	wire, err := json.Marshal(struct {
		Tenancy, Installation string
		Intent                region.OCIRIssuerIntent
	}{i.scope.TenancyID(), i.scope.InstallationID(), i.scope.Intent()}, json.Deterministic(true))
	if err != nil {
		return nil, ErrIssuer
	}
	sum := sha256.Sum256(wire)
	hash := hex.EncodeToString(sum[:])
	key := "ocir-issuer." + hash
	entry, err := i.journal.Get(ctx, key)
	state := issuerRecord{ScopeHash: hash, Generation: i.scope.Generation(), GrantDigest: i.scope.GrantDigest(), OperationID: uuid.New().String(), Stage: "identity"}
	if err == nil {
		if len(entry.Value()) > 32<<10 || json.Unmarshal(entry.Value(), &state, json.RejectUnknownMembers(true)) != nil ||
			state.ScopeHash != hash || state.OperationID == "" || state.Generation > i.scope.Generation() ||
			state.Generation == i.scope.Generation() && state.GrantDigest != i.scope.GrantDigest() {
			return nil, ErrIssuer
		}
		if state.LeaseID != "" && time.Now().Before(state.LeaseUntil) {
			return nil, ErrIssuer
		}
		state.revision = entry.Revision()
	} else if !errors.Is(err, jetstream.ErrKeyNotFound) {
		return nil, ErrIssuer
	}
	state.Generation, state.GrantDigest = i.scope.Generation(), i.scope.GrantDigest()
	lease := uuid.New().String()
	state.LeaseID, state.LeaseUntil = lease, time.Now().Add(issuerLease)
	a := &issuerAttempt{issuer: i, state: state, key: key, lease: lease}
	if err := a.save(ctx, false); err != nil {
		return nil, err
	}
	return a, nil
}

func (a *issuerAttempt) check(ctx context.Context) error {
	if err := a.issuer.authorized(ctx); err != nil {
		return err
	}
	entry, err := a.issuer.journal.Get(ctx, a.key)
	if err != nil || entry.Revision() != a.state.revision || !time.Now().Before(a.state.LeaseUntil) || a.state.LeaseID != a.lease {
		return ErrIssuer
	}
	return nil
}

func (a *issuerAttempt) save(ctx context.Context, check bool) error {
	if check {
		if err := a.check(ctx); err != nil {
			return err
		}
	} else if err := a.issuer.authorized(ctx); err != nil {
		return err
	}
	wire, err := json.Marshal(a.state)
	if err != nil {
		return ErrIssuer
	}
	var revision uint64
	if a.state.revision == 0 {
		revision, err = a.issuer.journal.Create(ctx, a.key, wire)
	} else {
		revision, err = a.issuer.journal.Update(ctx, a.key, wire, a.state.revision)
	}
	if err != nil {
		return ErrIssuer
	}
	a.state.revision = revision
	return nil
}

func (a *issuerAttempt) call(ctx context.Context, iam bool, run func(context.Context) error) error {
	release := func() {}
	if iam {
		var err error
		var leased context.Context
		leased, release, err = a.issuer.homeWrite(ctx)
		if err != nil || release == nil || leased == nil {
			if release != nil {
				release()
			}
			return ErrIssuer
		}
		ctx = leased
	}
	defer release()
	if err := a.check(ctx); err != nil {
		return err
	}
	ctx = ociclient.WithAuthority(ctx, a.check)
	if err := run(ociclient.RequestContext(ctx)); err != nil {
		return errors.Join(ErrIssuer, ctx.Err())
	}
	return nil
}

// Ensure reconciles the exact signed identity and automatically rotates after
// thirty days. It returns only the independently owned Vault binding.
func (i *Issuer) Ensure(ctx context.Context) (PullSecret, error) {
	a, err := i.begin(ctx)
	if err != nil {
		return PullSecret{}, err
	}
	releaseContext := ctx
	defer func() {
		// An expired/fenced attempt cannot release another owner's lease.
		if a.check(releaseContext) == nil {
			a.state.LeaseID = ""
			a.state.LeaseUntil = time.Time{}
			_ = a.save(releaseContext, false)
		}
	}()
	ctx, cancel := context.WithTimeout(ctx, 90*time.Second)
	defer cancel()
	if err := a.repository(ctx); err != nil {
		return PullSecret{}, err
	}
	user, err := a.ensureIdentity(ctx)
	if err != nil {
		return PullSecret{}, err
	}
	if err := a.ensureCredential(ctx, user); err != nil {
		return PullSecret{}, err
	}
	intent := i.scope.Intent()
	return PullSecret{RegistryHost: i.host, Repository: intent.RegistryNamespace + "/" + intent.RepositoryName, Ref: vaultsecret.Ref{Vault: intent.VaultTarget.VaultID, Name: intent.SecretName}}, nil
}
