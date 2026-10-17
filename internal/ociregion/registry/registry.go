// Package registry reconciles the platform's private OCI container repositories.
// Repository metadata uses instance principals; pull credentials remain Vault references.
package registry

import (
	"context"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json/v2"
	"errors"
	"fmt"
	"net/http"
	"strings"
	"time"
	"uuid"

	"github.com/nats-io/nats.go/jetstream"
	"github.com/oracle/oci-go-sdk/v65/artifacts"

	"github.com/TerraScale/ts-orchestrator/internal/ociclient"
	"github.com/TerraScale/ts-orchestrator/internal/ociresource"
)

var (
	ErrOwnership = errors.New("OCIR repository ownership is not proven")
	ErrPins      = errors.New("OCIR retention inventory is missing, stale, or incomplete")
	ErrRetiring  = errors.New("OCIR image retirement already started")
)

// Repository identifies one platform repository and the admitted creating principal.
// PrincipalID is persisted before creation; later leaders retain that original
// creator from the journal even when their own admitted principal differs.
type Repository struct {
	CompartmentID string `json:"compartment_id"`
	Name          string `json:"name"`
	Namespace     string `json:"namespace"`
	PrincipalID   string `json:"principal_id"`
	Owner         string `json:"owner"`
}

// Controller consumes a persistent regional KV bucket and the shared SDK client.
// Guard checks the current authority before every OCI and journal write.
type Controller struct {
	client  artifacts.ArtifactsClient
	journal Journal
	guard   func(context.Context) error
	region  string
}

// Journal supplies guarded durable compare-and-swap storage without claiming
// that a protected foundation object is a JetStream bucket.
type Journal interface {
	Load(context.Context, string) (Record, error)
	CompareAndSwap(context.Context, string, Record) error
}

// New builds the registry metadata client with the persistent regional bucket.
func New(factory *ociclient.Factory, journal jetstream.KeyValue, guard func(context.Context) error) (*Controller, error) {
	if journal == nil {
		return nil, errors.New("OCIR requires a durable journal")
	}
	return NewWithJournal(factory, kvJournal{journal}, guard)
}

// NewWithJournal accepts the same lifecycle over a protected root journal.
func NewWithJournal(factory *ociclient.Factory, journal Journal, guard func(context.Context) error) (*Controller, error) {
	if factory == nil || journal == nil || guard == nil {
		return nil, errors.New("OCIR requires the OCI factory, durable journal and authority guard")
	}
	client, err := factory.Artifacts()
	if err != nil {
		return nil, err
	}
	previous := client.Interceptor
	client.Interceptor = func(request *http.Request) error {
		if previous != nil {
			if err := previous(request); err != nil {
				return err
			}
		}
		if request.Method != http.MethodGet && request.Method != http.MethodHead {
			return guard(request.Context())
		}
		return nil
	}
	return &Controller{client: client, journal: journal, guard: guard, region: factory.Region()}, nil
}

// ImageRecord retains an admitted image and any irreversible retirement claim.
type ImageRecord struct {
	ID         string    `json:"id"`
	RecordedAt time.Time `json:"recorded_at"`
	Retiring   string    `json:"retiring,omitempty"`
}

// Record is the public operation metadata stored by the durable journal.
type Record struct {
	Repository      Repository             `json:"repository"`
	OperationID     string                 `json:"operation_id"`
	RepositoryID    string                 `json:"repository_id,omitempty"`
	CreateExpiresAt time.Time              `json:"create_expires_at"`
	Pins            Pins                   `json:"pins"`
	Images          map[string]ImageRecord `json:"images"`
	Revision        uint64                 `json:"-"`
}

func (c *Controller) key(repository Repository) (string, error) {
	if c == nil || c.journal == nil || c.guard == nil || repository.CompartmentID == "" || repository.PrincipalID == "" ||
		repository.Namespace == "" || repository.Name == "" || len(repository.Name) > 256 || strings.TrimSpace(repository.Name) != repository.Name ||
		strings.ContainsAny(repository.Name, "@:\\ \t\r\n") || c.region == "" {
		return "", errors.New("invalid OCIR repository identity or controller")
	}
	if err := (ociresource.Ownership{Mode: ociresource.TagModeFreeform, Owner: repository.Owner}).Validate(); err != nil {
		return "", err
	}
	sum := sha256.Sum256([]byte(c.region + "\x00" + repository.CompartmentID + "\x00" + repository.Name))
	return "ocir." + hex.EncodeToString(sum[:]), nil
}

func (c *Controller) load(ctx context.Context, repository Repository) (Record, error) {
	key, err := c.key(repository)
	if err != nil {
		return Record{}, err
	}
	state, err := c.journal.Load(ctx, key)
	if err != nil {
		return Record{}, err
	}
	if state.Repository.CompartmentID != repository.CompartmentID || state.Repository.Name != repository.Name || state.Repository.Namespace != repository.Namespace || state.Repository.Owner != repository.Owner ||
		state.Repository.PrincipalID == "" || state.OperationID == "" || state.CreateExpiresAt.IsZero() || state.Images == nil {
		return Record{}, ErrOwnership
	}
	return state, nil
}

func (c *Controller) save(ctx context.Context, state Record) error {
	key, err := c.key(state.Repository)
	if err != nil {
		return err
	}
	if err := c.guard(ctx); err != nil {
		return err
	}
	return c.journal.CompareAndSwap(ctx, key, state)
}

// The native adapter verifies the actual bucket on each read.
type kvJournal struct{ bucket jetstream.KeyValue }

func (s kvJournal) Load(ctx context.Context, key string) (Record, error) {
	status, err := s.bucket.Status(ctx)
	if err != nil {
		return Record{}, err
	}
	config := status.Config()
	if config.Storage != jetstream.FileStorage || config.TTL != 0 {
		return Record{}, errors.New("OCIR journal requires persistent non-expiring storage")
	}
	entry, err := s.bucket.Get(ctx, key)
	if err != nil {
		return Record{}, err
	}
	var state Record
	if len(entry.Value()) > 1<<20 {
		return Record{}, errors.New("OCIR journal exceeds its size bound")
	}
	if err := json.Unmarshal(entry.Value(), &state, json.RejectUnknownMembers(true)); err != nil {
		return Record{}, err
	}
	state.Revision = entry.Revision()
	return state, nil
}

func (s kvJournal) CompareAndSwap(ctx context.Context, key string, state Record) error {
	wire, err := json.Marshal(state)
	if err != nil {
		return err
	}
	if len(wire) > 1<<20 {
		return errors.New("OCIR journal exceeds its size bound")
	}
	if state.Revision == 0 {
		_, err = s.bucket.Create(ctx, key, wire)
	} else {
		_, err = s.bucket.Update(ctx, key, wire, state.Revision)
	}
	return err
}

func (c *Controller) tags(state Record) map[string]string {
	return map[string]string{"terrascale-managed-by": "ts-orchestrator", "terrascale-owner": state.Repository.Owner,
		"terrascale-ocir-operation": state.OperationID}
}

func (c *Controller) validate(state Record, repo artifacts.ContainerRepository) error {
	if repo.Id == nil || *repo.Id == "" || text(repo.CompartmentId) != state.Repository.CompartmentID ||
		text(repo.DisplayName) != state.Repository.Name || text(repo.Namespace) != state.Repository.Namespace || text(repo.CreatedBy) != state.Repository.PrincipalID ||
		state.RepositoryID != "" && *repo.Id != state.RepositoryID {
		return ErrOwnership
	}
	for key, want := range c.tags(state) {
		if repo.FreeformTags[key] != want {
			return ErrOwnership
		}
	}
	if repo.LifecycleState != artifacts.ContainerRepositoryLifecycleStateAvailable {
		return errors.New("OCIR repository is not available")
	}
	return nil
}

// Ensure checkpoints creation before calling OCI and binds the returned OCID.
// An unrecorded existing name is refused; an interrupted create reuses its token.
func (c *Controller) Ensure(ctx context.Context, repository Repository) (artifacts.ContainerRepository, error) {
	state, err := c.load(ctx, repository)
	if errors.Is(err, jetstream.ErrKeyNotFound) {
		deadline, ok := ctx.Deadline()
		if !ok || !time.Now().Before(deadline) {
			return artifacts.ContainerRepository{}, errors.New("OCIR creation requires the original deadline")
		}
		state = Record{Repository: repository, OperationID: uuid.New().String(), CreateExpiresAt: deadline.UTC(), Images: map[string]ImageRecord{}}
		if err := c.save(ctx, state); err != nil {
			return artifacts.ContainerRepository{}, err
		}
		state, err = c.load(ctx, repository)
	}
	if err != nil {
		return artifacts.ContainerRepository{}, err
	}
	if state.RepositoryID == "" {
		if !time.Now().Before(state.CreateExpiresAt) {
			return artifacts.ContainerRepository{}, errors.New("OCIR original create operation expired")
		}
		create, cancel := context.WithDeadline(ctx, state.CreateExpiresAt)
		defer cancel()
		// A name match never grants adoption. Only this durable create operation may bind an OCID.
		if err := c.guard(ctx); err != nil {
			return artifacts.ContainerRepository{}, err
		}
		response, err := c.client.CreateContainerRepository(ociclient.RequestContext(create), artifacts.CreateContainerRepositoryRequest{
			CompartmentId: new(repository.CompartmentID), DisplayName: new(repository.Name), IsPublic: new(false), IsImmutable: new(true), FreeformTags: c.tags(state),
			OpcRetryToken: new(state.OperationID)})
		if err != nil {
			return artifacts.ContainerRepository{}, fmt.Errorf("create/recover OCIR repository: %w", err)
		}
		if err := c.validate(state, response.ContainerRepository); err != nil {
			return artifacts.ContainerRepository{}, err
		}
		state.RepositoryID = text(response.Id)
		if err := c.save(ctx, state); err != nil {
			return artifacts.ContainerRepository{}, err
		}
	}
	response, err := c.client.GetContainerRepository(ociclient.RequestContext(ctx), artifacts.GetContainerRepositoryRequest{RepositoryId: new(state.RepositoryID)})
	if err != nil {
		return artifacts.ContainerRepository{}, err
	}
	if err := c.validate(state, response.ContainerRepository); err != nil {
		return artifacts.ContainerRepository{}, err
	}
	if response.IsPublic == nil || response.IsImmutable == nil || text(response.Namespace) == "" {
		return artifacts.ContainerRepository{}, errors.New("OCIR repository metadata is incomplete")
	}
	if *response.IsPublic || !*response.IsImmutable {
		if text(response.Etag) == "" {
			return artifacts.ContainerRepository{}, errors.New("OCIR repository has no concurrency token")
		}
		if err := c.guard(ctx); err != nil {
			return artifacts.ContainerRepository{}, err
		}
		_, err := c.client.UpdateContainerRepository(ociclient.RequestContext(ctx), artifacts.UpdateContainerRepositoryRequest{RepositoryId: new(state.RepositoryID), IfMatch: response.Etag, OpcRequestId: new(state.OperationID),
			IsPublic: new(false), IsImmutable: new(true)})
		if err != nil {
			return artifacts.ContainerRepository{}, err
		}
		// Re-observe before dependents receive the repository.
		observed, err := c.client.GetContainerRepository(ociclient.RequestContext(ctx), artifacts.GetContainerRepositoryRequest{RepositoryId: new(state.RepositoryID)})
		if err != nil {
			return artifacts.ContainerRepository{}, err
		}
		if err := c.validate(state, observed.ContainerRepository); err != nil {
			return artifacts.ContainerRepository{}, err
		}
		if observed.IsPublic == nil || *observed.IsPublic || observed.IsImmutable == nil || !*observed.IsImmutable || text(observed.Namespace) == "" {
			return artifacts.ContainerRepository{}, errors.New("OCIR private immutable repository update is not observed")
		}
		return observed.ContainerRepository, nil
	}
	return response.ContainerRepository, nil
}

func text(value *string) string {
	if value == nil {
		return ""
	}
	return *value
}
